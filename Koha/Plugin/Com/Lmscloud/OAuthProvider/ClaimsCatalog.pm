package Koha::Plugin::Com::Lmscloud::OAuthProvider::ClaimsCatalog;

# Static allow-list of patron fields that MAY be released to OAuth clients.
# 'userid' is deliberately not part of this catalog: it is always released,
# regardless of a client's configured claims (see the plugin's requirements).

use Modern::Perl;

use C4::Context;
use Mojo::JSON qw(false);

# Order here is the order shown in the admin UI and in userinfo responses.
# No display labels here on purpose: templates look up a translated label
# per key (translation key "claim_label_<key>") from the plugin's i18n
# catalog (see i18n/default.inc / i18n/de-DE.inc), so this list stays
# language-neutral.
our @CATALOG = (
    { key => 'cardnumber' },
    { key => 'borrowernumber' },
    { key => 'firstname' },
    { key => 'surname' },
    { key => 'email' },
    { key => 'branchcode' },
    { key => 'branchname' },
    { key => 'categorycode' },
    { key => 'category_description' },
    { key => 'dateexpiry' },
    { key => 'age' },
    { key => 'address' },
    { key => 'email_verified' },
    { key => 'phone_number' },
    { key => 'phone_number_verified' },
    { key => 'fsk' },
    { key => 'status' },
);

my %ACCESSOR_OF = (
    cardnumber           => sub { $_[0]->cardnumber },
    borrowernumber       => sub { $_[0]->borrowernumber },
    firstname            => sub { $_[0]->firstname },
    surname              => sub { $_[0]->surname },
    email                => sub { $_[0]->email },
    branchcode           => sub { $_[0]->branchcode },
    branchname           => sub { $_[0]->library ? $_[0]->library->branchname : undef },
    categorycode         => sub { $_[0]->categorycode },
    category_description => sub { $_[0]->category ? $_[0]->category->description : undef },
    dateexpiry           => sub { $_[0]->dateexpiry },
    # Koha::Patron::get_age() returns years as of today, computed from
    # dateofbirth; undef if no dateofbirth is on file.
    age                   => sub { $_[0]->get_age },
    # Structured per the OIDC Core 'address' Claim (5.1.1): only the base/
    # home address fields (address/address2/city/state/zipcode/country) -
    # deliberately not the alternate/"B_" address Koha also has, since
    # OIDC's address claim models a single address, not two.
    address               => sub { _format_address( $_[0] ) },
    # Koha has no concept of email/phone verification at all (no "verified"
    # column anywhere on the borrowers table) - these two are hardcoded to
    # the JSON boolean false (via Mojo::JSON, matching the Mojolicious
    # controller that ultimately renders this hash) rather than omitted,
    # since "not verified" is an honest, spec-compliant answer for a system
    # that plainly never verifies either.
    email_verified        => sub { false },
    # Koha's primary phone number field ("phone" on the borrowers table) -
    # not "mobile" or "phonepro". Change this accessor if a client actually
    # needs the mobile number instead.
    phone_number          => sub { $_[0]->phone },
    phone_number_verified => sub { false },
    # 'fsk' and 'status' replicate what opac/opac-divibib-auth.pl returns to
    # the German "Onleihe" (divibib GmbH) service - see _patron_status()
    # below. Deliberately NOT calling C4::External::DivibibPatronStatus: that
    # module only exists in the LMSCloud fork, and this plugin is meant to
    # install on any Koha, so the equivalent logic is copied in below
    # instead of depended on. These two are present here (with their own
    # accessor) purely so is_valid_key()/valid_keys() recognise them the
    # same way as every other claim; build_claims() bypasses these closures
    # and computes both from one shared call instead, since calling each
    # independently would run the underlying fines/overdues/debarred/
    # expired checks twice for no reason.
    fsk                   => sub { _patron_status( $_[0] )->{fsk} + 0 },
    status                => sub { _patron_status( $_[0] )->{status} + 0 },
);

# =========================== patron status (fsk / status) ==================
#
# A from-scratch reimplementation of the same logic
# C4::External::DivibibPatronStatus::getPatronStatus() applies when given an
# already-resolved patron (i.e. the branch of that method that does NOT
# re-validate a password - this plugin never has the patron's plaintext
# password available at /userinfo time, only briefly during the earlier
# /authorize login step, and never persists it). Kept in sync by hand with
# that module's logic/precedence order; see the plugin README for the full
# status-code table and rationale.
#
# Uses only Koha::Patron's public API and system preferences that ship with
# core Koha (OverduesBlockCirc, noissuescharge) - no code dependency on any
# LMSCloud-only module. The original module's category-based lending block
# (DivibibAuthDisabledForGroups, -> status -4) has no equivalent here at
# all: it was replaced by a per-client patron-category allow-list/deny-list
# that gates the login itself at /authorize (see
# OAuthProvider::is_client_allowed_for_patron, called from
# Controller::_handle_login) rather than only informing the caller via this
# claim - a patron whose category isn't eligible for a given client never
# gets an access_token for it in the first place, so status=-4 could never
# be observed here anyway.

sub _patron_status {
    my ($patron) = @_;

    my $status = 3;    # innocent until one of the checks below says otherwise

    my $overdues_block = C4::Context->preference('OverduesBlockCirc') // '';
    if ( $patron->has_overdues && ( $overdues_block eq 'block' || $overdues_block eq 'confirmation' ) ) {
        $status = 1;
    }
    elsif ( $patron->is_debarred ) {
        $status = 1;
    }
    elsif ( $patron->is_expired ) {
        $status = -3;
    }
    elsif ( $patron->gonenoaddress && $patron->gonenoaddress == 1 ) {
        $status = 1;
    }
    elsif ( $patron->lost && $patron->lost == 1 ) {
        $status = 1;
    }
    elsif ( $patron->account->non_issues_charges > ( C4::Context->preference('noissuescharge') || 0 ) ) {
        $status = 4;
    }
    elsif ( $patron->account_locked ) {
        $status = 1;
    }

    my $age = $patron->get_age;
    my $fsk =
          ( defined $age && $age > 0  && $age < 6 )  ? 0
        : ( defined $age && $age >= 6  && $age < 12 ) ? 6
        : ( defined $age && $age >= 12 && $age < 16 ) ? 12
        : ( defined $age && $age >= 16 && $age < 18 ) ? 16
        :                                                18;

    return { status => $status, fsk => $fsk };
}

# Builds an OIDC Core "address" Claim object (5.1.1) from Koha's base/home
# address fields. Members are omitted entirely when empty (OIDC's address
# member set is all-optional; sending explicit nulls/empty strings for
# unknown fields would just be noise), and the whole claim is undef (JSON
# null) if the patron has no address information on file at all.
sub _format_address {
    my ($patron) = @_;

    my $street_address = join( "\n", grep { defined($_) && length($_) } ( $patron->address, $patron->address2 ) );

    my %addr;
    $addr{street_address} = $street_address if length $street_address;
    for my $pair ( [ locality => $patron->city ], [ region => $patron->state ],
        [ postal_code => $patron->zipcode ], [ country => $patron->country ] )
    {
        my ( $member, $value ) = @$pair;
        $addr{$member} = $value if defined $value && length $value;
    }

    return undef unless %addr;

    my @lines = grep { length }
        ( $addr{street_address} // '',
          join( ' ', grep { length } ( $addr{postal_code} // '', $addr{locality} // '' ) ),
          $addr{country} // '',
        );
    $addr{formatted} = join( "\n", @lines ) if @lines;

    return \%addr;
}

sub is_valid_key {
    my ($class, $key) = @_;
    return exists $ACCESSOR_OF{$key};
}

sub valid_keys {
    return keys %ACCESSOR_OF;
}

sub catalog {
    return \@CATALOG;
}

# Builds the userinfo claim set for a patron, given the extra claim keys a
# client is allowed to receive. 'userid' is always included (the original,
# OAuth2-era default). 'sub' is always included too: unlike 'userid' (which
# staff can rename), it is the patron's immutable borrowernumber, matching
# the id_token's 'sub' claim as OIDC requires - stringified, since OIDC
# mandates sub be a StringOrURI, not a JSON number.
#
sub build_claims {
    my ( $class, $patron, $allowed_claims ) = @_;

    my %claims = (
        userid => $patron->userid,
        sub    => "" . $patron->borrowernumber,
    );

    my %requested = map { $_ => 1 } @{ $allowed_claims || [] };

    # 'fsk'/'status' share one underlying computation (several DB lookups:
    # account charges, overdues, debarred/expired) - run it at most once
    # per build_claims() call, however many of the two are requested.
    if ( $requested{fsk} || $requested{status} ) {
        my $patron_status = _patron_status($patron);
        $claims{fsk}    = $patron_status->{fsk} + 0    if $requested{fsk};
        $claims{status} = $patron_status->{status} + 0 if $requested{status};
    }

    for my $key ( @{ $allowed_claims || [] } ) {
        next if $key eq 'fsk' || $key eq 'status';    # handled above
        next unless exists $ACCESSOR_OF{$key};
        $claims{$key} = $ACCESSOR_OF{$key}->($patron);
    }

    return \%claims;
}

1;
