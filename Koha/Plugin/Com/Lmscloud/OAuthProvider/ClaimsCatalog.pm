package Koha::Plugin::Com::Lmscloud::OAuthProvider::ClaimsCatalog;

# Static allow-list of patron fields that MAY be released to OAuth clients.
# 'userid' is deliberately not part of this catalog: it is always released,
# regardless of a client's configured claims (see the plugin's requirements).

use Modern::Perl;

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
);

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
sub build_claims {
    my ( $class, $patron, $allowed_claims ) = @_;

    my %claims = (
        userid => $patron->userid,
        sub    => "" . $patron->borrowernumber,
    );

    for my $key ( @{ $allowed_claims || [] } ) {
        next unless exists $ACCESSOR_OF{$key};
        $claims{$key} = $ACCESSOR_OF{$key}->($patron);
    }

    return \%claims;
}

1;
