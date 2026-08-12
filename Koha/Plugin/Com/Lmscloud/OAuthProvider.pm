package Koha::Plugin::Com::Lmscloud::OAuthProvider;

# Koha plugin turning Koha into an OAuth2 / OpenID Connect authorization
# server: external applications can let a patron log in with their library
# account and then fetch a per-client-configurable set of user data from
# /userinfo, or (when the client asks for the 'openid' scope) a signed
# id_token from /token.
#
# Deliberate scope (see plugin README for the reasoning):
#  - Confidential clients only (every client has a client_secret) - which
#    means id_tokens are signed HS256 with the client's own client_secret as
#    the shared HMAC key. No asymmetric keypair, no JWKS with real keys, no
#    new CPAN dependency: Mojo::JWT (already vendored) is all that's needed.
#    The /jwks endpoint exists only to satisfy clients/discovery consumers
#    that unconditionally expect one; it returns an empty key set.
#  - The OIDC discovery document is served under the plugin's own contrib
#    path, not at the spec-mandated /.well-known/openid-configuration root -
#    Koha plugin routes cannot be mounted outside /api/v1/contrib/<ns>/. An
#    administrator must add a webserver-level rewrite for full conformance
#    (documented in the README).

use Modern::Perl;

use base qw(Koha::Plugins::Base);

use C4::Context;
use C4::Languages qw(accept_language);
use CGI;
use Digest::SHA qw(sha256_hex sha256);
use JSON qw(encode_json decode_json);
use MIME::Base64 qw(encode_base64url);
use Mojo::JWT;
use Template;
use Try::Tiny;
use URI::Escape qw(uri_escape);
use UUID;

use Koha::AuthUtils;
use Koha::Patron::Categories;
use Koha::Token;
use Koha::Plugin::Com::Lmscloud::OAuthProvider::ClaimsCatalog;

# Charset used for all generated secrets/codes/tokens: they travel in URL
# query strings (authorization code), HTTP headers (Bearer access token) and
# POST bodies, so only URL/header-safe characters are used - never rely on
# Koha::Token's default '.' charset, which draws from the full printable
# ASCII set (includes '&', '%', '+', quotes, whitespace, ...).
my $SAFE_TOKEN_PATTERN = '[A-Za-z0-9]{%d}';

sub _random_token {
    my ($length) = @_;
    return Koha::Token->new->generate( { pattern => sprintf( $SAFE_TOKEN_PATTERN, $length ) } );
}

our $VERSION = '1.2.0';

our $metadata = {
    name            => 'OAuth2 / OpenID Connect Identity Provider',
    author          => 'LMSCloud GmbH',
    description     => 'Turns Koha into an OAuth2/OIDC server: external applications can '
                      . 'authenticate against library accounts and then fetch '
                      . 'per-client-configurable user data via /userinfo (and, with '
                      . 'scope=openid, a signed id_token).',
    date_authored   => '2026-08-04',
    date_updated    => '2026-08-04',
    minimum_version => '22.11',
    maximum_version => undef,
    version         => $VERSION,
    namespace       => 'oauthprovider',
};

# --- default, plugin-wide (not per-client) settings ------------------------

my %DEFAULT_SETTINGS = (
    access_token_ttl_seconds  => 3600,          # 1 hour
    refresh_token_ttl_seconds => 60 * 60 * 24 * 30, # 30 days
    auth_code_ttl_seconds     => 60,            # 1 minute
    login_ticket_ttl_seconds  => 60 * 5,        # 5 minutes
    # Public base URL of this plugin's contrib routes, e.g.
    # https://opac.example.org/api/v1/contrib/oauthprovider - used as the
    # OIDC 'iss' claim and to build absolute URLs in the discovery document.
    # Must be set by staff before OIDC (scope=openid) clients are usable.
    issuer_url                => '',
);

# =========================== plugin bootstrap ==============================

sub new {
    my ( $class, $args ) = @_;
    $args->{metadata} = $metadata;
    my $self = $class->SUPER::new($args);
    return $self;
}

sub api_namespace {
    my ($self) = @_;
    return 'oauthprovider';
}

sub api_routes {
    my ($self) = @_;

    my $spec_file = $self->mbf_path('api_routes.json');
    return {} unless $spec_file && -e $spec_file;

    open my $fh, '<:encoding(UTF-8)', $spec_file or return {};
    local $/;
    my $json = <$fh>;
    close $fh;

    my $spec = try {
        decode_json($json);
    } catch {
        warn "Koha::Plugin::Com::Lmscloud::OAuthProvider: invalid api_routes.json: $_";
        +{};    # '+' forces hashref parsing, not an empty block
    };

    return $spec;
}

# =========================== install / upgrade ==============================

sub install {
    my ( $self, $args ) = @_;
    my $dbh = C4::Context->dbh;

    my $clients_table = $self->_clients_table;
    $dbh->do(qq{
        CREATE TABLE IF NOT EXISTS $clients_table (
            id                  INT(11) NOT NULL AUTO_INCREMENT,
            client_id           VARCHAR(64) NOT NULL,
            client_secret_hash  VARCHAR(255) NOT NULL,
            client_name         VARCHAR(255) NOT NULL,
            redirect_uris       TEXT NOT NULL,
            allowed_claims      TEXT NOT NULL,
            allowed_categories  TEXT NULL,
            denied_categories   TEXT NULL,
            is_active           TINYINT(1) NOT NULL DEFAULT 1,
            created_on          DATETIME NOT NULL,
            updated_on          DATETIME NOT NULL,
            PRIMARY KEY (id),
            UNIQUE KEY client_id_idx (client_id)
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4
    });

    my $codes_table = $self->_codes_table;
    $dbh->do(qq{
        CREATE TABLE IF NOT EXISTS $codes_table (
            id                    INT(11) NOT NULL AUTO_INCREMENT,
            code_hash             VARCHAR(64) NOT NULL,
            client_id             VARCHAR(64) NOT NULL,
            borrowernumber        INT(11) NOT NULL,
            redirect_uri          TEXT NOT NULL,
            code_challenge        VARCHAR(255) NULL,
            code_challenge_method VARCHAR(10) NULL,
            nonce                 VARCHAR(255) NULL,
            scope                 VARCHAR(255) NULL,
            expires_on            DATETIME NOT NULL,
            used                   TINYINT(1) NOT NULL DEFAULT 0,
            created_on             DATETIME NOT NULL,
            PRIMARY KEY (id),
            UNIQUE KEY code_hash_idx (code_hash),
            KEY client_idx (client_id)
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4
    });

    my $tokens_table = $self->_tokens_table;
    $dbh->do(qq{
        CREATE TABLE IF NOT EXISTS $tokens_table (
            id             INT(11) NOT NULL AUTO_INCREMENT,
            token_hash      VARCHAR(64) NOT NULL,
            token_type      VARCHAR(10) NOT NULL,
            client_id       VARCHAR(64) NOT NULL,
            borrowernumber  INT(11) NOT NULL,
            scope            VARCHAR(255) NULL,
            expires_on      DATETIME NOT NULL,
            revoked          TINYINT(1) NOT NULL DEFAULT 0,
            created_on       DATETIME NOT NULL,
            PRIMARY KEY (id),
            UNIQUE KEY token_hash_idx (token_hash),
            KEY client_idx (client_id),
            KEY expires_idx (expires_on)
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4
    });

    # One-time secret used to sign the short-lived login->consent ticket.
    # Not shown/exported anywhere; internal use only.
    unless ( $self->retrieve_data('ticket_secret') ) {
        my $secret = _random_token(64);
        $self->store_data( { ticket_secret => $secret } );
    }

    unless ( $self->retrieve_data('settings') ) {
        $self->store_data( { settings => encode_json( \%DEFAULT_SETTINGS ) } );
    }

    return 1;
}

sub upgrade {
    my ( $self, $args ) = @_;
    my $dbh = C4::Context->dbh;

    # 1.1.0: added OIDC support (nonce/scope tracking for id_token issuance).
    # ADD COLUMN IF NOT EXISTS has been supported since MariaDB 10.0.2, long
    # before any MariaDB version Koha 22.11 runs on.
    my $clients_table = $self->_clients_table;
    my $codes_table   = $self->_codes_table;
    my $tokens_table  = $self->_tokens_table;
    $dbh->do("ALTER TABLE $codes_table ADD COLUMN IF NOT EXISTS nonce VARCHAR(255) NULL");
    $dbh->do("ALTER TABLE $codes_table ADD COLUMN IF NOT EXISTS scope VARCHAR(255) NULL");
    $dbh->do("ALTER TABLE $tokens_table ADD COLUMN IF NOT EXISTS scope VARCHAR(255) NULL");

    # 1.2.0: per-client patron-category allow-list/deny-list, replacing the
    # old global DivibibAuthDisabledForGroups-based restriction.
    $dbh->do("ALTER TABLE $clients_table ADD COLUMN IF NOT EXISTS allowed_categories TEXT NULL");
    $dbh->do("ALTER TABLE $clients_table ADD COLUMN IF NOT EXISTS denied_categories TEXT NULL");

    return 1;
}

sub uninstall {
    my ( $self, $args ) = @_;
    my $dbh = C4::Context->dbh;

    $dbh->do( 'DROP TABLE IF EXISTS ' . $self->_tokens_table );
    $dbh->do( 'DROP TABLE IF EXISTS ' . $self->_codes_table );
    $dbh->do( 'DROP TABLE IF EXISTS ' . $self->_clients_table );

    return 1;
}

sub cronjob_nightly {
    my ($self) = @_;
    $self->cleanup_expired;
    return 1;
}

# =========================== settings (plugin-wide) =========================

sub settings {
    my ($self) = @_;
    my $raw = $self->retrieve_data('settings');
    my $stored = $raw ? ( try { decode_json($raw) } catch { +{} } ) : {};
    return { %DEFAULT_SETTINGS, %$stored };
}

sub save_settings {
    my ( $self, $updates ) = @_;
    my $merged = { %{ $self->settings }, %$updates };
    $self->store_data( { settings => encode_json($merged) } );
    return $merged;
}

sub _ticket_secret {
    my ($self) = @_;
    return $self->retrieve_data('ticket_secret');
}

# =========================== table name helpers ==============================

sub _clients_table { return $_[0]->get_qualified_table_name('clients'); }
sub _codes_table   { return $_[0]->get_qualified_table_name('authorization_codes'); }
sub _tokens_table  { return $_[0]->get_qualified_table_name('tokens'); }

# =========================== client CRUD ==============================

sub list_clients {
    my ($self) = @_;
    my $dbh   = C4::Context->dbh;
    my $table = $self->_clients_table;
    my $rows  = $dbh->selectall_arrayref(
        "SELECT * FROM $table ORDER BY id",
        { Slice => {} }
    );
    $self->_decode_client_json($_) for @$rows;
    return $rows;
}

sub get_client {
    my ( $self, $client_id ) = @_;
    my $dbh   = C4::Context->dbh;
    my $table = $self->_clients_table;
    my $row   = $dbh->selectrow_hashref(
        "SELECT * FROM $table WHERE client_id = ?",
        undef, $client_id
    );
    return unless $row;
    $self->_decode_client_json($row);
    return $row;
}

sub get_client_by_row_id {
    my ( $self, $id ) = @_;
    my $dbh   = C4::Context->dbh;
    my $table = $self->_clients_table;
    my $row   = $dbh->selectrow_hashref(
        "SELECT * FROM $table WHERE id = ?",
        undef, $id
    );
    return unless $row;
    $self->_decode_client_json($row);
    return $row;
}

# Decodes a client row's JSON-array columns in place. allowed_categories/
# denied_categories are TEXT NULL (added in 1.2.0) - rows created before
# that migration, or never edited since, may have NULL there, so this
# defaults a missing/empty value to [] rather than choking on decode_json(undef).
sub _decode_client_json {
    my ( $self, $row ) = @_;
    $row->{redirect_uris}      = decode_json( $row->{redirect_uris} );
    $row->{allowed_claims}     = decode_json( $row->{allowed_claims} );
    $row->{allowed_categories} = $row->{allowed_categories} ? decode_json( $row->{allowed_categories} ) : [];
    $row->{denied_categories}  = $row->{denied_categories}  ? decode_json( $row->{denied_categories} )  : [];
    return $row;
}

# Returns ($client_id, $plain_secret)
sub create_client {
    my ( $self, $args ) = @_;

    my $client_id  = $self->_generate_unused_client_id;
    my $secret     = _random_token(48);
    my $secret_hash = Koha::AuthUtils::hash_password($secret);

    my $dbh   = C4::Context->dbh;
    my $table = $self->_clients_table;
    $dbh->do(
        "INSERT INTO $table
            (client_id, client_secret_hash, client_name, redirect_uris, allowed_claims, allowed_categories, denied_categories, is_active, created_on, updated_on)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, NOW(), NOW())",
        undef,
        $client_id,
        $secret_hash,
        $args->{client_name},
        encode_json( $args->{redirect_uris}  || [] ),
        encode_json( $self->_sanitize_claims( $args->{allowed_claims} ) ),
        encode_json( $self->_sanitize_categories( $args->{allowed_categories} ) ),
        encode_json( $self->_sanitize_categories( $args->{denied_categories} ) ),
        $args->{is_active} ? 1 : 0,
    );

    return ( $client_id, $secret );
}

sub update_client {
    my ( $self, $id, $args ) = @_;

    my $dbh   = C4::Context->dbh;
    my $table = $self->_clients_table;
    $dbh->do(
        "UPDATE $table
            SET client_name = ?, redirect_uris = ?, allowed_claims = ?, allowed_categories = ?, denied_categories = ?, is_active = ?, updated_on = NOW()
         WHERE id = ?",
        undef,
        $args->{client_name},
        encode_json( $args->{redirect_uris} || [] ),
        encode_json( $self->_sanitize_claims( $args->{allowed_claims} ) ),
        encode_json( $self->_sanitize_categories( $args->{allowed_categories} ) ),
        encode_json( $self->_sanitize_categories( $args->{denied_categories} ) ),
        $args->{is_active} ? 1 : 0,
        $id,
    );

    return 1;
}

sub delete_client {
    my ( $self, $id ) = @_;

    my $client = $self->get_client_by_row_id($id) or return;

    my $dbh = C4::Context->dbh;
    $dbh->do( "DELETE FROM " . $self->_tokens_table . " WHERE client_id = ?",       undef, $client->{client_id} );
    $dbh->do( "DELETE FROM " . $self->_codes_table  . " WHERE client_id = ?",       undef, $client->{client_id} );
    $dbh->do( "DELETE FROM " . $self->_clients_table . " WHERE id = ?",              undef, $id );

    return 1;
}

# Returns the new plaintext secret.
sub regenerate_secret {
    my ( $self, $id ) = @_;

    my $secret      = _random_token(48);
    my $secret_hash = Koha::AuthUtils::hash_password($secret);

    my $dbh   = C4::Context->dbh;
    my $table = $self->_clients_table;
    $dbh->do(
        "UPDATE $table SET client_secret_hash = ?, updated_on = NOW() WHERE id = ?",
        undef, $secret_hash, $id,
    );

    return $secret;
}

sub verify_client_secret {
    my ( $self, $client, $secret ) = @_;
    return 0 unless $client && defined $secret && length $secret;
    return Koha::AuthUtils::hash_password( $secret, $client->{client_secret_hash} ) eq $client->{client_secret_hash};
}

sub _sanitize_claims {
    my ( $self, $claims ) = @_;
    $claims ||= [];
    return [ grep { Koha::Plugin::Com::Lmscloud::OAuthProvider::ClaimsCatalog->is_valid_key($_) } @$claims ];
}

# Keeps only category codes that actually exist, so a hand-crafted POST
# can't smuggle arbitrary strings into allowed_categories/denied_categories
# (checkbox values in the admin UI already come from this same list, so
# this is defense-in-depth, not the primary safeguard).
sub _sanitize_categories {
    my ( $self, $categories ) = @_;
    $categories ||= [];
    my %valid = map { $_->categorycode => 1 } Koha::Patron::Categories->search->as_list;
    return [ grep { $valid{$_} } @$categories ];
}

# Per-client patron-category access control, gating the login itself at
# /authorize (see Controller::_handle_login) - replaces what used to be the
# global DivibibAuthDisabledForGroups system preference (LMSCloud-fork-only,
# and instance-wide rather than per-client). $client is the hashref shape
# get_client()/list_clients() return (allowed_categories/denied_categories
# already JSON-decoded into arrayrefs).
#
#   denied_categories non-empty and the patron's category is in it      -> not allowed
#   allowed_categories non-empty and the patron's category is NOT in it -> not allowed
#   otherwise                                                            -> allowed
#
# An empty/missing allowed_categories means "no allow-list restriction"
# (every category is fine), matching how every other claim-selection list
# in this plugin defaults to "nothing extra configured" rather than
# "nothing allowed". denied_categories is checked first and wins on
# overlap, so admins can carve out an exception from an otherwise-broad
# allow-list.
sub is_client_allowed_for_patron {
    my ( $self, $client, $patron ) = @_;
    return 1 unless $client;

    my $categorycode = $patron->categorycode;
    return 1 unless defined $categorycode && length $categorycode;

    my $denied = $client->{denied_categories} || [];
    return 0 if grep { lc($_) eq lc($categorycode) } @$denied;

    my $allowed = $client->{allowed_categories} || [];
    return 0 if @$allowed && !grep { lc($_) eq lc($categorycode) } @$allowed;

    return 1;
}

sub _generate_unused_client_id {
    my ($self) = @_;

    my ( $uuid, $uuidstring );
    UUID::generate($uuid);
    UUID::unparse( $uuid, $uuidstring );

    while ( $self->get_client($uuidstring) ) {
        UUID::generate($uuid);
        UUID::unparse( $uuid, $uuidstring );
    }

    return $uuidstring;
}

# =========================== authorization codes ==============================

# Returns the plaintext authorization code.
sub create_authorization_code {
    my ( $self, $args ) = @_;

    my $code      = _random_token(48);
    my $code_hash = sha256_hex($code);
    my $ttl       = $self->settings->{auth_code_ttl_seconds};

    my $dbh   = C4::Context->dbh;
    my $table = $self->_codes_table;
    $dbh->do(
        "INSERT INTO $table
            (code_hash, client_id, borrowernumber, redirect_uri, code_challenge, code_challenge_method, nonce, scope, expires_on, used, created_on)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, DATE_ADD(NOW(), INTERVAL ? SECOND), 0, NOW())",
        undef,
        $code_hash,
        $args->{client_id},
        $args->{borrowernumber},
        $args->{redirect_uri},
        $args->{code_challenge},
        $args->{code_challenge_method},
        $args->{nonce},
        $args->{scope},
        $ttl,
    );

    return $code;
}

# Validates and consumes (marks used) an authorization code. Returns the
# stored row on success, undef otherwise. Does NOT verify PKCE - callers
# must do that themselves using code_challenge/code_challenge_method plus
# the client-supplied code_verifier, since that requires the actual verifier.
sub consume_authorization_code {
    my ( $self, $code, $client_id, $redirect_uri ) = @_;

    my $code_hash = sha256_hex($code);
    my $dbh       = C4::Context->dbh;
    my $table     = $self->_codes_table;

    my $row = $dbh->selectrow_hashref(
        "SELECT * FROM $table WHERE code_hash = ? AND client_id = ? AND used = 0 AND expires_on >= NOW()",
        { Slice => {} }, $code_hash, $client_id,
    );
    return unless $row;
    return unless $row->{redirect_uri} eq $redirect_uri;

    $dbh->do( "UPDATE $table SET used = 1 WHERE id = ?", undef, $row->{id} );

    return $row;
}

# =========================== access / refresh tokens ==============================

# Returns ($access_token, $refresh_token, $access_ttl_seconds). $scope is
# stored on both tokens purely so a later refresh-token exchange can tell
# whether the original grant included 'openid' (and should reissue an
# id_token too) - it is not otherwise interpreted.
sub issue_token_pair {
    my ( $self, $client_id, $borrowernumber, $scope ) = @_;

    my $settings = $self->settings;
    my $access_token  = _random_token(64);
    my $refresh_token = _random_token(64);

    my $dbh   = C4::Context->dbh;
    my $table = $self->_tokens_table;
    $dbh->do(
        "INSERT INTO $table (token_hash, token_type, client_id, borrowernumber, scope, expires_on, revoked, created_on)
         VALUES (?, 'access', ?, ?, ?, DATE_ADD(NOW(), INTERVAL ? SECOND), 0, NOW())",
        undef, sha256_hex($access_token), $client_id, $borrowernumber, $scope, $settings->{access_token_ttl_seconds},
    );
    $dbh->do(
        "INSERT INTO $table (token_hash, token_type, client_id, borrowernumber, scope, expires_on, revoked, created_on)
         VALUES (?, 'refresh', ?, ?, ?, DATE_ADD(NOW(), INTERVAL ? SECOND), 0, NOW())",
        undef, sha256_hex($refresh_token), $client_id, $borrowernumber, $scope, $settings->{refresh_token_ttl_seconds},
    );

    return ( $access_token, $refresh_token, $settings->{access_token_ttl_seconds} );
}

# Returns the token row (with token_type 'access') if valid, else undef.
sub verify_access_token {
    my ( $self, $token ) = @_;
    return unless defined $token && length $token;

    my $dbh   = C4::Context->dbh;
    my $table = $self->_tokens_table;
    return $dbh->selectrow_hashref(
        "SELECT * FROM $table WHERE token_hash = ? AND token_type = 'access' AND revoked = 0 AND expires_on >= NOW()",
        { Slice => {} }, sha256_hex($token),
    );
}

# Consumes (revokes) a refresh token and, if valid, issues a fresh pair.
# Returns ($access_token, $refresh_token, $access_ttl_seconds, $scope) or
# empty list. $scope is the original grant's scope (carried forward from the
# consumed refresh token), so the caller can tell whether to reissue an
# id_token alongside the new access token.
sub rotate_refresh_token {
    my ( $self, $token, $client_id ) = @_;

    my $dbh   = C4::Context->dbh;
    my $table = $self->_tokens_table;
    my $row   = $dbh->selectrow_hashref(
        "SELECT * FROM $table WHERE token_hash = ? AND token_type = 'refresh' AND client_id = ? AND revoked = 0 AND expires_on >= NOW()",
        { Slice => {} }, sha256_hex($token), $client_id,
    );
    return unless $row;

    $dbh->do( "UPDATE $table SET revoked = 1 WHERE id = ?", undef, $row->{id} );

    my ( $access_token, $refresh_token, $ttl ) =
        $self->issue_token_pair( $client_id, $row->{borrowernumber}, $row->{scope} );
    return ( $access_token, $refresh_token, $ttl, $row->{scope}, $row->{borrowernumber} );
}

sub cleanup_expired {
    my ($self) = @_;
    my $dbh = C4::Context->dbh;

    $dbh->do( 'DELETE FROM ' . $self->_codes_table  . ' WHERE used = 1 OR expires_on < NOW()' );
    $dbh->do( 'DELETE FROM ' . $self->_tokens_table . ' WHERE revoked = 1 OR expires_on < NOW()' );

    return 1;
}

# =========================== login -> consent ticket ==============================
#
# Short-lived signed ticket binding a patron's borrowernumber (established at
# login time) to the authorize-request parameters, so the consent step can't
# be tricked into approving access for a different patron via a tampered
# hidden form field.

sub create_login_ticket {
    my ( $self, $payload ) = @_;

    my $ttl = $self->settings->{login_ticket_ttl_seconds};
    my $jwt = Mojo::JWT->new(
        claims => { %$payload, exp => time() + $ttl },
        secret => $self->_ticket_secret,
    );
    return $jwt->encode;
}

sub verify_login_ticket {
    my ( $self, $token ) = @_;
    return unless defined $token && length $token;

    my $claims = try {
        Mojo::JWT->new( secret => $self->_ticket_secret )->decode($token);
    } catch {
        undef;
    };
    return $claims;
}

# =========================== OpenID Connect (id_token / discovery) ==========
#
# id_token is deliberately minimal (only the claims OIDC Core actually
# requires/recommends) - the richer, per-client-configured claim set stays
# userinfo-only, so a client never receives more personal data than it was
# granted just by virtue of completing the login.

sub issue_id_token {
    my ( $self, %args ) = @_;

    my $issuer = $self->settings->{issuer_url};
    my $now    = time();

    my %claims = (
        iss => $issuer,
        sub => "$args{borrowernumber}",
        aud => $args{client_id},
        iat => $now,
        exp => $now + $self->settings->{access_token_ttl_seconds},
        amr => ['pwd'],
    );
    $claims{nonce} = $args{nonce} if defined $args{nonce} && length $args{nonce};

    if ( defined $args{access_token} && length $args{access_token} ) {

        # at_hash: base64url(left-half(SHA-256(access_token))), no padding -
        # lets strict clients confirm the id_token and access_token belong
        # together (OIDC Core 3.1.3.6).
        my $digest    = sha256( $args{access_token} );
        my $left_half = substr( $digest, 0, length($digest) / 2 );
        my $at_hash   = encode_base64url($left_half);
        $at_hash =~ s/=+$//;
        $claims{at_hash} = $at_hash;
    }

    return Mojo::JWT->new( claims => \%claims, secret => $args{client_secret} )->encode;
}

sub wants_openid {
    my ( $self, $scope ) = @_;
    return 0 unless defined $scope && length $scope;
    return scalar( grep { $_ eq 'openid' } split( /\s+/, $scope ) );
}

sub discovery_document {
    my ($self) = @_;

    my $issuer = $self->settings->{issuer_url};
    my @claims = ( 'sub', 'userid', Koha::Plugin::Com::Lmscloud::OAuthProvider::ClaimsCatalog->valid_keys );

    return {
        issuer                                => $issuer,
        authorization_endpoint                => "$issuer/authorize",
        token_endpoint                        => "$issuer/token",
        userinfo_endpoint                     => "$issuer/userinfo",
        jwks_uri                              => "$issuer/jwks",
        response_types_supported             => ['code'],
        subject_types_supported              => ['public'],
        id_token_signing_alg_values_supported => ['HS256'],
        scopes_supported                      => [ 'openid', 'profile', 'address', 'email', 'phone' ],
        token_endpoint_auth_methods_supported => [ 'client_secret_basic', 'client_secret_post' ],
        grant_types_supported                => [ 'authorization_code', 'refresh_token' ],
        code_challenge_methods_supported     => ['S256'],
        claims_supported                     => \@claims,
    };
}

# =========================== public page rendering ==============================
#
# login.tt/consent.tt/error.tt are patron-facing (OPAC context, unauthenticated)
# and rendered standalone via Template Toolkit directly - NOT via get_template(),
# which is hardcoded to the intranet template type and would pull in staff
# chrome that isn't reachable/appropriate for an anonymous OAuth flow.

sub render_standalone_template {
    my ( $self, $file, $vars, $lang ) = @_;

    my $path = $self->mbf_path("templates/$file");
    my $output = '';

    # ABSOLUTE => 1 lets the template's own
    # [% PROCESS "$PLUGIN_DIR/i18n/${LANG}.inc" %] directive (see i18n/,
    # following the pattern from
    # https://koha-community.gitlab.io/KohaAdvent/2020-12-08-translate-plugin/)
    # load an absolute-path include; without it Template Toolkit refuses to
    # PROCESS/INCLUDE anything outside its (here: unset) INCLUDE_PATH.
    my $tt = Template->new( { ABSOLUTE => 1, ENCODING => 'utf8' } );
    $tt->process(
        $path,
        {   %$vars,
            LANG       => $lang || 'en',
            PLUGIN_DIR => $self->bundle_path,
        },
        \$output
    ) or die $tt->error;
    return $output;
}

# =========================== language detection (public pages) =============
#
# configure.tt/tool.tt go through get_template() (C4::Auth::get_template_and_user),
# which already injects LANG (the logged-in staff user's interface language,
# via C4::Languages::getlanguage) and PLUGIN_DIR for free - see Base.pm. The
# public, unauthenticated pages (login/consent/error) have no session and no
# CGI object to hand to that function, so this replicates just the safe,
# per-request-scoped parts of the same logic for a Mojolicious request:
# 'KohaOpacLanguage' cookie, then Accept-Language (via Koha's own
# accept_language() content-negotiation helper), then the library's
# configured OPACLanguages default, then 'en'.
#
# Deliberately NOT calling C4::Languages::getlanguage() itself here: it caches
# its result under a single global, session-unaware cache key, which is fine
# for a short-lived per-request CGI process but would leak one anonymous
# visitor's detected language onto another's response under a persistent
# Mojolicious worker handling many concurrent requests.

sub detect_public_language {
    my ( $self, $c ) = @_;

    my @languages = split /,/, ( C4::Context->preference('OPACLanguages') || '' );
    return 'en' unless @languages;

    my $cookie = $c->req->cookie('KohaOpacLanguage');
    if ( $cookie && grep { $_ eq $cookie->value } @languages ) {
        return $cookie->value;
    }

    my $accept_header = $c->req->headers->accept_language;
    if ($accept_header) {
        my $match = accept_language( $accept_header, [ map { { rfc4646_subtag => $_ } } @languages ] );
        return $match if $match;
    }

    return $languages[0];
}

# =========================== staff admin UI (configure / tool) ==============================

sub configure {
    my ( $self, $args ) = @_;
    my $cgi = $self->{cgi};

    unless ( scalar $cgi->param('action') ) {
        my $edit_id = scalar $cgi->param('edit');
        return $self->_render_configure(
            { edit_client => $edit_id ? $self->get_client_by_row_id($edit_id) : undef } );
    }

    my $action = $cgi->param('action');

    if ( $action eq 'create' ) {
        my ( $client_id, $secret ) = $self->create_client(
            {   client_name        => scalar $cgi->param('client_name'),
                redirect_uris      => $self->_split_lines( scalar $cgi->param('redirect_uris') ),
                allowed_claims     => [ _multi_param( $cgi, 'allowed_claims' ) ],
                allowed_categories => [ _multi_param( $cgi, 'allowed_categories' ) ],
                denied_categories  => [ _multi_param( $cgi, 'denied_categories' ) ],
                is_active          => 1,
            }
        );
        return $self->_render_configure( { new_client_id => $client_id, new_secret => $secret } );
    }
    elsif ( $action eq 'update' ) {
        $self->update_client(
            scalar $cgi->param('id'),
            {   client_name        => scalar $cgi->param('client_name'),
                redirect_uris      => $self->_split_lines( scalar $cgi->param('redirect_uris') ),
                allowed_claims     => [ _multi_param( $cgi, 'allowed_claims' ) ],
                allowed_categories => [ _multi_param( $cgi, 'allowed_categories' ) ],
                denied_categories  => [ _multi_param( $cgi, 'denied_categories' ) ],
                is_active          => $cgi->param('is_active') ? 1 : 0,
            }
        );
    }
    elsif ( $action eq 'delete' ) {
        $self->delete_client( scalar $cgi->param('id') );
    }
    elsif ( $action eq 'regenerate_secret' ) {
        my $secret = $self->regenerate_secret( scalar $cgi->param('id') );
        my $client = $self->get_client_by_row_id( scalar $cgi->param('id') );
        return $self->_render_configure( { new_client_id => $client->{client_id}, new_secret => $secret } );
    }
    elsif ( $action eq 'save_settings' ) {
        my $issuer_url = scalar $cgi->param('issuer_url') // '';
        $issuer_url =~ s{/+$}{};    # strip trailing slash - endpoints are built as "$issuer/authorize" etc.
        $self->save_settings( { issuer_url => $issuer_url } );
    }

    print $cgi->redirect(
        -uri => '/cgi-bin/koha/plugins/run.pl?class=' . uri_escape( ref($self) ) . '&method=configure' );
    return;
}

sub _render_configure {
    my ( $self, $extra ) = @_;
    $extra ||= {};

    my $cgi      = $self->{cgi};
    my $template = $self->get_template( { file => 'configure.tt' } );

    my @categories =
        map { { categorycode => $_->categorycode, description => $_->description } }
        Koha::Patron::Categories->search( {}, { order_by => 'categorycode' } )->as_list;

    $template->param(
        clients          => $self->list_clients,
        claims_catalog   => Koha::Plugin::Com::Lmscloud::OAuthProvider::ClaimsCatalog->catalog,
        patron_categories => \@categories,
        settings         => $self->settings,
        base_url         => C4::Context->preference('staffClientBaseURL') || '',
        class_name       => uri_escape( ref($self) ),
        # Raw (unescaped) class name for hidden form fields - forms submit
        # their own class/method fields so plugins/run.pl's dispatch doesn't
        # depend on the browser preserving this page's query string on a
        # same-page POST (some browsers drop it when <form> has no explicit
        # action; Koha::Plugins::Handler::run() then gets an undef $method
        # and warns "Plugin does not have method"). uri_escape'd class_name
        # above is for embedding directly in an href's query string instead
        # - do not reuse it here, the browser already encodes form values.
        plugin_class     => ref($self),
        %$extra,
    );

    print $cgi->header( -charset => 'utf-8' );
    print $template->output;
    return;
}

sub tool {
    my ( $self, $args ) = @_;
    my $cgi = $self->{cgi};

    if ( $cgi->param('cleanup') ) {
        $self->cleanup_expired;
    }

    my $dbh          = C4::Context->dbh;
    my $tokens_table = $self->_tokens_table;
    my $active_tokens = $dbh->selectall_arrayref(
        "SELECT t.*, c.client_name FROM $tokens_table t
            LEFT JOIN " . $self->_clients_table . " c ON c.client_id = t.client_id
         WHERE t.revoked = 0 AND t.expires_on >= NOW()
         ORDER BY t.created_on DESC LIMIT 200",
        { Slice => {} }
    );

    my $template = $self->get_template( { file => 'tool.tt' } );
    $template->param( active_tokens => $active_tokens, plugin_class => ref($self) );

    print $cgi->header( -charset => 'utf-8' );
    print $template->output;
    return;
}

sub _split_lines {
    my ( $self, $text ) = @_;
    return [] unless defined $text;
    return [ grep { length $_ } map { s/^\s+|\s+$//gr } split /\r?\n/, $text ];
}

# CGI.pm only gained multi_param() in 4.08; the Koha cpanfile floor is 3.15,
# so fall back to param() in list context on older installs.
sub _multi_param {
    my ( $cgi, $name ) = @_;
    return $cgi->can('multi_param') ? $cgi->multi_param($name) : $cgi->param($name);
}

1;
