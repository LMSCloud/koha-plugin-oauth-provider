package Koha::Plugin::Com::LMSCloud::OAuthProvider::Controller;

use Modern::Perl;

use Mojo::Base 'Mojolicious::Controller';
use Mojo::URL;

use C4::Auth qw(checkpw_internal);
use C4::Context;
use Digest::SHA qw(sha256);
use MIME::Base64 qw(decode_base64 encode_base64url);

use Koha::Auth::TwoFactorAuth;
use Koha::Patron::Attribute::Types;
use Koha::Patrons;

# Mojolicious autoloads this controller purely off the x-mojo-to string in
# api_routes.json; it does not guarantee the main plugin package is loaded,
# so pull it in explicitly (same pattern as the eID-verification plugin).
use Koha::Plugin::Com::LMSCloud::OAuthProvider;
use Koha::Plugin::Com::LMSCloud::OAuthProvider::ClaimsCatalog;

use constant PLUGIN_CLASS => 'Koha::Plugin::Com::LMSCloud::OAuthProvider';

# =========================== GET /authorize ==============================

sub authorize_get {
    my $c = shift->openapi->valid_input or return;

    my $plugin = PLUGIN_CLASS->new();
    my $v      = $c->validation;

    my $client_id     = $v->param('client_id');
    my $redirect_uri  = $v->param('redirect_uri');
    my $response_type = $v->param('response_type');
    my $state         = $v->param('state');
    my $code_challenge        = $v->param('code_challenge');
    my $code_challenge_method = $v->param('code_challenge_method');
    my $scope         = $v->param('scope');
    my $nonce         = $v->param('nonce');

    my $client = $plugin->get_client($client_id);
    unless ( $client && $client->{is_active} ) {
        return _render_error( $c, $plugin, 'unauthorized_client' );
    }
    unless ( $redirect_uri && grep { $_ eq $redirect_uri } @{ $client->{redirect_uris} } ) {
        return _render_error( $c, $plugin, 'invalid_redirect_uri' );
    }

    # From here on redirect_uri is trusted (registered for this client), so
    # further errors can be safely reported back to the client via redirect.
    unless ( $response_type && $response_type eq 'code' ) {
        return _redirect_with_error( $c, $redirect_uri, 'unsupported_response_type', $state );
    }
    if ( $code_challenge_method && $code_challenge_method ne 'S256' ) {

        # 'plain' PKCE is intentionally not supported.
        return _redirect_with_error( $c, $redirect_uri, 'invalid_request', $state );
    }

    return _render_login(
        $c, $plugin,
        {   client_id             => $client_id,
            client_name           => $client->{client_name},
            redirect_uri          => $redirect_uri,
            state                 => $state,
            code_challenge        => $code_challenge,
            code_challenge_method => $code_challenge_method,
            scope                 => $scope,
            nonce                 => $nonce,
            error                 => undef,
        }
    );
}

# =========================== POST /authorize ==============================
#
# Handles all steps of the flow via a hidden 'stage' field: 'login' (userid
# + password), 'otp' (one-time code, only for patrons with 2FA enabled -
# gated by a signed ticket minted at the end of the login step) and
# 'consent' (allow/deny, gated by a signed ticket minted at the end of the
# login/otp step).

sub authorize_post {
    my $c = shift->openapi->valid_input or return;

    my $plugin = PLUGIN_CLASS->new();
    my $stage  = $c->validation->param('stage') // 'login';

    return _handle_consent( $c, $plugin ) if $stage eq 'consent';
    return _handle_otp( $c, $plugin ) if $stage eq 'otp';
    return _handle_login( $c, $plugin );
}

sub _handle_login {
    my ( $c, $plugin ) = @_;
    my $v = $c->validation;

    my $client_id = $v->param('client_id');
    my $redirect_uri = $v->param('redirect_uri');

    my $client = $plugin->get_client($client_id);
    unless ( $client && $client->{is_active} ) {
        return _render_error( $c, $plugin, 'unauthorized_client' );
    }
    unless ( $redirect_uri && grep { $_ eq $redirect_uri } @{ $client->{redirect_uris} } ) {
        return _render_error( $c, $plugin, 'invalid_redirect_uri' );
    }

    my $authz_ctx = {
        client_id             => $client_id,
        client_name           => $client->{client_name},
        redirect_uri          => $redirect_uri,
        state                 => $v->param('state'),
        code_challenge        => $v->param('code_challenge'),
        code_challenge_method => $v->param('code_challenge_method'),
        scope                 => $v->param('scope'),
        nonce                 => $v->param('nonce'),
    };

    my $userid   = $v->param('userid');
    my $password = $v->param('password');

    unless ( defined $userid && length $userid && defined $password && length $password ) {
        return _render_login( $c, $plugin, { %$authz_ctx, error => 'missing_credentials' } );
    }

    # checkpw_internal accepts either a userid or a cardnumber and returns
    # (1, $cardnumber, $userid, $patron) on success, or 0 on failure. Login
    # attempt tracking / account lockout is handled by Koha itself inside
    # checkpw_internal, so no separate rate limiting is needed here.
    my ( $ok, undef, undef, $patron ) = checkpw_internal( $userid, $password, 1 );
    unless ( $ok && $patron ) {
        return _render_login( $c, $plugin, { %$authz_ctx, error => 'invalid_credentials' } );
    }

    # Per-client patron-category allow-list/deny-list, checked only now that
    # we actually know who logged in - redirect_uri is already trusted at
    # this point, so a rejection is reported back to the client the same way
    # a denied consent is (error=access_denied), not as a standalone error
    # page. This patron simply never gets a code/token for this client.
    unless ( $plugin->is_client_allowed_for_patron( $client, $patron ) ) {
        return _redirect_with_error( $c, $redirect_uri, 'access_denied', $authz_ctx->{state} );
    }

    # checkpw_internal() only verifies the password - it knows nothing about
    # Koha's own two-factor authentication (that lives entirely inside
    # C4::Auth::checkauth()'s session-based flow, which this plugin never
    # goes through, on purpose - see create_login_ticket's doc). A patron who
    # has 2FA enabled must not be able to fully authenticate via this plugin
    # with just their password, so that check is replicated here explicitly.
    if ( _patron_requires_2fa($patron) ) {
        my $ticket = $plugin->create_login_ticket(
            {   borrowernumber => $patron->borrowernumber,
                %$authz_ctx,
            }
        );
        return _render_otp( $c, $plugin, { %$authz_ctx, ticket => $ticket, error => undef } );
    }

    return _proceed_after_authentication( $c, $plugin, $client, $client_id, $patron, $authz_ctx );
}

# True if this patron must pass a one-time-code challenge before this plugin
# considers them authenticated: Koha's 2FA system preference is not
# 'disabled', and the patron has actually completed 2FA enrollment (has a
# secret on file). Deliberately does NOT replicate the 'enforced' mode's
# behaviour of *requiring* not-yet-enrolled patrons to set up 2FA there and
# then - that needs a QR-code enrollment UI this plugin doesn't have, and is
# out of scope for "accounts where 2FA is already enabled".
sub _patron_requires_2fa {
    my ($patron) = @_;
    return 0 if C4::Context->preference('TwoFactorAuthentication') eq 'disabled';
    return $patron->secret ? 1 : 0;
}

sub _handle_otp {
    my ( $c, $plugin ) = @_;
    my $v = $c->validation;

    my $ticket   = $v->param('ticket');
    my $otp_code = $v->param('otp_token');

    # Same trust model as the consent ticket: client_id, redirect_uri,
    # borrowernumber, PKCE challenge/method, scope, state and nonce all come
    # from the signed ticket minted at the end of the login step, never from
    # client-submitted form fields.
    my $claims = $plugin->verify_login_ticket($ticket);
    unless ( $claims && $claims->{client_id} && $claims->{redirect_uri} && $claims->{borrowernumber} ) {
        return _render_error( $c, $plugin, 'invalid_request' );
    }

    my $client = $plugin->get_client( $claims->{client_id} );
    unless ( $client && $client->{is_active} ) {
        return _render_error( $c, $plugin, 'unauthorized_client' );
    }

    my $patron = Koha::Patrons->find( $claims->{borrowernumber} );
    unless ( $patron && _patron_requires_2fa($patron) ) {
        return _render_error( $c, $plugin, 'invalid_request' );
    }

    my $authz_ctx = {
        client_id             => $claims->{client_id},
        client_name           => $client->{client_name},
        redirect_uri          => $claims->{redirect_uri},
        state                 => $claims->{state},
        code_challenge        => $claims->{code_challenge},
        code_challenge_method => $claims->{code_challenge_method},
        scope                 => $claims->{scope},
        nonce                 => $claims->{nonce},
    };

    my $auth = Koha::Auth::TwoFactorAuth->new( { patron => $patron } );
    my $verified = $otp_code && length($otp_code) && $auth->verify($otp_code);
    $auth->clear;
    unless ($verified) {
        return _render_otp( $c, $plugin, { %$authz_ctx, ticket => $ticket, error => 'invalid_otp' } );
    }

    return _proceed_after_authentication( $c, $plugin, $client, $claims->{client_id}, $patron, $authz_ctx );
}

# Shared tail of the login step, reached either straight from _handle_login
# (no 2FA required) or from _handle_otp (2FA required and the code checked
# out) - decides whether the consent screen can be skipped (consent_mode)
# and either mints the authorization code right away or shows consent.tt.
sub _proceed_after_authentication {
    my ( $c, $plugin, $client, $client_id, $patron, $authz_ctx ) = @_;

    # consent_mode 'never' always skips the consent screen; 'remember' skips
    # it only once a prior consent already covers every claim the client is
    # *currently* configured to receive (see
    # OAuthProvider::consent_covers) - so widening a client's allowed_claims
    # later makes patrons see the consent screen again, on the very first
    # login after that change.
    my $claim_keys = _claim_names_for_client($client);
    if (   $client->{consent_mode} eq 'never'
        || ( $client->{consent_mode} eq 'remember'
            && $plugin->consent_covers( $client_id, $patron->borrowernumber, $claim_keys ) ) )
    {
        my $code = $plugin->create_authorization_code(
            {   client_id             => $client_id,
                borrowernumber        => $patron->borrowernumber,
                redirect_uri          => $authz_ctx->{redirect_uri},
                code_challenge        => $authz_ctx->{code_challenge},
                code_challenge_method => $authz_ctx->{code_challenge_method},
                nonce                 => $authz_ctx->{nonce},
                scope                 => $authz_ctx->{scope},
            }
        );
        return _redirect_with_code( $c, $authz_ctx->{redirect_uri}, $code, $authz_ctx->{state} );
    }

    my $ticket = $plugin->create_login_ticket(
        {   borrowernumber => $patron->borrowernumber,
            %$authz_ctx,
        }
    );

    return _render_consent( $c, $plugin, $client, $patron, { %$authz_ctx, ticket => $ticket } );
}

sub _handle_consent {
    my ( $c, $plugin ) = @_;
    my $v = $c->validation;

    my $ticket   = $v->param('ticket');
    my $decision = $v->param('consent') // 'deny';

    # Everything security-relevant (client_id, redirect_uri, borrowernumber,
    # PKCE challenge/method, state) comes from the signed ticket minted at
    # the end of the login step - never from client-submitted form fields -
    # so a tampered hidden field can't redirect the code to a different
    # client/redirect_uri or bind it to a different patron.
    my $claims = $plugin->verify_login_ticket($ticket);
    unless ( $claims && $claims->{client_id} && $claims->{redirect_uri} ) {
        return _render_error( $c, $plugin, 'invalid_request' );
    }

    if ( $decision ne 'allow' ) {
        return _redirect_with_error( $c, $claims->{redirect_uri}, 'access_denied', $claims->{state} );
    }

    my $client = $plugin->get_client( $claims->{client_id} );
    if ( $client && $client->{consent_mode} eq 'remember' ) {
        $plugin->remember_consent(
            $claims->{client_id}, $claims->{borrowernumber}, _claim_names_for_client($client) );
    }

    my $code = $plugin->create_authorization_code(
        {   client_id             => $claims->{client_id},
            borrowernumber        => $claims->{borrowernumber},
            redirect_uri          => $claims->{redirect_uri},
            code_challenge        => $claims->{code_challenge},
            code_challenge_method => $claims->{code_challenge_method},
            nonce                 => $claims->{nonce},
            scope                 => $claims->{scope},
        }
    );

    return _redirect_with_code( $c, $claims->{redirect_uri}, $code, $claims->{state} );
}

# =========================== POST /token ==============================

sub token {
    my $c = shift->openapi->valid_input or return;

    my $plugin = PLUGIN_CLASS->new();
    my $v      = $c->validation;

    my $grant_type = $v->param('grant_type') // '';

    my ( $client_id, $client_secret ) = _extract_client_credentials($c);
    my $client = $client_id ? $plugin->get_client($client_id) : undef;

    unless ( $client
        && $client->{is_active}
        && $plugin->verify_client_secret( $client, $client_secret ) )
    {
        # Never logs the secret itself - just enough to tell apart the five
        # distinct ways this can fail, since the client only ever sees a
        # generic 401/invalid_client either way (RFC 6749 doesn't want a
        # more specific error here, to avoid helping an attacker enumerate
        # valid client_ids). Distinguishing "no secret received at all" from
        # "a secret was received but didn't match" matters here: the former
        # points at how the RP is transmitting credentials (Basic-Auth vs.
        # POST body), the latter at what secret is actually configured.
        my $auth_header_present = defined $c->req->headers->authorization && length $c->req->headers->authorization;
        my $reason =
              !$client_id                                     ? 'no client credentials received (neither an Authorization: Basic header nor client_id/client_secret form fields)'
            : !$client                                        ? "unknown client_id '$client_id'"
            : !$client->{is_active}                            ? "client '$client_id' is deactivated"
            : ( !defined $client_secret || !length $client_secret )
                  ? "client_id '$client_id' received but no client_secret at all (Authorization header present: "
                    . ( $auth_header_present ? 'yes' : 'no' ) . ')'
            :                                                     "client_secret did not match for '$client_id' (received: "
                    . _mask_secret_preview($client_secret) . ", via "
                    . ( $auth_header_present ? 'Authorization header' : 'form field' )
                    . ", stored hash uses " . _bcrypt_prefix( $client->{client_secret_hash} ) . ')';
        $c->app->log->warn("OAuthProvider /token: invalid_client - $reason");
        return $c->render( json => { error => 'invalid_client' }, status => 401 );
    }

    if ( $grant_type eq 'authorization_code' ) {
        return _token_from_authorization_code( $c, $plugin, $client, $client_secret, $v );
    }
    elsif ( $grant_type eq 'refresh_token' ) {
        return _token_from_refresh_token( $c, $plugin, $client, $client_secret, $v );
    }

    return $c->render( json => { error => 'unsupported_grant_type' }, status => 400 );
}

# Diagnostic-only, temporary: shows just enough of a rejected secret to
# compare it against the known-correct value by eye (first/last 4 chars,
# total length) without logging anything close to the full secret.
sub _mask_secret_preview {
    my ($secret) = @_;
    my $len = length($secret);
    return "<empty>" unless $len;
    return "'$secret' (length $len)" if $len <= 8;
    return "'" . substr( $secret, 0, 4 ) . ('*' x ( $len - 8 )) . substr( $secret, -4 ) . "' (length $len)";
}

# Diagnostic-only, temporary: the bcrypt algorithm id + cost factor prefix
# (e.g. "$2a$08$") is not sensitive (no salt/hash material beyond what's
# needed to identify the settings used) - useful to rule out a cost/format
# mismatch between what created the hash and what's verifying it.
sub _bcrypt_prefix {
    my ($hash) = @_;
    return 'n/a' unless defined $hash;
    return $1 if $hash =~ /^(\$2[abxy]?\$\d+\$)/;
    return "unrecognized format (length " . length($hash) . ")";
}

sub _extract_client_credentials {
    my ($c) = @_;

    my $auth_header = $c->req->headers->authorization;
    if ( $auth_header && $auth_header =~ /^Basic\s+(.+)$/i ) {
        my $decoded = eval { decode_base64($1) };
        if ( $decoded && $decoded =~ /^([^:]*):(.*)$/s ) {
            return ( $1, $2 );
        }
    }

    my $v = $c->validation;
    return ( scalar $v->param('client_id'), scalar $v->param('client_secret') );
}

sub _token_from_authorization_code {
    my ( $c, $plugin, $client, $client_secret, $v ) = @_;

    my $code          = $v->param('code');
    my $redirect_uri  = $v->param('redirect_uri');
    my $code_verifier = $v->param('code_verifier');

    unless ( $code && $redirect_uri ) {
        return $c->render( json => { error => 'invalid_request' }, status => 400 );
    }

    my $row = $plugin->consume_authorization_code( $code, $client->{client_id}, $redirect_uri );
    unless ($row) {
        return $c->render( json => { error => 'invalid_grant' }, status => 400 );
    }

    if ( $row->{code_challenge} ) {
        unless ( $code_verifier
            && _pkce_matches( $row->{code_challenge}, $row->{code_challenge_method}, $code_verifier ) )
        {
            return $c->render( json => { error => 'invalid_grant' }, status => 400 );
        }
    }

    my ( $access_ttl, $refresh_ttl ) = $plugin->effective_ttls($client);
    my ( $access_token, $refresh_token, $ttl ) =
        $plugin->issue_token_pair( $client->{client_id}, $row->{borrowernumber}, $row->{scope}, $access_ttl, $refresh_ttl );

    my %response = (
        access_token  => $access_token,
        token_type    => 'Bearer',
        expires_in    => $ttl + 0,
        refresh_token => $refresh_token,
    );

    if ( $plugin->wants_openid( $row->{scope} ) ) {
        $response{id_token} = $plugin->issue_id_token(
            client_id      => $client->{client_id},
            client_secret  => $client_secret,
            borrowernumber => $row->{borrowernumber},
            nonce          => $row->{nonce},
            access_token   => $access_token,
            access_ttl     => $ttl,
        );
    }

    return $c->render( json => \%response );
}

sub _token_from_refresh_token {
    my ( $c, $plugin, $client, $client_secret, $v ) = @_;

    my $refresh_token = $v->param('refresh_token');
    unless ($refresh_token) {
        return $c->render( json => { error => 'invalid_request' }, status => 400 );
    }

    my ( $access_token, $new_refresh_token, $ttl, $scope, $borrowernumber ) =
        $plugin->rotate_refresh_token( $refresh_token, $client->{client_id} );
    unless ($access_token) {
        return $c->render( json => { error => 'invalid_grant' }, status => 400 );
    }

    my %response = (
        access_token  => $access_token,
        token_type    => 'Bearer',
        expires_in    => $ttl + 0,
        refresh_token => $new_refresh_token,
    );

    # No 'nonce' here on purpose: nonce is tied to the original
    # authentication request/consent, not to each token refresh.
    if ( $plugin->wants_openid($scope) ) {
        $response{id_token} = $plugin->issue_id_token(
            client_id      => $client->{client_id},
            client_secret  => $client_secret,
            borrowernumber => $borrowernumber,
            access_token   => $access_token,
            access_ttl     => $ttl,
        );
    }

    return $c->render( json => \%response );
}

sub _pkce_matches {
    my ( $challenge, $method, $verifier ) = @_;
    $method ||= 'S256';
    return 0 unless $method eq 'S256';

    my $computed = encode_base64url( sha256($verifier) );
    $computed =~ s/=+$//;
    ( my $stored = $challenge ) =~ s/=+$//;

    return $computed eq $stored;
}

# =========================== GET /userinfo ==============================

sub userinfo {
    my $c = shift->openapi->valid_input or return;

    my $plugin = PLUGIN_CLASS->new();

    my $auth_header = $c->req->headers->authorization // '';
    unless ( $auth_header =~ /^Bearer\s+(.+)$/i ) {
        $c->app->log->warn(
            'OAuthProvider /userinfo: invalid_token - no (or malformed) Authorization header ('
            . ( length($auth_header) ? "received: '$auth_header'" : 'header absent/empty' ) . ')'
        );
        $c->res->headers->www_authenticate('Bearer realm="oauthprovider"');
        return $c->render( json => { error => 'invalid_token' }, status => 401 );
    }
    my $token = $1;

    my $row = $plugin->verify_access_token($token);
    unless ($row) {
        $c->app->log->warn(
            'OAuthProvider /userinfo: invalid_token - access token not found/expired/revoked (token length '
            . length($token) . ')'
        );
        $c->res->headers->www_authenticate('Bearer realm="oauthprovider", error="invalid_token"');
        return $c->render( json => { error => 'invalid_token' }, status => 401 );
    }

    my $client = $plugin->get_client( $row->{client_id} );
    my $patron = Koha::Patrons->find( $row->{borrowernumber} );
    unless ( $client && $patron ) {
        $c->app->log->warn(
            "OAuthProvider /userinfo: invalid_token - token valid but "
            . ( !$client ? "client '$row->{client_id}' no longer exists" : "borrowernumber $row->{borrowernumber} no longer exists" )
        );
        return $c->render( json => { error => 'invalid_token' }, status => 401 );
    }

    my $claims =
        Koha::Plugin::Com::LMSCloud::OAuthProvider::ClaimsCatalog->build_claims( $patron, $client->{allowed_claims} );

    return $c->render( json => $claims );
}

# =========================== OIDC discovery / jwks ==============================
#
# Served under the plugin's own /api/v1/contrib/oauthprovider/ path, not the
# spec-mandated /.well-known/openid-configuration at the domain root - Koha
# plugin routes cannot be mounted outside /api/v1/contrib/<namespace>/. Full
# conformance needs an administrator-configured webserver rewrite; see the
# README.

sub discovery {
    my $c = shift->openapi->valid_input or return;
    my $plugin = PLUGIN_CLASS->new();
    return $c->render( json => $plugin->discovery_document );
}

sub jwks {
    my $c = shift->openapi->valid_input or return;

    # Confidential-clients-only design: id_tokens are signed HS256 with each
    # client's own client_secret as the shared HMAC key, so there is no
    # asymmetric keypair and nothing to publish here. This stub exists only
    # so clients/libraries that unconditionally fetch jwks_uri get a valid
    # (empty) response instead of a 404.
    return $c->render( json => { keys => [] } );
}

# =========================== rendering helpers ==============================

sub _render_login {
    my ( $c, $plugin, $ctx ) = @_;
    my $lang  = $plugin->detect_public_language($c);
    # Pass the current route's own URL (no query string) as the form's
    # action: the query string carries the original authorize params, and
    # an empty action="" would make the browser resubmit those as a query
    # string on the POST too, which
    # Koha::REST::V1::Auth::validate_query_parameters rejects since POST
    # /authorize only declares them as formData. Resolved via url_for
    # ('current') rather than $c->req->url->path, since the latter comes
    # back without its leading slash behind this app's reverse-proxy
    # mount point, which turns it into a relative URL in the browser and
    # duplicates the mount prefix.
    my $html  = $plugin->render_standalone_template( 'login.tt', { %$ctx, action_path => $c->url_for('current') }, $lang );
    return $c->render( text => $html, format => 'html' );
}

sub _render_otp {
    my ( $c, $plugin, $ctx ) = @_;
    my $lang = $plugin->detect_public_language($c);
    my $html = $plugin->render_standalone_template( 'otp.tt', { %$ctx, action_path => $c->url_for('current') }, $lang );
    return $c->render( text => $html, format => 'html' );
}

sub _render_consent {
    my ( $c, $plugin, $client, $patron, $ctx ) = @_;

    my $lang = $plugin->detect_public_language($c);
    my $html = $plugin->render_standalone_template(
        'consent.tt',
        {   client_name  => $client->{client_name},
            consent_rows => _consent_rows_for_client($client),
            ticket       => $ctx->{ticket},
            action_path  => $c->url_for('current'),
        },
        $lang
    );
    return $c->render( text => $html, format => 'html' );
}

# The flat list of output claim names (the actual /userinfo keys) this
# client currently releases - 'userid' first (always released, not part of
# the configurable claim list), then each configured claim's own
# admin-chosen claim_name. Used for consent_covers()/remember_consent()
# comparisons, where only the *names* matter, not how each is sourced.
sub _claim_names_for_client {
    my ($client) = @_;
    return [ 'userid', map { $_->{claim_name} } @{ $client->{allowed_claims} || [] } ];
}

# Per-claim display rows for the consent screen: {claim_name, label_key} for
# a translated label (field-sourced claims, incl. the always-present
# 'userid'), or {claim_name, label_literal} for a plain-text label (extended
# attributes use their own Koha-configured description; fixed-value claims
# have no natural human label beyond their own claim name).
sub _consent_rows_for_client {
    my ($client) = @_;

    my @rows = ( { claim_name => 'userid', label_key => 'claim_label_userid' } );
    for my $entry ( @{ $client->{allowed_claims} || [] } ) {
        if ( $entry->{type} eq 'field' ) {
            push @rows, { claim_name => $entry->{claim_name}, label_key => 'claim_label_' . $entry->{source} };
        }
        elsif ( $entry->{type} eq 'attribute' ) {
            my $attribute_type = Koha::Patron::Attribute::Types->find( $entry->{source} );
            push @rows,
                {   claim_name    => $entry->{claim_name},
                    label_literal => $attribute_type ? $attribute_type->description : $entry->{source},
                };
        }
        else {    # 'static'
            push @rows, { claim_name => $entry->{claim_name}, label_literal => $entry->{claim_name} };
        }
    }
    return \@rows;
}

sub _render_error {
    my ( $c, $plugin, $error_code ) = @_;
    my $lang = $plugin->detect_public_language($c);
    my $html = $plugin->render_standalone_template( 'error.tt', { error_code => $error_code }, $lang );
    return $c->render( text => $html, format => 'html', status => 400 );
}

sub _redirect_with_error {
    my ( $c, $redirect_uri, $error, $state ) = @_;
    my $uri = Mojo::URL->new($redirect_uri);
    $uri->query->append( error => $error );
    $uri->query->append( state => $state ) if defined $state && length $state;
    return $c->redirect_to($uri);
}

sub _redirect_with_code {
    my ( $c, $redirect_uri, $code, $state ) = @_;
    my $uri = Mojo::URL->new($redirect_uri);
    $uri->query->append( code => $code );
    $uri->query->append( state => $state ) if defined $state && length $state;
    return $c->redirect_to($uri);
}

1;
