package Koha::Plugin::Com::Lmscloud::OAuthProvider::Controller;

use Modern::Perl;

use Mojo::Base 'Mojolicious::Controller';
use Mojo::URL;

use C4::Auth qw(checkpw_internal);
use Digest::SHA qw(sha256);
use MIME::Base64 qw(decode_base64 encode_base64url);

use Koha::Patrons;

# Mojolicious autoloads this controller purely off the x-mojo-to string in
# api_routes.json; it does not guarantee the main plugin package is loaded,
# so pull it in explicitly (same pattern as the eID-verification plugin).
use Koha::Plugin::Com::Lmscloud::OAuthProvider;
use Koha::Plugin::Com::Lmscloud::OAuthProvider::ClaimsCatalog;

use constant PLUGIN_CLASS => 'Koha::Plugin::Com::Lmscloud::OAuthProvider';

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
# Handles both steps of the flow via a hidden 'stage' field: 'login' (userid
# + password) and 'consent' (allow/deny, gated by a signed ticket minted at
# the end of the login step).

sub authorize_post {
    my $c = shift->openapi->valid_input or return;

    my $plugin = PLUGIN_CLASS->new();
    my $stage  = $c->validation->param('stage') // 'login';

    return _handle_consent( $c, $plugin ) if $stage eq 'consent';
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

    my ( $access_token, $refresh_token, $ttl ) =
        $plugin->issue_token_pair( $client->{client_id}, $row->{borrowernumber}, $row->{scope} );

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
        $c->res->headers->www_authenticate('Bearer realm="oauthprovider"');
        return $c->render( json => { error => 'invalid_token' }, status => 401 );
    }
    my $token = $1;

    my $row = $plugin->verify_access_token($token);
    unless ($row) {
        $c->res->headers->www_authenticate('Bearer realm="oauthprovider", error="invalid_token"');
        return $c->render( json => { error => 'invalid_token' }, status => 401 );
    }

    my $client = $plugin->get_client( $row->{client_id} );
    my $patron = Koha::Patrons->find( $row->{borrowernumber} );
    unless ( $client && $patron ) {
        return $c->render( json => { error => 'invalid_token' }, status => 401 );
    }

    my $claims =
        Koha::Plugin::Com::Lmscloud::OAuthProvider::ClaimsCatalog->build_claims( $patron, $client->{allowed_claims} );

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
    my $html  = $plugin->render_standalone_template( 'login.tt', $ctx, $lang );
    return $c->render( text => $html, format => 'html' );
}

sub _render_consent {
    my ( $c, $plugin, $client, $patron, $ctx ) = @_;

    my %allowed = map { $_ => 1 } @{ $client->{allowed_claims} };
    # 'userid' first (always released, not part of the catalog), then
    # whichever catalog keys this client is allowed. The template looks up
    # the translated label for each key itself (translation key
    # "claim_label_<key>") - no display text is built here.
    my @claim_keys = ('userid');
    for my $entry ( @{ Koha::Plugin::Com::Lmscloud::OAuthProvider::ClaimsCatalog->catalog } ) {
        push @claim_keys, $entry->{key} if $allowed{ $entry->{key} };
    }

    my $lang = $plugin->detect_public_language($c);
    my $html = $plugin->render_standalone_template(
        'consent.tt',
        {   client_name => $client->{client_name},
            claim_keys  => \@claim_keys,
            ticket      => $ctx->{ticket},
        },
        $lang
    );
    return $c->render( text => $html, format => 'html' );
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
