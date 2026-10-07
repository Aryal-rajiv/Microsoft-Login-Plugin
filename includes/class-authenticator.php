<?php
/**
 * OpenID Connect sign-in flow with Microsoft Entra ID.
 *
 * @package MSEntraSSO
 */

namespace MSEntraSSO;

use WP_Error;
use WP_User;

defined( 'ABSPATH' ) || exit;

/**
 * Implements the OAuth 2.0 authorization code flow (with PKCE) against the
 * Microsoft identity platform v2.0 endpoint and signs the user in to WordPress.
 */
class Authenticator {

	/**
	 * Login action that starts the flow: wp-login.php?action=msentra_sso.
	 */
	const ACTION = 'msentra_sso';

	/**
	 * Cookie that binds the pending sign-in to the browser that started it.
	 */
	const STATE_COOKIE = 'msentra_sso_state';

	/**
	 * Query argument used to report errors back to the login page.
	 */
	const ERROR_ARG = 'msentra_sso_error';

	/**
	 * User meta key holding the linked Entra identity ("<tenant id>:<object id>").
	 */
	const META_IDENTITY = 'msentra_sso_identity';

	/**
	 * Lifetime of a pending sign-in, in seconds.
	 */
	const STATE_TTL = 600;

	/**
	 * Tenant ID Microsoft uses for personal Microsoft accounts.
	 */
	const CONSUMER_TENANT = '9188040d-6c67-4c5b-b112-36a304b66dad';

	/**
	 * Set while a user is being signed in, so the session can be flagged.
	 *
	 * @var bool
	 */
	private $signing_in = false;

	/**
	 * Set when the user being logged out signed in with Microsoft.
	 *
	 * @var bool
	 */
	private $logout_from_microsoft = false;

	/**
	 * Registers hooks.
	 */
	public function register() {
		add_action( 'login_form_' . self::ACTION, array( $this, 'start' ) );
		add_action( 'login_init', array( $this, 'maybe_handle_callback' ), 1 );
		add_filter( 'attach_session_information', array( $this, 'flag_session' ) );
		add_action( 'login_form_logout', array( $this, 'detect_sso_logout' ) );
		add_filter( 'logout_redirect', array( $this, 'logout_redirect' ), 99 );
		add_filter( 'allowed_redirect_hosts', array( $this, 'allowed_redirect_hosts' ) );
	}

	/**
	 * URL that starts the Microsoft sign-in flow.
	 *
	 * @param string $redirect_to Optional URL to return to after signing in.
	 * @return string
	 */
	public static function login_url( $redirect_to = '' ) {
		$url = add_query_arg( 'action', self::ACTION, wp_login_url() );
		if ( '' !== $redirect_to ) {
			$url = add_query_arg( 'redirect_to', rawurlencode( $redirect_to ), $url );
		}
		return $url;
	}

	/**
	 * Host of the Microsoft identity platform (changeable for national clouds).
	 *
	 * @return string
	 */
	public static function authority_host() {
		/**
		 * Filters the Microsoft identity platform host, e.g. for national clouds
		 * such as login.microsoftonline.us or login.chinacloudapi.cn.
		 *
		 * @param string $host Host name without scheme.
		 */
		return (string) apply_filters( 'msentra_sso_authority_host', 'login.microsoftonline.com' );
	}

	/**
	 * Base URL of the Microsoft Graph API (changeable for national clouds).
	 *
	 * @return string
	 */
	public static function graph_url() {
		/**
		 * Filters the Microsoft Graph base URL.
		 *
		 * @param string $url Graph URL without a trailing slash.
		 */
		return untrailingslashit( (string) apply_filters( 'msentra_sso_graph_url', 'https://graph.microsoft.com' ) );
	}

	/**
	 * Builds an endpoint URL for the configured tenant.
	 *
	 * @param string $path Endpoint path, e.g. "oauth2/v2.0/token".
	 * @return string
	 */
	private static function endpoint( $path ) {
		return sprintf( 'https://%s/%s/%s', self::authority_host(), rawurlencode( Settings::get( 'tenant_id' ) ), $path );
	}

	/**
	 * Step 1: send the browser to Microsoft.
	 *
	 * Runs on wp-login.php?action=msentra_sso.
	 */
	public function start() {
		if ( ! Settings::is_configured() ) {
			$this->fail( 'not_configured' );
		}

		// phpcs:ignore WordPress.Security.NonceVerification.Recommended -- Read-only redirect target, validated below.
		$redirect_to = isset( $_REQUEST['redirect_to'] ) && is_string( $_REQUEST['redirect_to'] ) ? wp_sanitize_redirect( wp_unslash( $_REQUEST['redirect_to'] ) ) : '';
		$redirect_to = wp_validate_redirect( $redirect_to, '' );

		$state    = $this->random_token();
		$verifier = $this->random_token( 48 );
		$nonce    = $this->random_token();

		set_transient(
			$this->state_key( $state ),
			array(
				'verifier'    => $verifier,
				'nonce'       => $nonce,
				'redirect_to' => $redirect_to,
			),
			self::STATE_TTL
		);
		$this->set_state_cookie( $state, time() + self::STATE_TTL );

		$params = array(
			'client_id'             => Settings::get( 'client_id' ),
			'response_type'         => 'code',
			'redirect_uri'          => Settings::redirect_uri(),
			'response_mode'         => 'query',
			'scope'                 => $this->scopes(),
			'state'                 => $state,
			'nonce'                 => $nonce,
			'code_challenge'        => $this->base64url( hash( 'sha256', $verifier, true ) ),
			'code_challenge_method' => 'S256',
		);

		/**
		 * Filters the parameters of the Microsoft authorization request.
		 *
		 * Useful to add "prompt" (e.g. "select_account") or "domain_hint".
		 *
		 * @param array $params Query parameters.
		 */
		$params = apply_filters( 'msentra_sso_authorize_params', $params );

		nocache_headers();
		// Microsoft's host is added to the allowed hosts in allowed_redirect_hosts().
		wp_safe_redirect( self::endpoint( 'oauth2/v2.0/authorize' ) . '?' . http_build_query( $params, '', '&', PHP_QUERY_RFC3986 ) );
		exit;
	}

	/**
	 * Step 2: handle Microsoft redirecting back to wp-login.php.
	 */
	public function maybe_handle_callback() {
		// phpcs:disable WordPress.Security.NonceVerification.Recommended -- The OAuth "state" parameter, bound to a browser cookie, is the CSRF protection here.
		if ( ! isset( $_GET['state'] ) || ( ! isset( $_GET['code'] ) && ! isset( $_GET['error'] ) ) ) {
			return;
		}
		if ( ! isset( $_SERVER['REQUEST_METHOD'] ) || 'GET' !== $_SERVER['REQUEST_METHOD'] ) {
			return;
		}

		$state = sanitize_text_field( wp_unslash( $_GET['state'] ) );
		$code  = isset( $_GET['code'] ) ? sanitize_text_field( wp_unslash( $_GET['code'] ) ) : '';
		$error = isset( $_GET['error'] ) ? sanitize_text_field( wp_unslash( $_GET['error'] ) ) : '';
		$desc  = isset( $_GET['error_description'] ) ? sanitize_text_field( wp_unslash( $_GET['error_description'] ) ) : '';
		// phpcs:enable

		$pending = get_transient( $this->state_key( $state ) );
		if ( false === $pending ) {
			// Not ours, or expired. Let wp-login.php carry on (or show an error if it is clearly ours).
			if ( isset( $_COOKIE[ self::STATE_COOKIE ] ) ) {
				$this->clear_state_cookie();
				$this->fail( 'invalid_state' );
			}
			return;
		}

		// One-time use.
		delete_transient( $this->state_key( $state ) );

		$cookie = isset( $_COOKIE[ self::STATE_COOKIE ] ) ? sanitize_text_field( wp_unslash( $_COOKIE[ self::STATE_COOKIE ] ) ) : '';
		$this->clear_state_cookie();

		if ( '' === $cookie || ! hash_equals( $state, $cookie ) ) {
			$this->fail( 'invalid_state' );
		}

		if ( '' !== $error ) {
			$this->log( 'Microsoft returned an error: ' . $error . ' ' . $desc );
			$this->fail( 'access_denied' === $error ? 'access_denied' : 'provider_error' );
		}

		$user = $this->authenticate( $code, $pending );
		if ( is_wp_error( $user ) ) {
			$this->log( $user->get_error_code() . ': ' . $user->get_error_message() );
			$this->fail( $user->get_error_code() );
		}

		$this->sign_in( $user, $pending['redirect_to'] );
	}

	/**
	 * Exchanges the code for tokens, validates them and resolves the WordPress user.
	 *
	 * @param string $code    Authorization code.
	 * @param array  $pending Data saved when the flow started.
	 * @return WP_User|WP_Error
	 */
	private function authenticate( $code, array $pending ) {
		$tokens = $this->exchange_code( $code, $pending['verifier'] );
		if ( is_wp_error( $tokens ) ) {
			return $tokens;
		}

		$claims = $this->validate_id_token( $tokens['id_token'], $pending['nonce'] );
		if ( is_wp_error( $claims ) ) {
			return $claims;
		}

		$profile = $this->build_profile( $claims, isset( $tokens['access_token'] ) ? $tokens['access_token'] : '' );
		if ( is_wp_error( $profile ) ) {
			return $profile;
		}

		/**
		 * Filters whether a Microsoft-authenticated user may continue signing in.
		 *
		 * Return a WP_Error to block the sign-in (e.g. based on a custom claim).
		 *
		 * @param null|WP_Error $check   Null to allow.
		 * @param array $profile Normalized profile (see build_profile()).
		 * @param array $claims  Raw ID token claims.
		 */
		$check = apply_filters( 'msentra_sso_pre_user', null, $profile, $claims );
		if ( is_wp_error( $check ) ) {
			return $check;
		}

		return $this->resolve_user( $profile );
	}

	/**
	 * Calls the token endpoint.
	 *
	 * @param string $code     Authorization code.
	 * @param string $verifier PKCE code verifier.
	 * @return array|WP_Error Token response.
	 */
	private function exchange_code( $code, $verifier ) {
		if ( '' === $code ) {
			return new WP_Error( 'token_error', 'Missing authorization code.' );
		}

		$response = wp_remote_post(
			self::endpoint( 'oauth2/v2.0/token' ),
			array(
				'timeout' => 20,
				'headers' => array( 'Accept' => 'application/json' ),
				'body'    => array(
					'client_id'     => Settings::get( 'client_id' ),
					'client_secret' => Settings::get( 'client_secret' ),
					'grant_type'    => 'authorization_code',
					'code'          => $code,
					'redirect_uri'  => Settings::redirect_uri(),
					'code_verifier' => $verifier,
					'scope'         => $this->scopes(),
				),
			)
		);

		if ( is_wp_error( $response ) ) {
			return new WP_Error( 'token_error', 'Token request failed: ' . $response->get_error_message() );
		}

		$body = json_decode( wp_remote_retrieve_body( $response ), true );
		if ( ! is_array( $body ) || empty( $body['id_token'] ) ) {
			$detail = is_array( $body ) && isset( $body['error_description'] ) ? $body['error_description'] : wp_remote_retrieve_response_code( $response );
			return new WP_Error( 'token_error', 'Token endpoint returned no ID token: ' . $detail );
		}

		return $body;
	}

	/**
	 * Validates the ID token claims.
	 *
	 * The token is received directly from Microsoft's token endpoint over TLS
	 * using the client secret, so per OpenID Connect Core 3.1.3.7 the TLS
	 * connection authenticates the issuer and the signature need not be checked.
	 * All other claims are verified.
	 *
	 * @param string $id_token Encoded ID token.
	 * @param string $nonce    Expected nonce.
	 * @return array|WP_Error Claims.
	 */
	private function validate_id_token( $id_token, $nonce ) {
		$parts = explode( '.', (string) $id_token );
		if ( 3 !== count( $parts ) ) {
			return new WP_Error( 'invalid_token', 'Malformed ID token.' );
		}

		$claims = json_decode( $this->base64url_decode( $parts[1] ), true );
		if ( ! is_array( $claims ) ) {
			return new WP_Error( 'invalid_token', 'Unreadable ID token.' );
		}

		$now    = time();
		$leeway = 300;

		$audience = isset( $claims['aud'] ) ? (array) $claims['aud'] : array();
		if ( ! in_array( Settings::get( 'client_id' ), $audience, true ) ) {
			return new WP_Error( 'invalid_token', 'ID token audience mismatch.' );
		}
		if ( empty( $claims['nonce'] ) || ! hash_equals( $nonce, (string) $claims['nonce'] ) ) {
			return new WP_Error( 'invalid_token', 'ID token nonce mismatch.' );
		}
		if ( empty( $claims['exp'] ) || $claims['exp'] < $now - $leeway ) {
			return new WP_Error( 'invalid_token', 'ID token expired.' );
		}
		if ( ! empty( $claims['nbf'] ) && $claims['nbf'] > $now + $leeway ) {
			return new WP_Error( 'invalid_token', 'ID token not yet valid.' );
		}
		if ( empty( $claims['tid'] ) || empty( $claims['oid'] ) ) {
			return new WP_Error( 'invalid_token', 'ID token is missing the tid or oid claim.' );
		}

		$tid = strtolower( (string) $claims['tid'] );
		if ( empty( $claims['iss'] ) || sprintf( 'https://%s/%s/v2.0', self::authority_host(), $tid ) !== $claims['iss'] ) {
			return new WP_Error( 'invalid_token', 'ID token issuer mismatch.' );
		}

		$tenant_check = $this->check_tenant( $tid );
		if ( is_wp_error( $tenant_check ) ) {
			return $tenant_check;
		}

		return $claims;
	}

	/**
	 * Makes sure the user belongs to an allowed directory.
	 *
	 * @param string $tid Tenant ID from the token.
	 * @return true|WP_Error
	 */
	private function check_tenant( $tid ) {
		$configured = strtolower( Settings::get( 'tenant_id' ) );

		if ( Settings::is_multi_tenant() ) {
			$allowed = Settings::get_list( 'allowed_tenants' );
			if ( 'consumers' === $configured ) {
				$allowed[] = self::CONSUMER_TENANT;
			}
			/**
			 * Filters the tenant IDs allowed to sign in when a multi-tenant
			 * value ("common", "organizations" or "consumers") is configured.
			 *
			 * @param string[] $allowed Allowed tenant IDs.
			 */
			$allowed = (array) apply_filters( 'msentra_sso_allowed_tenants', $allowed );
			return in_array( $tid, $allowed, true ) ? true : new WP_Error( 'tenant_not_allowed', 'Tenant ' . $tid . ' is not allowed.' );
		}

		if ( $this->is_guid( $configured ) ) {
			return $tid === $configured ? true : new WP_Error( 'tenant_not_allowed', 'Tenant ' . $tid . ' does not match the configured tenant.' );
		}

		// A domain name was configured (e.g. contoso.onmicrosoft.com): resolve it to its tenant ID.
		$resolved = $this->resolve_tenant_domain( $configured );
		if ( is_wp_error( $resolved ) ) {
			return $resolved;
		}
		return $tid === $resolved ? true : new WP_Error( 'tenant_not_allowed', 'Tenant ' . $tid . ' does not match ' . $configured . '.' );
	}

	/**
	 * Looks up the tenant ID of a verified domain via the OpenID discovery document.
	 *
	 * @param string $domain Tenant domain.
	 * @return string|WP_Error Tenant ID.
	 */
	private function resolve_tenant_domain( $domain ) {
		$cache_key = 'msentra_sso_tid_' . md5( self::authority_host() . $domain );
		$cached    = get_transient( $cache_key );
		if ( is_string( $cached ) && '' !== $cached ) {
			return $cached;
		}

		$response = wp_remote_get( self::endpoint( 'v2.0/.well-known/openid-configuration' ), array( 'timeout' => 15 ) );
		$body     = is_wp_error( $response ) ? null : json_decode( wp_remote_retrieve_body( $response ), true );

		if ( is_array( $body ) && ! empty( $body['issuer'] ) && preg_match( '#/([0-9a-f\-]{36})/v2\.0$#i', $body['issuer'], $m ) ) {
			$tid = strtolower( $m[1] );
			set_transient( $cache_key, $tid, DAY_IN_SECONDS );
			return $tid;
		}

		return new WP_Error( 'tenant_not_allowed', 'Could not resolve the tenant ID for ' . $domain . '.' );
	}

	/**
	 * Combines ID token claims and (optionally) Microsoft Graph data into a profile.
	 *
	 * @param array  $claims       ID token claims.
	 * @param string $access_token Graph access token.
	 * @return array|WP_Error {
	 *     @type string   $identity     "<tid>:<oid>".
	 *     @type string   $email        Lower-cased email address.
	 *     @type string   $display_name Display name.
	 *     @type string   $first_name   Given name.
	 *     @type string   $last_name    Surname.
	 *     @type string[] $roles        App roles from the token.
	 *     @type string[] $groups       Group object IDs from the token.
	 * }
	 */
	private function build_profile( array $claims, $access_token ) {
		$graph = array();
		if ( '' !== $access_token ) {
			$response = wp_remote_get(
				self::graph_url() . '/v1.0/me?$select=mail,userPrincipalName,displayName,givenName,surname',
				array(
					'timeout' => 15,
					'headers' => array( 'Authorization' => 'Bearer ' . $access_token ),
				)
			);
			if ( ! is_wp_error( $response ) && 200 === (int) wp_remote_retrieve_response_code( $response ) ) {
				$decoded = json_decode( wp_remote_retrieve_body( $response ), true );
				$graph   = is_array( $decoded ) ? $decoded : array();
			}
		}

		$candidates = array(
			isset( $graph['mail'] ) ? $graph['mail'] : '',
			isset( $claims['email'] ) ? $claims['email'] : '',
			isset( $graph['userPrincipalName'] ) ? $graph['userPrincipalName'] : '',
			isset( $claims['preferred_username'] ) ? $claims['preferred_username'] : '',
		);

		$email = '';
		foreach ( $candidates as $candidate ) {
			$candidate = strtolower( sanitize_email( (string) $candidate ) );
			if ( is_email( $candidate ) ) {
				$email = $candidate;
				break;
			}
		}
		if ( '' === $email ) {
			return new WP_Error( 'no_email', 'No email address in the Microsoft profile.' );
		}

		$profile = array(
			'identity'     => strtolower( $claims['tid'] . ':' . $claims['oid'] ),
			'email'        => $email,
			'display_name' => sanitize_text_field( isset( $graph['displayName'] ) ? $graph['displayName'] : ( isset( $claims['name'] ) ? $claims['name'] : '' ) ),
			'first_name'   => sanitize_text_field( isset( $graph['givenName'] ) ? $graph['givenName'] : ( isset( $claims['given_name'] ) ? $claims['given_name'] : '' ) ),
			'last_name'    => sanitize_text_field( isset( $graph['surname'] ) ? $graph['surname'] : ( isset( $claims['family_name'] ) ? $claims['family_name'] : '' ) ),
			'roles'        => isset( $claims['roles'] ) ? array_map( 'strval', (array) $claims['roles'] ) : array(),
			'groups'       => isset( $claims['groups'] ) ? array_map( 'strval', (array) $claims['groups'] ) : array(),
		);

		/**
		 * Filters the profile built from the Microsoft sign-in.
		 *
		 * @param array $profile Profile.
		 * @param array $claims  ID token claims.
		 * @param array $graph   Microsoft Graph /me response (may be empty).
		 */
		return apply_filters( 'msentra_sso_profile', $profile, $claims, $graph );
	}

	/**
	 * Finds, links or creates the WordPress user for a profile.
	 *
	 * @param array $profile Profile from build_profile().
	 * @return WP_User|WP_Error
	 */
	private function resolve_user( array $profile ) {
		$domains = Settings::get_list( 'allowed_domains' );
		if ( $domains ) {
			$domain = substr( strrchr( $profile['email'], '@' ), 1 );
			if ( ! in_array( $domain, $domains, true ) ) {
				return new WP_Error( 'domain_not_allowed', 'Email domain ' . $domain . ' is not allowed.' );
			}
		}

		// 1. A user already linked to this Microsoft identity.
		$users = get_users(
			array(
				'meta_key'    => self::META_IDENTITY, // phpcs:ignore WordPress.DB.SlowDBQuery.slow_db_query_meta_key
				'meta_value'  => $profile['identity'], // phpcs:ignore WordPress.DB.SlowDBQuery.slow_db_query_meta_value
				'number'      => 1,
				'count_total' => false,
				'blog_id'     => 0,
			)
		);
		$user  = $users ? $users[0] : null;

		// 2. An existing user with the same email address.
		if ( ! $user && Settings::get( 'match_by_email' ) ) {
			$by_email = get_user_by( 'email', $profile['email'] );
			if ( $by_email ) {
				$linked = get_user_meta( $by_email->ID, self::META_IDENTITY, true );
				if ( $linked && $linked !== $profile['identity'] ) {
					return new WP_Error( 'identity_conflict', 'User ' . $by_email->ID . ' is linked to a different Microsoft account.' );
				}
				$user = $by_email;
			}
		}

		$created = false;

		// 3. Create a new user.
		if ( ! $user ) {
			if ( ! Settings::get( 'create_users' ) ) {
				return new WP_Error( 'user_not_found', 'No WordPress account for ' . $profile['email'] . '.' );
			}
			if ( get_user_by( 'email', $profile['email'] ) ) {
				// Exists but email matching is off: do not create a duplicate.
				return new WP_Error( 'user_not_found', 'Account exists for ' . $profile['email'] . ' but email matching is disabled.' );
			}
			$user = $this->create_user( $profile );
			if ( is_wp_error( $user ) ) {
				return $user;
			}
			$created = true;
		}

		if ( is_multisite() && ! is_user_member_of_blog( $user->ID ) ) {
			if ( ! Settings::get( 'create_users' ) ) {
				return new WP_Error( 'user_not_found', 'User ' . $user->ID . ' is not a member of this site.' );
			}
			add_user_to_blog( get_current_blog_id(), $user->ID, $this->role_for( $profile ) );
		}

		update_user_meta( $user->ID, self::META_IDENTITY, $profile['identity'] );

		if ( ! $created && Settings::get( 'sync_roles' ) ) {
			$this->sync_role( $user, $profile );
		}

		/**
		 * Fires after a Microsoft account has been resolved to a WordPress user, before sign-in.
		 *
		 * @param WP_User $user    User.
		 * @param array   $profile Profile.
		 * @param bool    $created Whether the user was just created.
		 */
		do_action( 'msentra_sso_user_resolved', $user, $profile, $created );

		return get_user_by( 'id', $user->ID );
	}

	/**
	 * Creates a WordPress user from a profile.
	 *
	 * @param array $profile Profile.
	 * @return WP_User|WP_Error
	 */
	private function create_user( array $profile ) {
		$base   = sanitize_user( strstr( $profile['email'], '@', true ), true );
		$base   = '' === $base ? 'user' : $base;
		$login  = $base;
		$suffix = 2;
		while ( username_exists( $login ) ) {
			$login = $base . $suffix;
			++$suffix;
		}

		$userdata = array(
			'user_login'   => $login,
			'user_email'   => $profile['email'],
			'user_pass'    => wp_generate_password( 32, true, true ),
			'display_name' => '' !== $profile['display_name'] ? $profile['display_name'] : $login,
			'first_name'   => $profile['first_name'],
			'last_name'    => $profile['last_name'],
			'role'         => $this->role_for( $profile ),
		);

		/**
		 * Filters the data used to create a user on first Microsoft sign-in.
		 *
		 * @param array $userdata Arguments for wp_insert_user().
		 * @param array $profile  Profile.
		 */
		$userdata = apply_filters( 'msentra_sso_new_user_data', $userdata, $profile );

		$user_id = wp_insert_user( $userdata );
		if ( is_wp_error( $user_id ) ) {
			return new WP_Error( 'create_failed', $user_id->get_error_message() );
		}

		return get_user_by( 'id', $user_id );
	}

	/**
	 * Determines the WordPress role from the role mapping, falling back to the default role.
	 *
	 * @param array $profile Profile.
	 * @param bool  $mapped_only Return '' instead of the default role when nothing matches.
	 * @return string
	 */
	private function role_for( array $profile, $mapped_only = false ) {
		$role   = $mapped_only ? '' : Settings::get( 'default_role' );
		$values = array_merge( $profile['roles'], $profile['groups'] );

		foreach ( Settings::get_role_mapping() as $claim => $mapped_role ) {
			foreach ( $values as $value ) {
				if ( 0 === strcasecmp( $claim, $value ) ) {
					$role = $mapped_role;
					break 2;
				}
			}
		}

		/**
		 * Filters the WordPress role assigned to a Microsoft user.
		 *
		 * @param string $role    Role slug ('' to leave roles unchanged).
		 * @param array  $profile Profile.
		 */
		return (string) apply_filters( 'msentra_sso_user_role', $role, $profile );
	}

	/**
	 * Applies the role mapping to an existing user on every sign-in.
	 *
	 * Only users matching a mapping rule are changed, so manually managed
	 * accounts keep their roles.
	 *
	 * @param WP_User $user    User.
	 * @param array   $profile Profile.
	 */
	private function sync_role( WP_User $user, array $profile ) {
		$role = $this->role_for( $profile, true );
		if ( '' !== $role && null !== get_role( $role ) && array( $role ) !== array_values( $user->roles ) ) {
			$user->set_role( $role );
		}
	}

	/**
	 * Logs the user in and redirects.
	 *
	 * @param WP_User $user        User.
	 * @param string  $redirect_to Requested redirect.
	 */
	private function sign_in( WP_User $user, $redirect_to ) {
		$this->signing_in = true;
		wp_set_current_user( $user->ID );
		wp_set_auth_cookie( $user->ID, false );
		$this->signing_in = false;

		/** This action is documented in wp-includes/user.php */
		do_action( 'wp_login', $user->user_login, $user ); // phpcs:ignore WordPress.NamingConventions.PrefixAllGlobals.NonPrefixedHooknameFound -- Core hook, fired so logging/security plugins see the sign-in.

		$default = Settings::get( 'login_redirect' );
		$default = '' !== $default ? $default : admin_url();
		$target  = '' !== $redirect_to ? $redirect_to : $default;

		/** This filter is documented in wp-login.php */
		$target = apply_filters( 'login_redirect', $target, $redirect_to, $user ); // phpcs:ignore WordPress.NamingConventions.PrefixAllGlobals.NonPrefixedHooknameFound -- Core hook.

		// Users without dashboard access go to their profile, like core does.
		if ( ( empty( $target ) || admin_url() === $target ) && ! $user->has_cap( 'edit_posts' ) ) {
			$target = is_multisite() && ! get_active_blog_for_user( $user->ID ) && ! is_super_admin( $user->ID ) ? user_admin_url() : admin_url( 'profile.php' );
		}

		wp_safe_redirect( $target );
		exit;
	}

	/**
	 * Marks sessions started through Microsoft so single logout can be applied.
	 *
	 * @param array $info Session information.
	 * @return array
	 */
	public function flag_session( $info ) {
		if ( $this->signing_in ) {
			$info['msentra_sso'] = true;
		}
		return $info;
	}

	/**
	 * Before WordPress logs a user out, remember whether they signed in with Microsoft.
	 */
	public function detect_sso_logout() {
		if ( ! Settings::get( 'single_logout' ) || ! is_user_logged_in() ) {
			return;
		}
		$session                     = \WP_Session_Tokens::get_instance( get_current_user_id() )->get( wp_get_session_token() );
		$this->logout_from_microsoft = is_array( $session ) && ! empty( $session['msentra_sso'] );
	}

	/**
	 * Sends Microsoft users through Microsoft's logout endpoint after WordPress logout.
	 *
	 * @param string $redirect_to Where WordPress would redirect after logout.
	 * @return string
	 */
	public function logout_redirect( $redirect_to ) {
		if ( ! $this->logout_from_microsoft ) {
			return $redirect_to;
		}
		$back = '' !== $redirect_to ? $redirect_to : add_query_arg( 'loggedout', 'true', wp_login_url() );
		return add_query_arg( 'post_logout_redirect_uri', rawurlencode( $back ), self::endpoint( 'oauth2/v2.0/logout' ) );
	}

	/**
	 * Allows redirects to the Microsoft login host.
	 *
	 * @param string[] $hosts Allowed hosts.
	 * @return string[]
	 */
	public function allowed_redirect_hosts( $hosts ) {
		$hosts[] = self::authority_host();
		return $hosts;
	}

	/**
	 * Redirects to the login page with an error code and stops.
	 *
	 * @param string $code Error code (see Login_UI::error_message()).
	 */
	private function fail( $code ) {
		nocache_headers();
		wp_safe_redirect( add_query_arg( self::ERROR_ARG, rawurlencode( $code ), wp_login_url() ) );
		exit;
	}

	/**
	 * OAuth scopes requested from Microsoft.
	 *
	 * @return string
	 */
	private function scopes() {
		/**
		 * Filters the OAuth scopes. "openid" is required.
		 *
		 * @param string[] $scopes Scopes.
		 */
		return implode( ' ', (array) apply_filters( 'msentra_sso_scopes', array( 'openid', 'profile', 'email', 'User.Read' ) ) );
	}

	/**
	 * Transient key for a pending sign-in.
	 *
	 * @param string $state State value.
	 * @return string
	 */
	private function state_key( $state ) {
		return 'msentra_sso_' . hash( 'sha256', $state );
	}

	/**
	 * Sets the browser-binding cookie.
	 *
	 * @param string $value  Cookie value.
	 * @param int    $expire Expiry timestamp.
	 */
	private function set_state_cookie( $value, $expire ) {
		$path = defined( 'COOKIEPATH' ) && COOKIEPATH ? COOKIEPATH : '/';
		// SameSite=Lax lets the cookie travel with Microsoft's top-level GET redirect back to the site.
		setcookie(
			self::STATE_COOKIE,
			$value,
			array(
				'expires'  => $expire,
				'path'     => $path,
				'domain'   => defined( 'COOKIE_DOMAIN' ) && COOKIE_DOMAIN ? COOKIE_DOMAIN : '',
				'secure'   => is_ssl(),
				'httponly' => true,
				'samesite' => 'Lax',
			)
		);
		if ( defined( 'SITECOOKIEPATH' ) && SITECOOKIEPATH && SITECOOKIEPATH !== $path ) {
			setcookie(
				self::STATE_COOKIE,
				$value,
				array(
					'expires'  => $expire,
					'path'     => SITECOOKIEPATH,
					'domain'   => defined( 'COOKIE_DOMAIN' ) && COOKIE_DOMAIN ? COOKIE_DOMAIN : '',
					'secure'   => is_ssl(),
					'httponly' => true,
					'samesite' => 'Lax',
				)
			);
		}
	}

	/**
	 * Removes the browser-binding cookie.
	 */
	private function clear_state_cookie() {
		$this->set_state_cookie( '', time() - YEAR_IN_SECONDS );
		unset( $_COOKIE[ self::STATE_COOKIE ] );
	}

	/**
	 * Cryptographically secure random URL-safe token.
	 *
	 * @param int $bytes Number of random bytes.
	 * @return string
	 */
	private function random_token( $bytes = 32 ) {
		return $this->base64url( random_bytes( $bytes ) );
	}

	/**
	 * Base64url-encodes binary data without padding.
	 *
	 * @param string $data Data.
	 * @return string
	 */
	private function base64url( $data ) {
		return rtrim( strtr( base64_encode( $data ), '+/', '-_' ), '=' ); // phpcs:ignore WordPress.PHP.DiscouragedPHPFunctions.obfuscation_base64_encode
	}

	/**
	 * Decodes base64url data.
	 *
	 * @param string $data Data.
	 * @return string
	 */
	private function base64url_decode( $data ) {
		$data = strtr( $data, '-_', '+/' );
		$pad  = strlen( $data ) % 4;
		if ( $pad ) {
			$data .= str_repeat( '=', 4 - $pad );
		}
		return (string) base64_decode( $data, true ); // phpcs:ignore WordPress.PHP.DiscouragedPHPFunctions.obfuscation_base64_decode
	}

	/**
	 * Whether a string is a GUID.
	 *
	 * @param string $value Value.
	 * @return bool
	 */
	private function is_guid( $value ) {
		return (bool) preg_match( '/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/', $value );
	}

	/**
	 * Writes a diagnostic message to the PHP error log when WP_DEBUG is on.
	 *
	 * @param string $message Message.
	 */
	private function log( $message ) {
		if ( defined( 'WP_DEBUG' ) && WP_DEBUG ) {
			error_log( '[SSO Login for Microsoft Entra ID] ' . $message ); // phpcs:ignore WordPress.PHP.DevelopmentFunctions.error_log_error_log
		}
	}
}
