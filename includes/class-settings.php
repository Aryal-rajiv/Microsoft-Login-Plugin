<?php
/**
 * Settings storage and access.
 *
 * @package MSEntraSSO
 */

namespace MSEntraSSO;

defined( 'ABSPATH' ) || exit;

/**
 * Reads, sanitizes and stores the plugin settings.
 *
 * All settings live in a single option. The connection credentials can also be
 * defined as constants in wp-config.php, which then take precedence over the
 * values stored in the database.
 */
class Settings {

	/**
	 * Option name used to store the settings.
	 */
	const OPTION = 'msentra_sso_settings';

	/**
	 * Settings that may be overridden by a wp-config.php constant.
	 *
	 * @var array<string, string>
	 */
	const CONSTANTS = array(
		'client_id'     => 'MSENTRA_SSO_CLIENT_ID',
		'client_secret' => 'MSENTRA_SSO_CLIENT_SECRET',
		'tenant_id'     => 'MSENTRA_SSO_TENANT_ID',
	);

	/**
	 * Tenant values that allow accounts from more than one directory.
	 *
	 * @var string[]
	 */
	const MULTI_TENANT_VALUES = array( 'common', 'organizations', 'consumers' );

	/**
	 * Per-request cache of the merged settings.
	 *
	 * @var array|null
	 */
	private static $cache = null;

	/**
	 * Default values for every setting.
	 *
	 * @return array
	 */
	public static function defaults() {
		return array(
			'client_id'       => '',
			'client_secret'   => '',
			'tenant_id'       => '',
			'allowed_tenants' => '',
			'match_by_email'  => 1,
			'create_users'    => 0,
			'default_role'    => 'subscriber',
			'allowed_domains' => '',
			'role_mapping'    => '',
			'sync_roles'      => 0,
			'login_mode'      => 'button',
			'button_text'     => '',
			'login_redirect'  => '',
			'single_logout'   => 0,
		);
	}

	/**
	 * Returns all settings, with wp-config.php constants applied.
	 *
	 * @return array
	 */
	public static function all() {
		if ( null === self::$cache ) {
			$stored = get_option( self::OPTION, array() );
			$values = wp_parse_args( is_array( $stored ) ? $stored : array(), self::defaults() );

			foreach ( self::CONSTANTS as $key => $constant ) {
				if ( defined( $constant ) ) {
					$values[ $key ] = (string) constant( $constant );
				}
			}

			self::$cache = $values;
		}

		return self::$cache;
	}

	/**
	 * Returns a single setting.
	 *
	 * @param string $key Setting name.
	 * @return mixed
	 */
	public static function get( $key ) {
		$all = self::all();
		return isset( $all[ $key ] ) ? $all[ $key ] : null;
	}

	/**
	 * Clears the per-request cache. Called whenever the option changes.
	 */
	public static function flush() {
		self::$cache = null;
	}

	/**
	 * Whether a setting is locked by a wp-config.php constant.
	 *
	 * @param string $key Setting name.
	 * @return bool
	 */
	public static function is_constant( $key ) {
		return isset( self::CONSTANTS[ $key ] ) && defined( self::CONSTANTS[ $key ] );
	}

	/**
	 * Whether the minimum settings needed to sign in are present.
	 *
	 * @return bool
	 */
	public static function is_configured() {
		return '' !== self::get( 'client_id' ) && '' !== self::get( 'client_secret' ) && '' !== self::get( 'tenant_id' );
	}

	/**
	 * Whether the configured tenant accepts accounts from several directories.
	 *
	 * @return bool
	 */
	public static function is_multi_tenant() {
		return in_array( strtolower( (string) self::get( 'tenant_id' ) ), self::MULTI_TENANT_VALUES, true );
	}

	/**
	 * The redirect (reply) URI to register in Microsoft Entra ID.
	 *
	 * Microsoft sends users back to the standard WordPress login URL, which
	 * keeps the URI free of query strings as recommended by Microsoft.
	 *
	 * @return string
	 */
	public static function redirect_uri() {
		/**
		 * Filters the OAuth redirect URI sent to Microsoft.
		 *
		 * The value must exactly match a Web redirect URI registered on the
		 * app registration in Microsoft Entra ID.
		 *
		 * @param string $uri Redirect URI. Defaults to the WordPress login URL.
		 */
		return (string) apply_filters( 'msentra_sso_redirect_uri', wp_login_url() );
	}

	/**
	 * Splits a textarea/comma separated setting into a clean list.
	 *
	 * @param string $key Setting name.
	 * @return string[]
	 */
	public static function get_list( $key ) {
		$items = preg_split( '/[\s,;]+/', strtolower( (string) self::get( $key ) ) );
		return array_values( array_filter( array_map( 'trim', $items ) ) );
	}

	/**
	 * Parses the role mapping setting.
	 *
	 * Each line has the form "<Entra app role or group object ID> = <WordPress role>".
	 *
	 * @return array<string, string> Map of Entra value => WordPress role slug, in priority order.
	 */
	public static function get_role_mapping() {
		$mapping = array();
		$lines   = preg_split( '/\r\n|\r|\n/', (string) self::get( 'role_mapping' ) );

		foreach ( $lines as $line ) {
			$parts = explode( '=', $line, 2 );
			if ( 2 !== count( $parts ) ) {
				continue;
			}
			$claim = trim( $parts[0] );
			$role  = sanitize_key( trim( $parts[1] ) );
			if ( '' !== $claim && '' !== $role && ! isset( $mapping[ $claim ] ) ) {
				$mapping[ $claim ] = $role;
			}
		}

		return $mapping;
	}

	/**
	 * Sanitize callback for register_setting().
	 *
	 * @param mixed $input Raw submitted values.
	 * @return array
	 */
	public static function sanitize( $input ) {
		$input    = is_array( $input ) ? $input : array();
		$previous = get_option( self::OPTION, array() );
		$previous = wp_parse_args( is_array( $previous ) ? $previous : array(), self::defaults() );
		$output   = self::defaults();

		$output['client_id'] = isset( $input['client_id'] ) ? sanitize_text_field( $input['client_id'] ) : $previous['client_id'];
		$output['tenant_id'] = isset( $input['tenant_id'] ) ? self::sanitize_tenant( $input['tenant_id'] ) : $previous['tenant_id'];

		// An empty secret field means "keep the saved secret" so it never has to be echoed back into the page.
		$secret = isset( $input['client_secret'] ) ? trim( (string) $input['client_secret'] ) : '';
		if ( ! empty( $input['clear_client_secret'] ) ) {
			$output['client_secret'] = '';
		} elseif ( '' !== $secret ) {
			$output['client_secret'] = $secret;
		} else {
			$output['client_secret'] = $previous['client_secret'];
		}

		$output['allowed_tenants'] = isset( $input['allowed_tenants'] ) ? self::sanitize_list( $input['allowed_tenants'], '/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/' ) : '';
		$output['allowed_domains'] = isset( $input['allowed_domains'] ) ? self::sanitize_list( $input['allowed_domains'] ) : '';

		foreach ( array( 'match_by_email', 'create_users', 'sync_roles', 'single_logout' ) as $checkbox ) {
			$output[ $checkbox ] = empty( $input[ $checkbox ] ) ? 0 : 1;
		}

		$roles                  = self::assignable_roles();
		$role                   = isset( $input['default_role'] ) ? sanitize_key( $input['default_role'] ) : '';
		$output['default_role'] = isset( $roles[ $role ] ) ? $role : 'subscriber';

		$output['role_mapping'] = isset( $input['role_mapping'] ) ? self::sanitize_role_mapping( $input['role_mapping'] ) : '';

		$mode                 = isset( $input['login_mode'] ) ? sanitize_key( $input['login_mode'] ) : 'button';
		$output['login_mode'] = in_array( $mode, array( 'button', 'redirect' ), true ) ? $mode : 'button';

		$output['button_text']    = isset( $input['button_text'] ) ? sanitize_text_field( $input['button_text'] ) : '';
		$output['login_redirect'] = isset( $input['login_redirect'] ) ? esc_url_raw( trim( $input['login_redirect'] ) ) : '';

		self::flush();

		return $output;
	}

	/**
	 * Roles that may be chosen as the default role for new users.
	 *
	 * Administrator is deliberately excluded: granting it should be an explicit
	 * decision made through the role mapping.
	 *
	 * @return array<string, string> Role slug => translated role name.
	 */
	public static function assignable_roles() {
		$roles = array();
		foreach ( wp_roles()->get_names() as $slug => $name ) {
			if ( 'administrator' !== $slug ) {
				$roles[ $slug ] = translate_user_role( $name );
			}
		}
		return $roles;
	}

	/**
	 * Sanitizes a tenant identifier (GUID, domain or a multi-tenant keyword).
	 *
	 * @param string $value Raw value.
	 * @return string
	 */
	private static function sanitize_tenant( $value ) {
		$value = strtolower( trim( (string) $value ) );
		return preg_match( '/^[a-z0-9][a-z0-9.\-]*$/', $value ) ? $value : '';
	}

	/**
	 * Normalizes a comma/whitespace separated list to one item per line.
	 *
	 * @param string $value   Raw value.
	 * @param string $pattern Optional regular expression every item must match.
	 * @return string
	 */
	private static function sanitize_list( $value, $pattern = '' ) {
		$items = preg_split( '/[\s,;]+/', strtolower( sanitize_textarea_field( (string) $value ) ) );
		$items = array_unique( array_filter( array_map( 'trim', $items ) ) );
		if ( '' !== $pattern ) {
			$items = preg_grep( $pattern, $items );
		}
		return implode( "\n", $items );
	}

	/**
	 * Keeps only well-formed "claim = role" lines that point to existing roles.
	 *
	 * @param string $value Raw value.
	 * @return string
	 */
	private static function sanitize_role_mapping( $value ) {
		$roles = wp_roles()->get_names();
		$lines = preg_split( '/\r\n|\r|\n/', sanitize_textarea_field( (string) $value ) );
		$clean = array();

		foreach ( $lines as $line ) {
			$parts = explode( '=', $line, 2 );
			if ( 2 !== count( $parts ) ) {
				continue;
			}
			$claim = trim( $parts[0] );
			$role  = sanitize_key( trim( $parts[1] ) );
			if ( '' !== $claim && isset( $roles[ $role ] ) ) {
				$clean[] = $claim . ' = ' . $role;
			}
		}

		return implode( "\n", $clean );
	}
}
