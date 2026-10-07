<?php
/**
 * Plugin bootstrap.
 *
 * @package MSEntraSSO
 */

namespace MSEntraSSO;

defined( 'ABSPATH' ) || exit;

/**
 * Wires the plugin components together.
 */
final class Plugin {

	/**
	 * Option storing the installed version, used for upgrade routines.
	 */
	const VERSION_OPTION = 'msentra_sso_version';

	/**
	 * Singleton instance.
	 *
	 * @var Plugin|null
	 */
	private static $instance = null;

	/**
	 * Returns (and on first call boots) the plugin.
	 *
	 * @return Plugin
	 */
	public static function instance() {
		if ( null === self::$instance ) {
			self::$instance = new self();
			self::$instance->boot();
		}
		return self::$instance;
	}

	/**
	 * Registers all hooks.
	 */
	private function boot() {
		if ( get_option( self::VERSION_OPTION ) !== MSENTRA_SSO_VERSION ) {
			self::upgrade();
		}

		add_action( 'update_option_' . Settings::OPTION, array( Settings::class, 'flush' ) );

		( new Authenticator() )->register();
		( new Login_UI() )->register();

		if ( is_admin() ) {
			( new Admin() )->register();
		}
	}

	/**
	 * Activation hook.
	 */
	public static function activate() {
		self::upgrade();
	}

	/**
	 * Creates default settings and migrates data from version 1.x.
	 */
	public static function upgrade() {
		if ( false === get_option( Settings::OPTION ) ) {
			add_option( Settings::OPTION, Settings::defaults() );
		}

		self::migrate_legacy_table();

		update_option( self::VERSION_OPTION, MSENTRA_SSO_VERSION );
	}

	/**
	 * Version 1.x stored its settings in a custom "azure_auth_settings" table.
	 * Moves those credentials into the option and drops the table.
	 */
	private static function migrate_legacy_table() {
		global $wpdb;

		$table = $wpdb->prefix . 'azure_auth_settings';

		// phpcs:disable WordPress.DB.DirectDatabaseQuery, WordPress.DB.PreparedSQL.InterpolatedNotPrepared, PluginCheck.Security.DirectDB.UnescapedDBParameter -- One-off migration of a legacy table; the table name is not user input.
		if ( $wpdb->get_var( $wpdb->prepare( 'SHOW TABLES LIKE %s', $wpdb->esc_like( $table ) ) ) !== $table ) {
			return;
		}

		$row      = $wpdb->get_row( "SELECT client_id, client_secret, tenant_id FROM {$table} ORDER BY id ASC LIMIT 1", ARRAY_A );
		$settings = get_option( Settings::OPTION, array() );
		$settings = wp_parse_args( is_array( $settings ) ? $settings : array(), Settings::defaults() );

		if ( is_array( $row ) && '' === $settings['client_id'] ) {
			$settings['client_id']     = (string) $row['client_id'];
			$settings['client_secret'] = (string) $row['client_secret'];
			$settings['tenant_id']     = strtolower( (string) $row['tenant_id'] );
			update_option( Settings::OPTION, $settings );
		}

		$wpdb->query( "DROP TABLE IF EXISTS {$table}" );
		// phpcs:enable
	}
}
