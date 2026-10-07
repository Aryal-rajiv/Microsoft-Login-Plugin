<?php
/**
 * Removes all plugin data when the plugin is deleted from the Plugins screen.
 *
 * @package MSEntraSSO
 */

defined( 'WP_UNINSTALL_PLUGIN' ) || exit;

/**
 * Deletes the options, pending sign-in transients and user links of one site.
 */
function msentra_sso_uninstall_site() {
	global $wpdb;

	delete_option( 'msentra_sso_settings' );
	delete_option( 'msentra_sso_version' );

	// phpcs:disable WordPress.DB.DirectDatabaseQuery -- Cleanup of transients with dynamic names and of the legacy 1.x table.
	$wpdb->query(
		$wpdb->prepare(
			"DELETE FROM {$wpdb->options} WHERE option_name LIKE %s OR option_name LIKE %s",
			$wpdb->esc_like( '_transient_msentra_sso_' ) . '%',
			$wpdb->esc_like( '_transient_timeout_msentra_sso_' ) . '%'
		)
	);
	$wpdb->query( "DROP TABLE IF EXISTS {$wpdb->prefix}azure_auth_settings" ); // phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared, WordPress.DB.DirectDatabaseQuery.SchemaChange
	// phpcs:enable
}

if ( is_multisite() ) {
	foreach ( get_sites(
		array(
			'fields' => 'ids',
			'number' => 0,
		)
	) as $msentra_sso_site_id ) {
		switch_to_blog( $msentra_sso_site_id );
		msentra_sso_uninstall_site();
		restore_current_blog();
	}
} else {
	msentra_sso_uninstall_site();
}

// User meta is shared by the whole network.
delete_metadata( 'user', 0, 'msentra_sso_identity', '', true );
