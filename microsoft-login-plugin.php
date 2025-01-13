<?php
/**
 * Plugin Name: Azure Authentication Settings
 * Description: Enables Single Sign-On (SSO) with Microsoft Azure AD for WordPress.
 * Version: 1.1
 * Author: Your Name
 */

// Prevent direct access
if (!defined('ABSPATH')) {
    exit;
}

//Include necessary files here
require_once plugin_dir_path(__FILE__) . 'admin-setting-page.php';
require_once plugin_dir_path(__FILE__) . 'button-oath-handing.php';


// Hook to create the table when the plugin is activated
register_activation_hook(__FILE__, 'create_azure_auth_settings_table');

function create_azure_auth_settings_table() {
    global $wpdb;
    $table_name = $wpdb->prefix . 'azure_auth_settings';
    $charset_collate = $wpdb->get_charset_collate();
    $sql = "CREATE TABLE {$table_name} (
        id INT(11) NOT NULL AUTO_INCREMENT,
        client_id VARCHAR(255) NOT NULL,
        client_secret VARCHAR(255) NOT NULL,
        tenant_id VARCHAR(255) NOT NULL,
        redirect_uri VARCHAR(255) NOT NULL,
        admin_role VARCHAR(255) NOT NULL, 
        PRIMARY KEY (id)
    ) $charset_collate;";

    require_once(ABSPATH . 'wp-admin/includes/upgrade.php');
    dbDelta($sql);
}

// Hook to delete the table when the plugin is uninstalled
register_uninstall_hook(__FILE__, 'delete_azure_auth_settings_table');

function delete_azure_auth_settings_table() {
    global $wpdb;
    $table_name = $wpdb->prefix . 'azure_auth_settings';
    $wpdb->query("DROP TABLE IF EXISTS {$table_name}");
}

?>