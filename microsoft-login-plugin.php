<?php
/**
 * Plugin Name: Azure Authentication Settings
 * Description: Stores Client ID, Client Secret, Tenant ID, and Redirect URI for Microsoft Azure authentication.
 * Version: 1.0
 * Author: Your Name
 */

// Prevent direct access
if (!defined('ABSPATH')) {
    exit;
}

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
        PRIMARY KEY (id)
    ) $charset_collate;";

    require_once(ABSPATH . 'wp-admin/includes/upgrade.php');
    dbDelta($sql);

    error_log('Azure Auth Settings Table created or already exists.');
}

// Add admin menu page
add_action('admin_menu', 'azure_auth_add_settings_page');

function azure_auth_add_settings_page() {
    add_menu_page(
        'Azure Auth Settings',
        'Azure Auth Settings',
        'manage_options',
        'azure-auth-settings',
        'azure_auth_settings_page',
        'dashicons-admin-generic',
        100
    );
}

// Render the admin settings page
function azure_auth_settings_page() {
    global $wpdb;
    $table_name = $wpdb->prefix . 'azure_auth_settings';

    // Save settings on form submission
    if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['azure_auth_save_settings'])) {
        $client_id = sanitize_text_field($_POST['azure_client_id']);
        $client_secret = sanitize_text_field($_POST['azure_client_secret']);
        $tenant_id = sanitize_text_field($_POST['azure_tenant_id']);
        $redirect_uri = esc_url_raw($_POST['azure_redirect_uri']);

        $wpdb->replace(
            $table_name,
            [
                'id' => 1, // Single row for settings
                'client_id' => $client_id,
                'client_secret' => $client_secret,
                'tenant_id' => $tenant_id,
                'redirect_uri' => $redirect_uri
            ],
            ['%d', '%s', '%s', '%s', '%s']
        );

        echo '<div class="updated"><p>Settings saved successfully!</p></div>';
    }

    // Retrieve existing values from the database
    $settings = $wpdb->get_row("SELECT * FROM $table_name WHERE id = 1", ARRAY_A);

    $client_id = $settings['client_id'] ?? '';
    $client_secret = $settings['client_secret'] ?? '';
    $tenant_id = $settings['tenant_id'] ?? '';
    $redirect_uri = $settings['redirect_uri'] ?? '';

    ?>
    <div class="wrap">
        <h1>Azure Authentication Settings</h1>
        <form method="post">
            <table class="form-table">
                <tr>
                    <th scope="row"><label for="azure_client_id">Client ID</label></th>
                    <td><input type="text" name="azure_client_id" id="azure_client_id" value="<?php echo esc_attr($client_id); ?>" class="regular-text"></td>
                </tr>
                <tr>
                    <th scope="row"><label for="azure_client_secret">Client Secret</label></th>
                    <td><input type="text" name="azure_client_secret" id="azure_client_secret" value="<?php echo esc_attr($client_secret); ?>" class="regular-text"></td>
                </tr>
                <tr>
                    <th scope="row"><label for="azure_tenant_id">Tenant ID</label></th>
                    <td><input type="text" name="azure_tenant_id" id="azure_tenant_id" value="<?php echo esc_attr($tenant_id); ?>" class="regular-text"></td>
                </tr>
                <tr>
                    <th scope="row"><label for="azure_redirect_uri">Redirect URI</label></th>
                    <td><input type="url" name="azure_redirect_uri" id="azure_redirect_uri" value="<?php echo esc_attr($redirect_uri); ?>" class="regular-text"></td>
                </tr>
            </table>
            <?php submit_button('Save Settings', 'primary', 'azure_auth_save_settings'); ?>
        </form>
    </div>
    <?php
}

?>







    


<?php

// Hook to add "Login with Microsoft" button on the login page
add_action('login_form', 'add_microsoft_login_button');

function add_microsoft_login_button() {
    // Fetch Azure settings from the database
    global $wpdb;
    $table_name = $wpdb->prefix . 'azure_auth_settings';

    $settings = $wpdb->get_row("SELECT * FROM $table_name LIMIT 1", ARRAY_A);

    if (!$settings) {
        echo '<p style="color:red; text-align:center;">Azure settings not configured!</p>';
        return;
    }

    $tenant_id = esc_attr($settings['tenant_id']);
    $client_id = esc_attr($settings['client_id']);
    $redirect_uri = esc_url($settings['redirect_uri']);

    // Microsoft OAuth 2.0 authorization endpoint
    $oauth_url = "https://login.microsoftonline.com/{$tenant_id}/oauth2/v2.0/authorize";
    $params = [
        'client_id' => $client_id,
        'response_type' => 'code',
        'redirect_uri' => $redirect_uri,
        'response_mode' => 'query',
        'scope' => 'https://graph.microsoft.com/User.Read',
        'state' => wp_create_nonce('microsoft_login'), // Secure nonce
    ];

    $login_url = $oauth_url . '?' . http_build_query($params);

    // Render the button
    echo '<p style="text-align: center; margin-top: 20px;">
        <a href="' . esc_url($login_url) . '" class="button button-secondary" style="background: #0078d7; color: #fff; text-decoration: none; padding: 10px 20px; border-radius: 4px;">
            Login with Microsoft
        </a>
    </p>';
}

// Hook to handle OAuth callback
add_action('init', 'handle_microsoft_login_callback');

function handle_microsoft_login_callback() {
    if (!isset($_GET['code']) || !isset($_GET['state'])) {
        return; // Not an OAuth callback
    }

    // Validate nonce
    if (!wp_verify_nonce($_GET['state'], 'microsoft_login')) {
        wp_die('Invalid state parameter.');
    }

    // Fetch Azure settings from the database
    global $wpdb;
    $table_name = $wpdb->prefix . 'azure_auth_settings';
    $settings = $wpdb->get_row("SELECT * FROM $table_name LIMIT 1", ARRAY_A);

    if (!$settings) {
        wp_die('Azure settings not configured.');
    }

    $tenant_id = esc_attr($settings['tenant_id']);
    $client_id = esc_attr($settings['client_id']);
    $client_secret = esc_attr($settings['client_secret']);
    $redirect_uri = esc_url($settings['redirect_uri']);

    // Exchange authorization code for access token
    $token_url = "https://login.microsoftonline.com/{$tenant_id}/oauth2/v2.0/token";

    $response = wp_remote_post($token_url, [
        'body' => [
            'client_id' => $client_id,
            'scope' => 'https://graph.microsoft.com/User.Read',
            'code' => sanitize_text_field($_GET['code']),
            'redirect_uri' => $redirect_uri,
            'grant_type' => 'authorization_code',
            'client_secret' => $client_secret,
        ],
    ]);

    if (is_wp_error($response)) {
        error_log('Token request failed: ' . $response->get_error_message());
        wp_die('Token request failed: ' . $response->get_error_message());
    }

    $response_body = wp_remote_retrieve_body($response);
    $token_data = json_decode($response_body, true);

    if (!isset($token_data['access_token'])) {
        wp_die('Failed to retrieve access token.');
    }

    // Use the access token to fetch Microsoft user info
    $access_token = $token_data['access_token'];
    $user_info_response = wp_remote_get('https://graph.microsoft.com/v1.0/me', [
        'headers' => [
            'Authorization' => 'Bearer ' . $access_token,
        ],
    ]);

    if (is_wp_error($user_info_response)) {
        wp_die('Failed to fetch user info: ' . $user_info_response->get_error_message());
    }

    $user_info = json_decode(wp_remote_retrieve_body($user_info_response), true);

    if (!isset($user_info['mail']) && !isset($user_info['userPrincipalName'])) {
        wp_die('Failed to retrieve user email.');
    }

    // Extract user email and check if it exists in WordPress
    $email = $user_info['mail'] ?? $user_info['userPrincipalName'];
    $user = get_user_by('email', $email);

    if (!$user) {
        wp_die('Access Denied: No WordPress account is associated with this email.');
    }

    // Log in the user
    wp_set_auth_cookie($user->ID);
    wp_redirect(admin_url()); // Redirect to WordPress admin
    exit;
}
?>
