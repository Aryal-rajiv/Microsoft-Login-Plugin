<?php
/**
 * Plugin Name: Microsoft Login Plugin
 * Description: Allow users to log in to WordPress admin using Microsoft login.
 * Version: 1.0.0
 * Author: Rajiv Aryal
 */
 function microsoft_login_enqueue_scripts() {
    wp_enqueue_style('microsoft-login-style', plugin_dir_url(__FILE__) . 'style.css');
}
add_action('admin_enqueue_scripts', 'microsoft_login_enqueue_scripts');

// Add Menu Page
function microsoft_login_menu_page() {
    add_options_page(
        'Microsoft Login Settings',
        'Microsoft Login',
        'manage_options',
        'microsoft-login',
        'microsoft_login_settings_page'
    );
}
add_action('admin_menu', 'microsoft_login_menu_page');


// Render Settings Page
function microsoft_login_settings_page() {
    ?>
    <div class="wrap">
        <h1>Microsoft Login Settings</h1>
        <form method="post" action="options.php">
            <?php
            settings_fields('microsoft-login-settings-group');
            do_settings_sections('microsoft-login-settings-group');
            ?>
            <table class="form-table">
                <tr valign="top">
                    <th scope="row">Client ID</th>
                    <td><input type="text" name="microsoft_client_id" value="<?php echo esc_attr(get_option('microsoft_client_id')); ?>" /></td>
                </tr>
                <tr valign="top">
                    <th scope="row">Client Secret</th>
                    <td><input type="text" name="microsoft_client_secret" value="<?php echo esc_attr(get_option('microsoft_client_secret')); ?>" /></td>
                </tr>
                <tr valign="top">
                    <th scope="row">Tenant ID</th>
                    <td><input type="text" name="microsoft_tenant_id" value="<?php echo esc_attr(get_option('microsoft_tenant_id')); ?>" /></td>
                </tr>
                <tr valign="top">
                    <th scope="row">Redirect URI</th>
                    <td><input type="text" name="microsoft_redirect_uri" value="<?php echo esc_attr(get_option('microsoft_redirect_uri')); ?>" /></td>
                </tr>
            </table>
            <?php submit_button(); ?>
        </form>

        <form method="post" action="">
            <input type="hidden" name="action" value="microsoft_login_initiate">
            <button type="submit" class="button button-primary">Login with Microsoft</button>
        </form>
    </div>
    <?php
}
// Register Settings
function microsoft_login_register_settings() {
    register_setting('microsoft-login-settings-group', 'microsoft_client_id');
    register_setting('microsoft-login-settings-group', 'microsoft_client_secret');
    register_setting('microsoft-login-settings-group', 'microsoft_tenant_id');
    register_setting('microsoft-login-settings-group', 'microsoft_redirect_uri');
}
add_action('admin_init', 'microsoft_login_register_settings');

// Handle Microsoft Login Initiation
function microsoft_login_initiate() {
    if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['action']) && $_POST['action'] === 'microsoft_login_initiate') {
        $clientId = get_option('microsoft_client_id');
        $tenantId = get_option('microsoft_tenant_id');
        $redirectUri = get_option('microsoft_redirect_uri');

        $authUrl = "https://login.microsoftonline.com/$tenantId/oauth2/v2.0/authorize?client_id=$clientId&response_type=code&redirect_uri=$redirectUri&scope=openid profile email";

        wp_redirect($authUrl);
        exit;
    }
}
add_action('admin_post_microsoft_login_initiate', 'microsoft_login_initiate');

// Handle Microsoft Login Callback
function microsoft_login_callback() {
    if (isset($_GET['code'])) {
        $authCode = sanitize_text_field($_GET['code']);

        $clientId = get_option('microsoft_client_id');
        $clientSecret = get_option('microsoft_client_secret');
        $tenantId = get_option('microsoft_tenant_id');
        $redirectUri = get_option('microsoft_redirect_uri');

        $tokenUrl = "https://login.microsoftonline.com/$tenantId/oauth2/v2.0/token";
        $response = wp_remote_post($tokenUrl, [
            'body' => [
                'client_id' => $clientId,
                'client_secret' => $clientSecret,
                'code' => $authCode,
                'redirect_uri' => $redirectUri,
                'grant_type' => 'authorization_code',
            ],
        ]);

        $responseBody = wp_remote_retrieve_body($response);
        $responseJson = json_decode($responseBody, true);

        if (isset($responseJson['access_token'])) {
            $userInfoUrl = "https://graph.microsoft.com/v1.0/me";
            $userInfoResponse = wp_remote_get($userInfoUrl, [
                'headers' => [
                    'Authorization' => 'Bearer ' . $responseJson['access_token'],
                ],
            ]);

            $userInfo = json_decode(wp_remote_retrieve_body($userInfoResponse), true);

            if (isset($userInfo['id'])) {
                // Log in user or display user info
                wp_die("Login successful. Welcome, {$userInfo['displayName']} ({$userInfo['mail']}).");
            } else {
                wp_die("Failed to retrieve user information.");
            }
        } else {
            wp_die("Failed to authenticate with Microsoft.");
        }
    }
}
add_action('admin_post_microsoft_login_callback', 'microsoft_login_callback');

