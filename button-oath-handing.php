<?php

//Prevent direct access
if (!defined('ABSPATH')){
    exit;
}

// Hook to add "Login with Microsoft" button on the login page
add_action('login_form', 'add_microsoft_login_button');

function add_microsoft_login_button() {
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

    $oauth_url = "https://login.microsoftonline.com/{$tenant_id}/oauth2/v2.0/authorize";
    $params = [
        'client_id' => $client_id,
        'response_type' => 'code',
        'redirect_uri' => $redirect_uri,
        'response_mode' => 'query',
        'scope' => 'https://graph.microsoft.com/User.Read',
        'state' => wp_create_nonce('microsoft_login'),
    ];

    $login_url = $oauth_url . '?' . http_build_query($params);

    echo '<p style="text-align: center; margin-top: 20px;">
        <a href="' . esc_url($login_url) . '" class="button button-secondary" style="background: #0078d7; color: #fff; text-decoration: none; padding: 10px 10px; border-radius: 4px;">
            Login with Microsoft
        </a>
    </p>';
}

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

    // Extract user email
    $email = strtolower($user_info['mail'] ?? $user_info['userPrincipalName'] ?? null);

    if (!$email) {
        wp_die('Failed to retrieve user email from Microsoft account.');
    }

    // Debug email logging
    error_log('Email from Microsoft: ' . $email);

    // Check if user exists in WordPress
    $user = get_user_by('email', $email);

    if ($user) {
        // If the user exists, log them in
        wp_set_auth_cookie($user->ID);
        wp_redirect(admin_url()); // Redirect to WordPress admin dashboard
        exit;
    } else {
        // If the user doesn't exist, create a new user
        $username = sanitize_user(str_replace('@', '_', $email), true); // Replace '@' with '_'
        $username = $username . '_' . uniqid(); // Append a unique ID to ensure uniqueness

        // Create a new user with a unique username
        $user_id = wp_create_user($username, wp_generate_password(), $email);

        if (is_wp_error($user_id)) {
            wp_die('Failed to create WordPress user: ' . $user_id->get_error_message());
        }

        // Optionally, update user role or metadata
        $user = get_user_by('id', $user_id);
        $user->set_role('editor'); // Set default role

        // Log in the new user
        wp_set_auth_cookie($user_id);
        wp_redirect(admin_url()); // Redirect to WordPress admin dashboard
        exit;
    }
}
?>