<?php
// Hook to add admin menu page
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
                'id' => 1,
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
                    <td><input type="password" name="azure_client_secret" id="azure_client_secret" value="<?php echo esc_attr($client_secret); ?>" class="regular-text"></td>
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