<?php
/**
 * Plugin Name:       SSO Login for Microsoft Entra ID
 * Plugin URI:        https://github.com/Aryal-rajiv/Microsoft-Login-Plugin
 * Description:       Let users sign in to WordPress with their Microsoft work or school account (Microsoft Entra ID, formerly Azure AD) using secure OpenID Connect single sign-on.
 * Version:           2.0.0
 * Requires at least: 6.0
 * Requires PHP:      7.4
 * Author:            Rajiv Aryal
 * Author URI:        https://aryalrajiv.com.np
 * License:           GPL-2.0-or-later
 * License URI:       https://www.gnu.org/licenses/gpl-2.0.html
 * Text Domain:       sso-login-for-microsoft-entra-id
 * Domain Path:       /languages
 *
 * @package MSEntraSSO
 */

defined( 'ABSPATH' ) || exit;

define( 'MSENTRA_SSO_VERSION', '2.0.0' );
define( 'MSENTRA_SSO_FILE', __FILE__ );
define( 'MSENTRA_SSO_DIR', plugin_dir_path( __FILE__ ) );
define( 'MSENTRA_SSO_URL', plugin_dir_url( __FILE__ ) );

require_once MSENTRA_SSO_DIR . 'includes/class-settings.php';
require_once MSENTRA_SSO_DIR . 'includes/class-authenticator.php';
require_once MSENTRA_SSO_DIR . 'includes/class-login-ui.php';
require_once MSENTRA_SSO_DIR . 'includes/class-admin.php';
require_once MSENTRA_SSO_DIR . 'includes/class-plugin.php';

register_activation_hook( __FILE__, array( 'MSEntraSSO\\Plugin', 'activate' ) );

add_action( 'plugins_loaded', array( 'MSEntraSSO\\Plugin', 'instance' ) );
