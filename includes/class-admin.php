<?php
/**
 * Admin screens.
 *
 * @package MSEntraSSO
 */

namespace MSEntraSSO;

use WP_User;

defined( 'ABSPATH' ) || exit;

/**
 * Settings page, notices and user profile integration.
 */
class Admin {

	/**
	 * Settings page slug.
	 */
	const PAGE = 'msentra-sso';

	/**
	 * Registers hooks.
	 */
	public function register() {
		add_action( 'admin_menu', array( $this, 'add_menu' ) );
		add_action( 'admin_init', array( $this, 'register_settings' ) );
		add_action( 'admin_notices', array( $this, 'setup_notice' ) );
		add_filter( 'plugin_action_links_' . plugin_basename( MSENTRA_SSO_FILE ), array( $this, 'action_links' ) );
		add_action( 'show_user_profile', array( $this, 'profile_section' ) );
		add_action( 'edit_user_profile', array( $this, 'profile_section' ) );
		add_action( 'personal_options_update', array( $this, 'save_profile' ) );
		add_action( 'edit_user_profile_update', array( $this, 'save_profile' ) );
	}

	/**
	 * URL of the settings page.
	 *
	 * @return string
	 */
	public static function page_url() {
		return admin_url( 'options-general.php?page=' . self::PAGE );
	}

	/**
	 * Adds Settings → Microsoft Entra SSO.
	 */
	public function add_menu() {
		$hook = add_options_page(
			__( 'SSO Login for Microsoft Entra ID', 'sso-login-for-microsoft-entra-id' ),
			__( 'Microsoft Entra SSO', 'sso-login-for-microsoft-entra-id' ),
			'manage_options',
			self::PAGE,
			array( $this, 'render_page' )
		);
		add_action( 'admin_print_styles-' . $hook, array( $this, 'enqueue_assets' ) );
	}

	/**
	 * Loads the settings page stylesheet.
	 */
	public function enqueue_assets() {
		wp_enqueue_style( 'msentra-sso-admin', MSENTRA_SSO_URL . 'assets/css/admin.css', array(), MSENTRA_SSO_VERSION );
	}

	/**
	 * Adds a "Settings" link on the Plugins screen.
	 *
	 * @param string[] $links Action links.
	 * @return string[]
	 */
	public function action_links( $links ) {
		array_unshift( $links, '<a href="' . esc_url( self::page_url() ) . '">' . esc_html__( 'Settings', 'sso-login-for-microsoft-entra-id' ) . '</a>' );
		return $links;
	}

	/**
	 * Reminds administrators to finish the setup.
	 */
	public function setup_notice() {
		if ( Settings::is_configured() || ! current_user_can( 'manage_options' ) ) {
			return;
		}
		$screen = get_current_screen();
		if ( ! $screen || ! in_array( $screen->id, array( 'plugins', 'dashboard' ), true ) ) {
			return;
		}
		printf(
			'<div class="notice notice-info"><p>%s <a href="%s">%s</a></p></div>',
			esc_html__( 'SSO Login for Microsoft Entra ID is almost ready.', 'sso-login-for-microsoft-entra-id' ),
			esc_url( self::page_url() ),
			esc_html__( 'Enter your app registration details to enable the "Sign in with Microsoft" button.', 'sso-login-for-microsoft-entra-id' )
		);
	}

	/**
	 * Registers the option, sections and fields.
	 */
	public function register_settings() {
		register_setting(
			self::PAGE,
			Settings::OPTION,
			array(
				'type'              => 'array',
				'sanitize_callback' => array( Settings::class, 'sanitize' ),
				'default'           => Settings::defaults(),
			)
		);

		add_settings_section( 'connection', __( 'Connection', 'sso-login-for-microsoft-entra-id' ), array( $this, 'section_connection' ), self::PAGE );
		add_settings_section( 'users', __( 'Users and roles', 'sso-login-for-microsoft-entra-id' ), array( $this, 'section_users' ), self::PAGE );
		add_settings_section( 'experience', __( 'Login experience', 'sso-login-for-microsoft-entra-id' ), '__return_false', self::PAGE );

		$fields = array(
			'redirect_uri'    => array( 'connection', __( 'Redirect URI', 'sso-login-for-microsoft-entra-id' ) ),
			'client_id'       => array( 'connection', __( 'Application (client) ID', 'sso-login-for-microsoft-entra-id' ) ),
			'tenant_id'       => array( 'connection', __( 'Directory (tenant) ID', 'sso-login-for-microsoft-entra-id' ) ),
			'client_secret'   => array( 'connection', __( 'Client secret', 'sso-login-for-microsoft-entra-id' ) ),
			'allowed_tenants' => array( 'connection', __( 'Allowed tenant IDs', 'sso-login-for-microsoft-entra-id' ) ),
			'match_by_email'  => array( 'users', __( 'Existing users', 'sso-login-for-microsoft-entra-id' ) ),
			'create_users'    => array( 'users', __( 'New users', 'sso-login-for-microsoft-entra-id' ) ),
			'default_role'    => array( 'users', __( 'Default role', 'sso-login-for-microsoft-entra-id' ) ),
			'allowed_domains' => array( 'users', __( 'Allowed email domains', 'sso-login-for-microsoft-entra-id' ) ),
			'role_mapping'    => array( 'users', __( 'Role mapping', 'sso-login-for-microsoft-entra-id' ) ),
			'sync_roles'      => array( 'users', __( 'Role sync', 'sso-login-for-microsoft-entra-id' ) ),
			'login_mode'      => array( 'experience', __( 'Login page', 'sso-login-for-microsoft-entra-id' ) ),
			'button_text'     => array( 'experience', __( 'Button text', 'sso-login-for-microsoft-entra-id' ) ),
			'login_redirect'  => array( 'experience', __( 'After sign-in', 'sso-login-for-microsoft-entra-id' ) ),
			'single_logout'   => array( 'experience', __( 'Sign out', 'sso-login-for-microsoft-entra-id' ) ),
		);

		foreach ( $fields as $key => $field ) {
			add_settings_field(
				$key,
				$field[1],
				array( $this, 'field_' . $key ),
				self::PAGE,
				$field[0],
				array( 'label_for' => 'msentra_sso_' . $key )
			);
		}
	}

	/**
	 * Renders the settings page.
	 */
	public function render_page() {
		if ( ! current_user_can( 'manage_options' ) ) {
			return;
		}
		?>
		<div class="wrap msentra-sso-admin">
			<h1><?php echo esc_html( get_admin_page_title() ); ?></h1>
			<div class="msentra-sso-admin__layout">
				<form action="options.php" method="post" class="msentra-sso-admin__form">
					<?php
					settings_fields( self::PAGE );
					do_settings_sections( self::PAGE );
					submit_button();
					?>
				</form>
				<aside class="msentra-sso-admin__help">
					<h2><?php esc_html_e( 'Quick setup', 'sso-login-for-microsoft-entra-id' ); ?></h2>
					<ol>
						<li>
							<?php
							printf(
								/* translators: %s: link to the Microsoft Entra admin center. */
								esc_html__( 'In the %s, go to Identity → Applications → App registrations → New registration.', 'sso-login-for-microsoft-entra-id' ),
								'<a href="https://entra.microsoft.com/" target="_blank" rel="noopener noreferrer">' . esc_html__( 'Microsoft Entra admin center', 'sso-login-for-microsoft-entra-id' ) . '</a>'
							);
							?>
						</li>
						<li><?php esc_html_e( 'Choose who can sign in (usually "Accounts in this organizational directory only").', 'sso-login-for-microsoft-entra-id' ); ?></li>
						<li><?php esc_html_e( 'Under Redirect URI choose "Web" and paste the Redirect URI shown on this page.', 'sso-login-for-microsoft-entra-id' ); ?></li>
						<li><?php esc_html_e( 'Copy the Application (client) ID and Directory (tenant) ID from the Overview page.', 'sso-login-for-microsoft-entra-id' ); ?></li>
						<li><?php esc_html_e( 'Under Certificates & secrets create a client secret and copy its Value (not the Secret ID).', 'sso-login-for-microsoft-entra-id' ); ?></li>
						<li><?php esc_html_e( 'Save these settings and test the "Sign in with Microsoft" button in a private browser window.', 'sso-login-for-microsoft-entra-id' ); ?></li>
					</ol>
					<p>
						<a href="https://github.com/Aryal-rajiv/Microsoft-Login-Plugin#readme" target="_blank" rel="noopener noreferrer"><?php esc_html_e( 'Full documentation', 'sso-login-for-microsoft-entra-id' ); ?></a>
					</p>
					<?php if ( Settings::is_configured() ) : ?>
						<h2><?php esc_html_e( 'Shortcode', 'sso-login-for-microsoft-entra-id' ); ?></h2>
						<p><?php esc_html_e( 'Place the sign-in button on any page:', 'sso-login-for-microsoft-entra-id' ); ?></p>
						<p><code>[msentra_sso_login]</code></p>
					<?php endif; ?>
				</aside>
			</div>
		</div>
		<?php
	}

	/**
	 * Intro for the connection section.
	 */
	public function section_connection() {
		echo '<p>' . esc_html__( 'Details of the app registration in Microsoft Entra ID (formerly Azure Active Directory).', 'sso-login-for-microsoft-entra-id' ) . '</p>';
	}

	/**
	 * Intro for the users section.
	 */
	public function section_users() {
		echo '<p>' . esc_html__( 'Control which Microsoft accounts can sign in and which WordPress role they get.', 'sso-login-for-microsoft-entra-id' ) . '</p>';
	}

	/**
	 * Field name attribute for a setting.
	 *
	 * @param string $key Setting name.
	 * @return string
	 */
	private function name( $key ) {
		return Settings::OPTION . '[' . $key . ']';
	}

	/**
	 * Renders a text input.
	 *
	 * @param string $key         Setting name.
	 * @param string $placeholder Placeholder.
	 * @param string $type        Input type.
	 */
	private function text_input( $key, $placeholder = '', $type = 'text' ) {
		$locked = Settings::is_constant( $key );
		printf(
			'<input type="%1$s" id="msentra_sso_%2$s" name="%3$s" value="%4$s" placeholder="%5$s" class="regular-text" autocomplete="off" spellcheck="false" %6$s>',
			esc_attr( $type ),
			esc_attr( $key ),
			esc_attr( $this->name( $key ) ),
			esc_attr( Settings::get( $key ) ),
			esc_attr( $placeholder ),
			disabled( $locked, true, false )
		);
		if ( $locked ) {
			$this->constant_note( $key );
		}
	}

	/**
	 * Notes that a value comes from wp-config.php.
	 *
	 * @param string $key Setting name.
	 */
	private function constant_note( $key ) {
		printf(
			'<p class="description">%s</p>',
			sprintf(
				/* translators: %s: PHP constant name. */
				esc_html__( 'Defined in wp-config.php by the %s constant.', 'sso-login-for-microsoft-entra-id' ),
				'<code>' . esc_html( Settings::CONSTANTS[ $key ] ) . '</code>'
			)
		);
	}

	/**
	 * Renders a checkbox.
	 *
	 * @param string $key   Setting name.
	 * @param string $label Label.
	 */
	private function checkbox( $key, $label ) {
		printf(
			'<label><input type="checkbox" id="msentra_sso_%1$s" name="%2$s" value="1" %3$s> %4$s</label>',
			esc_attr( $key ),
			esc_attr( $this->name( $key ) ),
			checked( (bool) Settings::get( $key ), true, false ),
			esc_html( $label )
		);
	}

	/**
	 * Renders a textarea.
	 *
	 * @param string $key         Setting name.
	 * @param string $placeholder Placeholder.
	 * @param int    $rows        Rows.
	 */
	private function textarea( $key, $placeholder = '', $rows = 3 ) {
		printf(
			'<textarea id="msentra_sso_%1$s" name="%2$s" rows="%3$d" class="large-text code" placeholder="%4$s" spellcheck="false">%5$s</textarea>',
			esc_attr( $key ),
			esc_attr( $this->name( $key ) ),
			(int) $rows,
			esc_attr( $placeholder ),
			esc_textarea( Settings::get( $key ) )
		);
	}

	/**
	 * Prints a field description.
	 *
	 * @param string $text Description (may contain <code>).
	 */
	private function description( $text ) {
		echo '<p class="description">' . wp_kses(
			$text,
			array(
				'code'   => array(),
				'strong' => array(),
			)
		) . '</p>';
	}

	/**
	 * Redirect URI (read-only).
	 */
	public function field_redirect_uri() {
		printf(
			'<input type="text" id="msentra_sso_redirect_uri" value="%s" class="regular-text code" readonly onfocus="this.select();">',
			esc_attr( Settings::redirect_uri() )
		);
		$this->description( __( 'Add this exact URL as a <strong>Web</strong> redirect URI in your app registration (Authentication → Platform configurations).', 'sso-login-for-microsoft-entra-id' ) );
	}

	/**
	 * Client ID.
	 */
	public function field_client_id() {
		$this->text_input( 'client_id', '00000000-0000-0000-0000-000000000000' );
	}

	/**
	 * Tenant ID.
	 */
	public function field_tenant_id() {
		$this->text_input( 'tenant_id', '00000000-0000-0000-0000-000000000000' );
		$this->description( __( 'Your directory (tenant) ID or a verified domain such as <code>contoso.onmicrosoft.com</code>. Use <code>organizations</code> or <code>common</code> only for multi-tenant apps, together with the allowed tenant IDs below.', 'sso-login-for-microsoft-entra-id' ) );
	}

	/**
	 * Client secret (never printed back).
	 */
	public function field_client_secret() {
		if ( Settings::is_constant( 'client_secret' ) ) {
			echo '<input type="password" id="msentra_sso_client_secret" value="" class="regular-text" placeholder="••••••••" disabled>';
			$this->constant_note( 'client_secret' );
			return;
		}

		$has_secret = '' !== Settings::get( 'client_secret' );
		printf(
			'<input type="password" id="msentra_sso_client_secret" name="%1$s" value="" class="regular-text" autocomplete="new-password" placeholder="%2$s">',
			esc_attr( $this->name( 'client_secret' ) ),
			esc_attr( $has_secret ? __( 'Saved — leave blank to keep the current secret', 'sso-login-for-microsoft-entra-id' ) : '' )
		);
		if ( $has_secret ) {
			printf(
				'<p><label><input type="checkbox" name="%s" value="1"> %s</label></p>',
				esc_attr( $this->name( 'clear_client_secret' ) ),
				esc_html__( 'Remove the saved secret', 'sso-login-for-microsoft-entra-id' )
			);
		}
		$this->description( __( 'Paste the secret <strong>Value</strong>. Secrets expire: set a reminder to renew it. For extra security define <code>MSENTRA_SSO_CLIENT_SECRET</code> in wp-config.php instead.', 'sso-login-for-microsoft-entra-id' ) );
	}

	/**
	 * Allowed tenants (multi-tenant mode only).
	 */
	public function field_allowed_tenants() {
		$this->textarea( 'allowed_tenants', '00000000-0000-0000-0000-000000000000', 2 );
		$this->description( __( 'Only used when the tenant is <code>common</code>, <code>organizations</code> or <code>consumers</code>. One tenant ID per line. Sign-ins from any other directory are rejected, which protects you from look-alike accounts in foreign directories.', 'sso-login-for-microsoft-entra-id' ) );
	}

	/**
	 * Match existing users by email.
	 */
	public function field_match_by_email() {
		$this->checkbox( 'match_by_email', __( 'Link Microsoft accounts to existing WordPress users with the same email address', 'sso-login-for-microsoft-entra-id' ) );
		$this->description( __( 'After the first sign-in the accounts stay linked by their immutable Microsoft object ID, even if the email address changes later.', 'sso-login-for-microsoft-entra-id' ) );
	}

	/**
	 * Create users.
	 */
	public function field_create_users() {
		$this->checkbox( 'create_users', __( 'Create a WordPress account the first time someone signs in with Microsoft', 'sso-login-for-microsoft-entra-id' ) );
		$this->description( __( 'When disabled, only people who already have an account on this site can sign in.', 'sso-login-for-microsoft-entra-id' ) );
	}

	/**
	 * Default role for new users.
	 */
	public function field_default_role() {
		printf( '<select id="msentra_sso_default_role" name="%s">', esc_attr( $this->name( 'default_role' ) ) );
		foreach ( Settings::assignable_roles() as $slug => $name ) {
			printf( '<option value="%s" %s>%s</option>', esc_attr( $slug ), selected( Settings::get( 'default_role' ), $slug, false ), esc_html( $name ) );
		}
		echo '</select>';
		$this->description( __( 'Role given to new users when no role mapping matches. Administrator can only be granted through the role mapping.', 'sso-login-for-microsoft-entra-id' ) );
	}

	/**
	 * Allowed email domains.
	 */
	public function field_allowed_domains() {
		$this->textarea( 'allowed_domains', 'contoso.com', 2 );
		$this->description( __( 'Optional. One domain per line. When set, only Microsoft accounts with these email domains can sign in.', 'sso-login-for-microsoft-entra-id' ) );
	}

	/**
	 * Role mapping.
	 */
	public function field_role_mapping() {
		$this->textarea( 'role_mapping', "WordPress.Admin = administrator\n00000000-0000-0000-0000-000000000000 = editor", 4 );
		$roles = implode( ', ', array_map( 'sanitize_key', array_keys( wp_roles()->get_names() ) ) );
		$this->description(
			sprintf(
				/* translators: %s: list of role slugs. */
				__( 'One rule per line: <code>Entra app role value or group object ID = WordPress role</code>. The first matching line wins. App roles come from the token\'s <code>roles</code> claim; group IDs require the <code>groups</code> claim to be enabled under Token configuration. Available roles: %s.', 'sso-login-for-microsoft-entra-id' ),
				'<code>' . esc_html( $roles ) . '</code>'
			)
		);
	}

	/**
	 * Role sync.
	 */
	public function field_sync_roles() {
		$this->checkbox( 'sync_roles', __( 'Update the role of existing users on every sign-in when a role mapping rule matches', 'sso-login-for-microsoft-entra-id' ) );
		$this->description( __( 'Make sure your own account matches the right rule before enabling this, so you do not lose administrator access.', 'sso-login-for-microsoft-entra-id' ) );
	}

	/**
	 * Login mode.
	 */
	public function field_login_mode() {
		$modes = array(
			'button'   => __( 'Show a "Sign in with Microsoft" button above the WordPress login form', 'sso-login-for-microsoft-entra-id' ),
			'redirect' => __( 'Send visitors straight to Microsoft (skip the WordPress login form)', 'sso-login-for-microsoft-entra-id' ),
		);
		echo '<fieldset>';
		foreach ( $modes as $value => $label ) {
			printf(
				'<label><input type="radio" name="%1$s" value="%2$s" %3$s> %4$s</label><br>',
				esc_attr( $this->name( 'login_mode' ) ),
				esc_attr( $value ),
				checked( Settings::get( 'login_mode' ), $value, false ),
				esc_html( $label )
			);
		}
		echo '</fieldset>';
		$this->description(
			sprintf(
				/* translators: %s: login URL that shows the regular form. */
				__( 'In redirect mode the regular form stays available at %s.', 'sso-login-for-microsoft-entra-id' ),
				'<code>' . esc_html( add_query_arg( Login_UI::LOCAL_ARG, '1', wp_login_url() ) ) . '</code>'
			)
		);
	}

	/**
	 * Button text.
	 */
	public function field_button_text() {
		$this->text_input( 'button_text', __( 'Sign in with Microsoft', 'sso-login-for-microsoft-entra-id' ) );
	}

	/**
	 * Redirect after login.
	 */
	public function field_login_redirect() {
		$this->text_input( 'login_redirect', admin_url(), 'url' );
		$this->description( __( 'Optional page to open after signing in. Defaults to the page the user came from, or the dashboard.', 'sso-login-for-microsoft-entra-id' ) );
	}

	/**
	 * Single logout.
	 */
	public function field_single_logout() {
		$this->checkbox( 'single_logout', __( 'Also sign users out of Microsoft when they log out of WordPress', 'sso-login-for-microsoft-entra-id' ) );
	}

	/**
	 * Shows the linked Microsoft account on the profile screen.
	 *
	 * @param WP_User $user User being edited.
	 */
	public function profile_section( $user ) {
		$identity = get_user_meta( $user->ID, Authenticator::META_IDENTITY, true );
		if ( ! $identity || ! current_user_can( 'edit_users' ) ) {
			return;
		}
		list( $tenant, $object ) = array_pad( explode( ':', $identity, 2 ), 2, '' );
		?>
		<h2><?php esc_html_e( 'Microsoft account', 'sso-login-for-microsoft-entra-id' ); ?></h2>
		<table class="form-table" role="presentation">
			<tr>
				<th scope="row"><?php esc_html_e( 'Linked identity', 'sso-login-for-microsoft-entra-id' ); ?></th>
				<td>
					<p>
						<?php esc_html_e( 'Object ID:', 'sso-login-for-microsoft-entra-id' ); ?> <code><?php echo esc_html( $object ); ?></code><br>
						<?php esc_html_e( 'Tenant ID:', 'sso-login-for-microsoft-entra-id' ); ?> <code><?php echo esc_html( $tenant ); ?></code>
					</p>
					<?php wp_nonce_field( 'msentra_sso_unlink_' . $user->ID, 'msentra_sso_unlink_nonce' ); ?>
					<label>
						<input type="checkbox" name="msentra_sso_unlink" value="1">
						<?php esc_html_e( 'Unlink this Microsoft account', 'sso-login-for-microsoft-entra-id' ); ?>
					</label>
				</td>
			</tr>
		</table>
		<?php
	}

	/**
	 * Unlinks the Microsoft account when requested from the profile screen.
	 *
	 * @param int $user_id User ID.
	 */
	public function save_profile( $user_id ) {
		if ( empty( $_POST['msentra_sso_unlink'] ) || ! current_user_can( 'edit_users' ) || ! current_user_can( 'edit_user', $user_id ) ) {
			return;
		}
		$nonce = isset( $_POST['msentra_sso_unlink_nonce'] ) ? sanitize_text_field( wp_unslash( $_POST['msentra_sso_unlink_nonce'] ) ) : '';
		if ( wp_verify_nonce( $nonce, 'msentra_sso_unlink_' . $user_id ) ) {
			delete_user_meta( $user_id, Authenticator::META_IDENTITY );
		}
	}
}
