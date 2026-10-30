<?php
/**
 * Login page button, shortcode and error messages.
 *
 * @package MSEntraSSO
 */

namespace MSEntraSSO;

use WP_Error;

defined( 'ABSPATH' ) || exit;

/**
 * Front-end output of the plugin.
 */
class Login_UI {

	/**
	 * Query argument that shows the regular WordPress login form in "redirect" mode.
	 */
	const LOCAL_ARG = 'local';

	/**
	 * Registers hooks.
	 */
	public function register() {
		add_action( 'login_enqueue_scripts', array( $this, 'enqueue_styles' ) );
		add_action( 'login_form', array( $this, 'render_login_form_button' ) );
		add_filter( 'wp_login_errors', array( $this, 'login_errors' ) );
		add_action( 'login_init', array( $this, 'maybe_auto_redirect' ), 20 );
		add_shortcode( 'msentra_sso_login', array( $this, 'shortcode' ) );
	}

	/**
	 * Enqueues the button stylesheet on the login page.
	 */
	public function enqueue_styles() {
		if ( Settings::is_configured() ) {
			wp_enqueue_style( 'msentra-sso-login', MSENTRA_SSO_URL . 'assets/css/login.css', array(), MSENTRA_SSO_VERSION );
			wp_enqueue_script(
				'msentra-sso-login',
				MSENTRA_SSO_URL . 'assets/js/login.js',
				array(),
				MSENTRA_SSO_VERSION,
				array(
					'in_footer' => true,
					'strategy'  => 'defer',
				)
			);
		}
	}

	/**
	 * Adds the "Sign in with Microsoft" button to wp-login.php.
	 */
	public function render_login_form_button() {
		if ( ! Settings::is_configured() ) {
			return;
		}

		// phpcs:ignore WordPress.Security.NonceVerification.Recommended -- Only forwarded to the sign-in URL, which validates it.
		$redirect_to = isset( $_REQUEST['redirect_to'] ) && is_string( $_REQUEST['redirect_to'] ) ? wp_sanitize_redirect( wp_unslash( $_REQUEST['redirect_to'] ) ) : '';

		echo '<div class="msentra-sso">';
		echo $this->button( $redirect_to ); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- Escaped in button().
		echo '<p class="msentra-sso__separator"><span>' . esc_html__( 'or', 'sso-login-for-microsoft-entra-id' ) . '</span></p>';
		echo '</div>';
	}

	/**
	 * [msentra_sso_login] shortcode.
	 *
	 * Attributes: text (button label), redirect_to (URL after sign-in).
	 *
	 * @param array|string $atts Shortcode attributes.
	 * @return string
	 */
	public function shortcode( $atts ) {
		if ( is_user_logged_in() || ! Settings::is_configured() ) {
			return '';
		}

		$atts = shortcode_atts(
			array(
				'text'        => '',
				'redirect_to' => '',
			),
			$atts,
			'msentra_sso_login'
		);

		wp_enqueue_style( 'msentra-sso-login', MSENTRA_SSO_URL . 'assets/css/login.css', array(), MSENTRA_SSO_VERSION );

		$redirect_to = '' !== $atts['redirect_to'] ? $atts['redirect_to'] : $this->current_url();

		return '<div class="msentra-sso msentra-sso--shortcode">' . $this->button( $redirect_to, $atts['text'] ) . '</div>';
	}

	/**
	 * Button markup following Microsoft's sign-in branding guidelines.
	 *
	 * @param string $redirect_to URL to return to after signing in.
	 * @param string $text        Optional label override.
	 * @return string
	 */
	public function button( $redirect_to = '', $text = '' ) {
		if ( '' === $text ) {
			$text = Settings::get( 'button_text' );
		}
		if ( '' === $text ) {
			$text = __( 'Sign in with Microsoft', 'sso-login-for-microsoft-entra-id' );
		}

		$logo = '<svg class="msentra-sso__logo" xmlns="http://www.w3.org/2000/svg" width="21" height="21" viewBox="0 0 21 21" aria-hidden="true" focusable="false">'
			. '<rect x="1" y="1" width="9" height="9" fill="#f25022"/><rect x="11" y="1" width="9" height="9" fill="#7fba00"/>'
			. '<rect x="1" y="11" width="9" height="9" fill="#00a4ef"/><rect x="11" y="11" width="9" height="9" fill="#ffb900"/></svg>';

		return sprintf(
			'<a class="msentra-sso__button" href="%1$s">%2$s<span class="msentra-sso__label">%3$s</span></a>',
			esc_url( Authenticator::login_url( $redirect_to ) ),
			$logo,
			esc_html( $text )
		);
	}

	/**
	 * In "redirect" mode, sends visitors of wp-login.php straight to Microsoft.
	 */
	public function maybe_auto_redirect() {
		if ( 'redirect' !== Settings::get( 'login_mode' ) || ! Settings::is_configured() ) {
			return;
		}

		// phpcs:disable WordPress.Security.NonceVerification.Recommended -- Only inspects which screen was requested.
		$action = isset( $_REQUEST['action'] ) ? sanitize_key( wp_unslash( $_REQUEST['action'] ) ) : 'login';
		if ( 'login' !== $action ) {
			return;
		}
		$skip = array( self::LOCAL_ARG, Authenticator::ERROR_ARG, 'loggedout', 'interim-login', 'reauth', 'checkemail', 'state', 'code', 'error' );
		foreach ( $skip as $arg ) {
			if ( isset( $_GET[ $arg ] ) ) {
				return;
			}
		}
		$redirect_to = isset( $_GET['redirect_to'] ) && is_string( $_GET['redirect_to'] ) ? wp_sanitize_redirect( wp_unslash( $_GET['redirect_to'] ) ) : '';
		// phpcs:enable

		if ( ! isset( $_SERVER['REQUEST_METHOD'] ) || 'GET' !== $_SERVER['REQUEST_METHOD'] || is_user_logged_in() ) {
			return;
		}

		wp_safe_redirect( Authenticator::login_url( $redirect_to ) );
		exit;
	}

	/**
	 * Shows sign-in errors on the login screen.
	 *
	 * @param WP_Error $errors Login errors.
	 * @return WP_Error
	 */
	public function login_errors( $errors ) {
		// phpcs:ignore WordPress.Security.NonceVerification.Recommended -- Display only.
		if ( ! isset( $_GET[ Authenticator::ERROR_ARG ] ) ) {
			return $errors;
		}

		// phpcs:ignore WordPress.Security.NonceVerification.Recommended -- Display only.
		$code = sanitize_key( wp_unslash( $_GET[ Authenticator::ERROR_ARG ] ) );

		if ( ! $errors instanceof WP_Error ) {
			$errors = new WP_Error();
		}
		$errors->add( 'msentra_sso_' . $code, self::error_message( $code ) );

		return $errors;
	}

	/**
	 * User-facing message for an error code.
	 *
	 * Details are never shown to visitors; they are written to the debug log instead.
	 *
	 * @param string $code Error code.
	 * @return string
	 */
	public static function error_message( $code ) {
		$prefix   = '<strong>' . esc_html__( 'Microsoft sign-in failed:', 'sso-login-for-microsoft-entra-id' ) . '</strong> ';
		$messages = array(
			'not_configured'     => __( 'Microsoft sign-in has not been configured yet.', 'sso-login-for-microsoft-entra-id' ),
			'invalid_state'      => __( 'Your sign-in session expired or was started in another browser. Please try again.', 'sso-login-for-microsoft-entra-id' ),
			'access_denied'      => __( 'The sign-in was cancelled or permission was not granted.', 'sso-login-for-microsoft-entra-id' ),
			'provider_error'     => __( 'Microsoft could not complete the sign-in. Please try again or contact the site administrator.', 'sso-login-for-microsoft-entra-id' ),
			'token_error'        => __( 'The site could not verify your sign-in with Microsoft. Please contact the site administrator.', 'sso-login-for-microsoft-entra-id' ),
			'invalid_token'      => __( 'The sign-in response from Microsoft was not valid. Please try again.', 'sso-login-for-microsoft-entra-id' ),
			'tenant_not_allowed' => __( 'Accounts from your organization are not allowed to sign in to this site.', 'sso-login-for-microsoft-entra-id' ),
			'domain_not_allowed' => __( 'Accounts with your email domain are not allowed to sign in to this site.', 'sso-login-for-microsoft-entra-id' ),
			'no_email'           => __( 'Your Microsoft account does not have an email address.', 'sso-login-for-microsoft-entra-id' ),
			'user_not_found'     => __( 'There is no account on this site for your Microsoft account. Please ask the site administrator to create one for you.', 'sso-login-for-microsoft-entra-id' ),
			'identity_conflict'  => __( 'The account with your email address is already linked to a different Microsoft account. Please contact the site administrator.', 'sso-login-for-microsoft-entra-id' ),
			'create_failed'      => __( 'Your account could not be created. Please contact the site administrator.', 'sso-login-for-microsoft-entra-id' ),
		);

		$message = isset( $messages[ $code ] ) ? $messages[ $code ] : __( 'Please try again or contact the site administrator.', 'sso-login-for-microsoft-entra-id' );

		/**
		 * Filters the message shown on the login page for a sign-in error.
		 *
		 * @param string $message Message (plain text).
		 * @param string $code    Error code.
		 */
		return $prefix . esc_html( apply_filters( 'msentra_sso_error_message', $message, $code ) );
	}

	/**
	 * URL of the current front-end request.
	 *
	 * @return string
	 */
	private function current_url() {
		if ( ! isset( $_SERVER['HTTP_HOST'], $_SERVER['REQUEST_URI'] ) ) {
			return home_url( '/' );
		}
		$url = wp_sanitize_redirect( wp_unslash( $_SERVER['HTTP_HOST'] . $_SERVER['REQUEST_URI'] ) );
		return set_url_scheme( 'http://' . $url );
	}
}
