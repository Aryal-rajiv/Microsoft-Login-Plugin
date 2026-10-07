# Changelog

All notable changes to this project are documented here. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses [Semantic Versioning](https://semver.org/).

## [2.0.0] - 2026-10-07

Complete rewrite, renamed to **SSO Login for Microsoft Entra ID**.

### Added
- OpenID Connect authorization code flow with PKCE, nonce and full ID token validation.
- Single-use state bound to the browser with an `HttpOnly` cookie.
- Users are linked by their immutable Microsoft object ID after the first sign-in.
- Optional automatic user creation with a default role.
- Role mapping from Entra ID app roles or group IDs, with optional role sync.
- Allowed tenant IDs (multi-tenant) and allowed email domains.
- Redirect mode, custom button text, redirect after sign-in.
- Optional single sign-out from Microsoft.
- `[msentra_sso_login]` shortcode.
- `MSENTRA_SSO_CLIENT_ID`, `MSENTRA_SSO_TENANT_ID` and `MSENTRA_SSO_CLIENT_SECRET` constants.
- "Microsoft account" section on user profiles with an unlink option.
- Developer filters and actions, national cloud support.
- Translation template, WordPress.org readme, coding standards and CI.

### Changed
- Redirect URI is now the WordPress login URL instead of `admin-post.php?action=oidc_callback`.
- Settings page moved to **Settings → Microsoft Entra SSO** and uses the Settings API.
- Settings are stored in the options table; credentials from the 1.x table are migrated automatically.
- Errors are shown on the login page instead of `wp_die()` screens.
- The client secret is no longer printed back into the settings page.

### Removed
- The custom `azure_auth_settings` database table.
- The unused "Admin role" setting (replaced by role mapping).

### Security
- The settings form is now protected against CSRF by the Settings API nonce.
- The OAuth `state` is now single-use and bound to the browser that started the sign-in.
- The client secret is no longer HTML-escaped before being sent to Microsoft, which could corrupt secrets containing special characters.

## [1.1] - 2025

- Admin role setting and login hardening.

## [1.0] - 2025

- Initial release: settings page and "Login with Microsoft" button.

[2.0.0]: https://github.com/Aryal-rajiv/Microsoft-Login-Plugin/releases/tag/v2.0.0
