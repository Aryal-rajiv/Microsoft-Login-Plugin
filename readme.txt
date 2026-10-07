=== SSO Login for Microsoft Entra ID ===
Contributors: rajivaryal
Tags: sso, microsoft, azure ad, entra id, login
Requires at least: 6.0
Tested up to: 7.1
Requires PHP: 7.4
Stable tag: 2.0.0
License: GPLv2 or later
License URI: https://www.gnu.org/licenses/gpl-2.0.html

Let your team sign in to WordPress with their Microsoft work or school account using secure single sign-on (Microsoft Entra ID, formerly Azure AD).

== Description ==

SSO Login for Microsoft Entra ID adds a **Sign in with Microsoft** button to your WordPress login page. People sign in with the Microsoft 365 / Entra ID account they already use every day: no extra passwords to remember, and access ends automatically when someone leaves your organization.

The plugin uses the standard OpenID Connect authorization code flow with PKCE against the Microsoft identity platform. It does not need any third-party service: your site talks directly to Microsoft.

= Features =

* **Sign in with Microsoft** button on wp-login.php, styled according to Microsoft's branding guidelines.
* **Redirect mode** that sends visitors straight to Microsoft, with a fallback URL for the regular WordPress form.
* **Link existing users** by email address on their first sign-in. After that, accounts stay linked by the immutable Microsoft object ID, even if the email address changes.
* **Automatic user creation** (optional) with a configurable default role.
* **Role mapping** from Entra ID app roles or security groups to WordPress roles, with optional role sync on every sign-in.
* **Restrict access** to specific tenants (directories) and email domains.
* **Single sign-out**: optionally sign users out of Microsoft when they log out of WordPress.
* **Shortcode** `[msentra_sso_login]` to place the button on any page.
* **wp-config.php constants** for the client ID, tenant ID and secret, so credentials can stay out of the database.
* Works with single-tenant and multi-tenant app registrations, and with national clouds through filters.
* Clean uninstall: removes all settings and user links.
* Developer friendly: many actions and filters to customize the flow.

= Security =

* Authorization code flow with **PKCE** and a client secret.
* The `state` value is single-use and bound to the browser that started the sign-in, which protects against login CSRF and replay.
* ID token checks: audience, issuer, tenant, nonce, expiry and not-before.
* Only accounts from your own directory are accepted. Multi-tenant setups require an explicit list of allowed tenant IDs.
* Administrator can never be the default role. It can only be granted through an explicit role mapping rule.
* The client secret is never printed back into the settings page.

= Requirements =

* A Microsoft Entra ID tenant (included with every Microsoft 365 business subscription) where you can create an app registration.
* HTTPS on your WordPress site (Microsoft requires HTTPS redirect URIs, except for `http://localhost`).

== Installation ==

1. Install and activate the plugin from **Plugins → Add New**, or upload the zip file.
2. Go to **Settings → Microsoft Entra SSO** and copy the **Redirect URI** shown there.
3. In the [Microsoft Entra admin center](https://entra.microsoft.com/) open **Identity → Applications → App registrations → New registration**:
    * Name: anything, e.g. "WordPress".
    * Supported account types: **Accounts in this organizational directory only** (recommended).
    * Redirect URI: platform **Web**, paste the Redirect URI from step 2.
4. On the app's **Overview** page copy the **Application (client) ID** and the **Directory (tenant) ID**.
5. Under **Certificates & secrets → Client secrets → New client secret**, create a secret and copy its **Value**.
6. Paste the three values into the plugin settings and click **Save Changes**.
7. Open your login page in a private browser window and click **Sign in with Microsoft**.

By default only people who already have a WordPress account with the same email address can sign in. Enable **New users** to create accounts automatically.

== Frequently Asked Questions ==

= Where do I find the Redirect URI? =

On **Settings → Microsoft Entra SSO**. It is your WordPress login URL, for example `https://example.com/wp-login.php`. It must be added to the app registration exactly as shown, with the **Web** platform.

= I get "AADSTS50011: The redirect URI ... does not match" =

The Redirect URI registered in Entra ID is different from the one the plugin sends. Copy it again from the settings page. Check `http` vs `https`, `www` vs no `www`, and a trailing slash.

= I get "AADSTS7000215: Invalid client secret provided" =

You probably copied the **Secret ID** instead of the secret **Value**, or the secret expired. Create a new secret and paste its Value.

= Can I keep the credentials out of the database? =

Yes. Add any of these to wp-config.php; the matching fields are then locked on the settings page:

`define( 'MSENTRA_SSO_CLIENT_ID', '...' );`
`define( 'MSENTRA_SSO_TENANT_ID', '...' );`
`define( 'MSENTRA_SSO_CLIENT_SECRET', '...' );`

= How do I make someone an administrator or editor automatically? =

Create app roles on the app registration (**App roles → Create app role**, e.g. value `WordPress.Admin`) and assign them to users or groups under **Enterprise applications → your app → Users and groups**. Then add a rule to **Role mapping**:

`WordPress.Admin = administrator`

You can also map security group object IDs once the `groups` claim is enabled under **Token configuration**. The first matching line wins.

= Can personal Microsoft accounts (outlook.com, hotmail.com) sign in? =

Yes. Register the app for personal accounts too, set the tenant to `common` or `consumers`, and add `9188040d-6c67-4c5b-b112-36a304b66dad` (the personal accounts tenant) to **Allowed tenant IDs**. Be aware that anyone can create a personal Microsoft account, so only combine this with automatic user creation if open registration is what you want.

= How do I get back to the normal login form in redirect mode? =

Visit `wp-login.php?local=1`.

= Somebody gets "There is no account on this site for your Microsoft account" =

Either create a WordPress user with their email address, or enable **New users** on the settings page.

= Where can I see why a sign-in failed? =

Visitors only see a short, safe message. With `WP_DEBUG` and `WP_DEBUG_LOG` enabled, the technical reason is written to `wp-content/debug.log`.

= Does it work on multisite? =

Yes. The plugin can be activated per site. A user who signs in on a site they are not a member of is added to it only when **New users** is enabled on that site.

= Does it work with national clouds (US Government, China)? =

Yes, using the `msentra_sso_authority_host` and `msentra_sso_graph_url` filters. See the developer documentation on GitHub.

== Screenshots ==

1. The Sign in with Microsoft button on the WordPress login page.
2. The settings page.

== Changelog ==

= 2.0.0 =
* Complete rewrite with a new name and a WordPress.org-ready structure.
* Secure OpenID Connect flow: PKCE, single-use browser-bound state, nonce and full ID token validation.
* The redirect URI is now the WordPress login URL. Update the redirect URI on your app registration when upgrading.
* Users are linked by their immutable Microsoft object ID.
* New: automatic user creation, default role, role mapping and role sync.
* New: allowed tenants and allowed email domains.
* New: redirect mode, custom button text, redirect after sign-in, single sign-out and the `[msentra_sso_login]` shortcode.
* New: wp-config.php constants for credentials.
* Settings moved from a custom database table to the options table; existing credentials are migrated automatically.
* Errors are shown on the login page instead of a blank error screen.
* Translation ready.
* Clean uninstall.

= 1.1 =
* Admin role setting and login hardening.

= 1.0 =
* Initial release.

== Upgrade Notice ==

= 2.0.0 =
Major security and feature update. The redirect URI changed to your login URL (shown on the settings page): add it to your Entra ID app registration after upgrading.
