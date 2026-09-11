# Microsoft AD FS SSO setup for Change-it

This fork adds an optional server-side OpenID Connect authorization-code flow.
Local accounts and the existing LDAP authentication path remain unchanged.
The API validates the AD FS ID token, maps the identity to a Change-it user,
then creates the same session and CSRF cookies used by the existing login.

## 1. Prerequisites

- AD FS on Windows Server 2016 or newer with OpenID Connect enabled.
- The Change-it instance reachable over HTTPS from the user's browser.
- A stable public hostname for the instance. Do not use an ephemeral preview URL
  for the production AD FS registration.
- The AD FS issuer URL, normally:
  `https://fs.example.com/adfs`

The discovery document should be reachable at:

`https://fs.example.com/adfs/.well-known/openid-configuration`

Open it in a browser and confirm it contains `authorization_endpoint`,
`token_endpoint`, and `jwks_uri`.

## 2. Create the AD FS application group

In **AD FS Management**:

1. Open **Application Groups** and choose **Add Application Group**.
2. Select the **Web browser accessing a web application** OpenID Connect
   scenario. A public client without a secret is supported when AD FS is
   configured to allow authorization-code exchange with PKCE.
3. Give it a name such as `Change-it`.
4. Record the generated **Client Identifier**.
5. If the AD FS application is a confidential server client, create a client
   secret. Public clients using PKCE can omit the secret.
6. Add this exact redirect URI:
   `https://<change-it-host>/api/auth/adfs/callback`

The URI must match character-for-character, including HTTPS, hostname, path,
and trailing slash behavior. The application uses the authorization-code flow
with PKCE. When a confidential-client secret is configured, it is used only by
the API during token exchange and is never exposed to the browser.

## 3. Issue the identity claims

Configure the application group / relying-party issuance rules so the ID token
contains these claims:

| Claim | Recommended AD value | Used for |
| --- | --- | --- |
| `upn` | Active Directory UPN | Match existing Change-it username |
| `email` | Mail or email address | Match existing email / auto-provision |
| `name` | Display name | Display name for a new user |

AD FS often emits claim-type URIs instead of short names. The implementation
accepts both short names and the standard Microsoft claim URI forms. If your
deployment uses another stable identifier, set `ADFS_USERNAME_CLAIM` to that
claim name.

In AD FS, add an **Issuance Transform Rule** using **Send LDAP Attributes as
Claims** and map:

- `User-Principal-Name` to `UPN`
- `E-Mail-Addresses` to `E-Mail Address`
- `Display-Name` to `Name`

The OIDC `sub` claim is issued by AD FS and does not need a custom LDAP mapping.
`upn` is the recommended login identifier. `email` is required when
auto-provisioning is enabled; `name` is optional and is used as the display name
for newly provisioned users.

### Client permissions

This integration signs users in and does not call a separate Web API. Permit the
client to request the `openid` scope. The configured request also asks for
`profile` and `email`; permit those when your AD FS version/application-group
configuration exposes them. No `user_impersonation` or custom API permission is
required for Change-it itself. If AD FS reports `invalid_scope`, first test with
the scope set to `openid`, then add the optional scopes supported by the server.

Start with a small test security group in the AD FS access policy. Do not grant
the application to the whole directory until the round trip is verified.

## 4. Configure Change-it in Settings

Sign in to Change-it as an administrator, then open **Settings → ADFS**.

1. Enable AD FS authentication.
2. Enter the issuer URL and client ID from the application group. Enter the
   client secret only for a confidential server client; leave it blank for a
   public PKCE client.
3. Enter the redirect URI registered in AD FS. The page proposes the current
   Change-it origin followed by `/api/auth/adfs/callback` and provides a copy
   button.
4. Keep the default scopes (`openid profile email`) unless your AD FS
   configuration requires a different set.
5. Set the username claim to `upn`, or to the stable claim configured by your
   issuance rules.
6. Leave auto-provisioning disabled for the first test.
7. If AD FS uses an internal CA, upload or paste the PEM-encoded root and
   intermediate CA certificates. Do not upload a private key or the AD FS
   certificate unless it is itself the trust anchor.
8. Save the configuration, then select **Test configuration** to verify the
   issuer discovery document and endpoints.

When used, the client secret is never returned to the browser after it is
saved. Leaving the client-secret field blank on a later save preserves the
stored secret. Replacing it requires entering the new secret.

Keep auto-provisioning disabled for the first test. In this mode an
administrator must create the user in Change-it first, with a username or
email matching the AD FS `upn` / `email` claim. Existing local and LDAP users
keep their existing source and roles; SSO only proves their identity.

After the controlled test succeeds, auto-provisioning may be enabled if the
desired policy is to create active, non-admin users automatically.
Auto-provisioning requires an `email` claim and never grants admin or roles.

### Automatic AD FS reauthentication

After a successful AD FS login, Change-it stores only a non-sensitive
`cm_login_method=adfs` preference cookie. When the 12-hour Change-it session
expires, the browser automatically starts AD FS login once. If the user's AD FS
SSO session is still valid, AD FS normally returns without asking for
credentials; otherwise AD FS shows its login page. Change-it does not store the
AD FS ID token, access token, or refresh token. Selecting **Logout** explicitly
clears both the Change-it session and the remembered AD FS login preference.

### Environment-variable fallback

For existing deployments, the API continues to support environment variables
when no enabled database-backed AD FS configuration is available. Add these
values to the `.env` used by the **api** container:

```dotenv
ADFS_OIDC_ISSUER=https://fs.example.com/adfs
ADFS_CLIENT_ID=<client-id-from-adfs>
# Optional for a public PKCE client
ADFS_CLIENT_SECRET=
ADFS_REDIRECT_URI=https://<change-it-host>/api/auth/adfs/callback
ADFS_SCOPE=openid profile email
ADFS_USERNAME_CLAIM=upn
ADFS_AUTO_PROVISION=false
```

Restart the API after changing the values:

```bash
docker compose up -d --build api
```

Settings configuration takes precedence over these fallback values.

## 5. Test checklist

1. Open the Change-it login screen and select **Login with SSO (ADFS)**.
2. Confirm the browser is redirected to the AD FS sign-in endpoint.
3. Sign in with a test AD account.
4. Confirm the browser returns to Change-it and lands on the dashboard.
5. Confirm the user can access only the roles already assigned in Change-it.
6. Log out, then verify local login still works.
7. Verify an LDAP account still logs in through the existing username/password form.
8. Test a disabled Change-it account and an unprovisioned ADFS account.

## Troubleshooting

- **`unavailable`**: the saved Settings configuration is incomplete or
  disabled, the fallback `ADFS_*` values are incomplete, or discovery cannot
  be reached from the API container.
- **AD FS redirect URI error**: the registered URI and the URI saved in
  Settings (or fallback `ADFS_REDIRECT_URI`) differ. Compare them
  character-for-character.
- **`not-provisioned`**: with auto-provisioning disabled, create/link the
  Change-it user first. Check the exact UPN and email values in the token.
- **`invalid_client`**: verify the client ID. For a confidential client, also
  verify the secret and ensure it has not expired. For a public client, confirm
  AD FS permits token exchange without client authentication and supports PKCE.
- **Nonce or state errors**: verify that the browser is returning to the same
  hostname and that cookies are enabled. The callback must be reached on the
  same HTTPS host that started the login.

For AD FS reference material, see Microsoft's documentation for
[OpenID Connect/OAuth concepts](https://learn.microsoft.com/en-us/windows-server/identity/ad-fs/development/ad-fs-openid-connect-oauth-concepts)
and [OpenID Connect/OAuth flows](https://learn.microsoft.com/en-us/windows-server/identity/ad-fs/overview/ad-fs-openid-connect-oauth-flows-scenarios).