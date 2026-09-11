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
2. Select the server-side web application / web browser OpenID Connect
   scenario.
3. Give it a name such as `Change-it`.
4. Record the generated **Client Identifier**.
5. Create a client secret and store it in the deployment secret store.
6. Add this exact redirect URI:
   `https://<change-it-host>/api/auth/adfs/callback`

The URI must match character-for-character, including HTTPS, hostname, path,
and trailing slash behavior. The application uses the authorization-code flow
with PKCE; it does not expose the client secret to the browser.

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

Start with a small test security group in the AD FS access policy. Do not grant
the application to the whole directory until the round trip is verified.

## 4. Configure the Change-it server

Add these values to the `.env` used by the **api** container:

```dotenv
ADFS_OIDC_ISSUER=https://fs.example.com/adfs
ADFS_CLIENT_ID=<client-id-from-adfs>
ADFS_CLIENT_SECRET=<client-secret-from-adfs>
ADFS_REDIRECT_URI=https://<change-it-host>/api/auth/adfs/callback
ADFS_SCOPE=openid profile email
ADFS_USERNAME_CLAIM=upn
ADFS_AUTO_PROVISION=false
```

Restart the API after changing the values:

```bash
docker compose up -d --build api
```

Keep `ADFS_AUTO_PROVISION=false` for the first test. In this mode an
administrator must create the user in Change-it first, with a username or
email matching the ADFS `upn` / `email` claim. Existing local and LDAP users
keep their existing source and roles; SSO only proves their identity.

After the controlled test succeeds, `ADFS_AUTO_PROVISION=true` may be enabled
if the desired policy is to create active, non-admin users automatically.
Auto-provisioning requires an `email` claim and never grants admin or roles.

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

- **`unavailable`**: one or more `ADFS_*` values are missing, or discovery
  cannot be reached from the API container.
- **AD FS redirect URI error**: the registered URI and
  `ADFS_REDIRECT_URI` differ. Compare them character-for-character.
- **`not-provisioned`**: with auto-provisioning disabled, create/link the
  Change-it user first. Check the exact UPN and email values in the token.
- **`invalid_client`**: verify the client ID and secret, and ensure the
  secret has not expired.
- **Nonce or state errors**: verify that the browser is returning to the same
  hostname and that cookies are enabled. The callback must be reached on the
  same HTTPS host that started the login.

For AD FS reference material, see Microsoft's documentation for
[OpenID Connect/OAuth concepts](https://learn.microsoft.com/en-us/windows-server/identity/ad-fs/development/ad-fs-openid-connect-oauth-concepts)
and [OpenID Connect/OAuth flows](https://learn.microsoft.com/en-us/windows-server/identity/ad-fs/overview/ad-fs-openid-connect-oauth-flows-scenarios).