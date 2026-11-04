# documentation

## OpenAPI

`openapi.yaml` describes the **core OIDC protocol routes** that relying
parties use:

| Route                                  | Purpose                                  |
| -------------------------------------- | ---------------------------------------- |
| `GET /healthz`                         | Service/database health probe            |
| `GET /.well-known/openid-configuration`| OIDC discovery metadata                  |
| `GET /.well-known/jwks.json`           | Public signing keys (JWKS)               |
| `GET /authorize`                       | Start the authorization code flow        |
| `POST /token`                          | Exchange an authorization code for tokens|

The admin UI routes (`/admin`, `/setup`, operator login/logout) are
server-rendered HTML and intentionally **not** part of this spec.

### Design notes

- Only the authorization code flow is supported. PKCE is mandatory (`S256`).
- `nonce` is required when the `openid` scope is requested.
- The token endpoint takes `application/x-www-form-urlencoded` bodies and
  returns JSON with `Cache-Control: no-store`.
- `/token` is not CSRF-protected because it is a server-to-server API call,
  not a browser form submission.
- Phase 1 issues an opaque bearer access token so standard OAuth2 clients can
  complete the exchange. No resource endpoint accepts it yet.
- Application users sign in only through brokered identity providers, rendered
  mid-flow by `/authorize`. There is no standalone login or registration page.
- Operator accounts authenticate separately under `/admin/login`.

## Authentication surfaces

centrauth has exactly two authentication surfaces:

- **Operators** sign in at `/admin/login` with a password. Operator accounts
  live in a separate store with their own sessions and cookie, and only
  operator sessions may reach `/admin`.
- **Application users** authenticate only through the OIDC authorization code
  flow. There is no standalone `/login` or `/register` page. When an unsigned-in
  user reaches `/authorize`, the provider renders a flow prompt with the
  identity providers configured for that app (Google or GitHub). Completing
  provider sign-in provisions or links a local user, establishes a
  flow-scoped session, and resumes the original authorization request.

User sessions exist to carry a single authorization request to completion;
centrauth does not offer persistent SSO across unrelated apps yet.

## Configuration

Beyond the database and session settings, the OIDC and broker features use:

| Variable                   | Default                  | Purpose                                 |
| -------------------------- | ------------------------ | --------------------------------------- |
| `ISSUER_URL`               | `http://localhost:8080`  | Canonical issuer; discovery and `iss`   |
| `SIGNING_KEY_PATH`         | `./signing-key.pem`      | RSA key for ID tokens (auto-generated)  |
| `ID_TOKEN_TTL`             | `10m`                    | ID token lifetime                       |
| `PROVIDER_SECRET_KEY_PATH` | `./provider-secret.key`  | AES-GCM key for provider secrets        |

Both key files are generated on first run if missing and are excluded from git.
Provider client secrets are stored encrypted and are never returned after
entry.

### Tooling

Validate the spec with the Redocly CLI:

```sh
npx @redocly/cli lint docs/openapi.yaml
```

Preview it interactively (serves a docs site with a live spec viewer):

```sh
npx @redocly/cli preview-docs docs/openapi.yaml
```
