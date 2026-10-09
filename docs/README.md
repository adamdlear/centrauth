# documentation

## OpenAPI

`openapi.yaml` describes the **core API routes that SDK clients use**:

| Route             | Purpose                          |
| ----------------- | -------------------------------- |
| `GET /healthz`    | Service/database health probe    |
| `POST /auth/login`    | Authenticate an end user     |
| `POST /auth/register` | Create a user account        |
| `POST /auth/logout`   | Revoke the current session   |

The admin UI routes (`/admin`, `/setup`, operator login/logout) and the
browser-only HTML pages (`GET /login`) are intentionally **not** part of this
spec.

### Design notes

- Endpoints take `application/x-www-form-urlencoded` form bodies.
- Success responses are HTTP `303 See Other` redirects that set the session
  cookie (`centrauth_session` by default); no JSON tokens are returned.
- All state-changing endpoints are CSRF-protected
  (`http.CrossOriginProtection`): cross-origin callers must complete the
  trusted-origin handshake or be same-origin.
- `POST /auth/register` returns `403` when registration is disabled
  (`ENABLE_REGISTRATION=true`).

### Tooling

Validate the spec with the Redocly CLI:

```sh
npx @redocly/cli lint docs/openapi.yaml
```

Preview it interactively (serves a docs site with a live spec viewer):

```sh
npx @redocly/cli preview-docs docs/openapi.yaml
```
