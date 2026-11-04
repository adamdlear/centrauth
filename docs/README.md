# documentation

## OpenAPI

`openapi.yaml` describes the **core OIDC protocol routes** that relying
parties use. The admin UI routes (`/admin`, `/setup`, operator login/logout)
are server-rendered HTML and intentionally not part of this spec.

## Authentication surfaces

centrauth has exactly two authentication surfaces:

- **Operators** sign in at `/admin/login` with a password. Operator accounts
  live in a separate store with their own sessions and cookie, and only
  operator sessions may reach `/admin`.
- **Application users** authenticate only through the OIDC authorization code
  flow. There is no standalone `/login` or `/register` page. When an
  unsigned-in user reaches `/authorize`, the provider renders a flow prompt;
  completing sign-in establishes a flow-scoped session and resumes the
  original authorization request.

User sessions exist to carry a single authorization request to completion;
centrauth does not offer persistent SSO across unrelated apps yet.

### Tooling

Validate the spec with the Redocly CLI:

```sh
npx @redocly/cli lint docs/openapi.yaml
```

Preview it interactively (serves a docs site with a live spec viewer):

```sh
npx @redocly/cli preview-docs docs/openapi.yaml
```
