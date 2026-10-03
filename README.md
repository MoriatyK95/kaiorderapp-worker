# kaiorderapp-worker

A JavaScript Cloudflare Worker developed and deployed with Wrangler. The current
checkpoint verifies a Cloudflare Access application token at `/secure` and returns
the authenticated email as plain text:

```text
Verified user: user@example.com
```

## Current behaviour

The handler accepts only the exact URL pathname `/secure`. Query strings do not
change that pathname; `/secure/` and `/secure-example` are different paths.

| Request or condition | Status | Response body |
| --- | --- | --- |
| Any other pathname | 404 | `Not found` |
| Missing issuer or audience configuration, or the placeholder audience | 500 | `Access configuration is incomplete.` |
| Missing `Cf-Access-Jwt-Assertion` | 403 | `Access token is missing.` |
| Token verification or signing-key retrieval fails | 403 | `Access token could not be verified.` |
| Verified token is not an application token, or its email is not a nonblank string | 403 | `A signed-in user is required.` |
| Valid application token with an email | 200 | `Verified user: user@example.com` |

On `/secure`, configuration is checked before the token header. Every response
created by this handler uses `Content-Type: text/plain; charset=utf-8` and
`Cache-Control: no-store`. The handler does not restrict the HTTP method.

## Authentication flow

Cloudflare Access handles the visitor's login and access policy before forwarding
a permitted request. The Access application and its email-allow policy are
configured separately; this repository does not provision them.

The Worker reads only the `Cf-Access-Jwt-Assertion` header for authentication.
It uses `jose` to retrieve public signing keys from
`${ACCESS_TEAM_DOMAIN}/cdn-cgi/access/certs` and verify the JWT. The public-key
lookup is reused between requests and replaced if the configured issuer changes.

The implemented checks are:

- The signature must verify with a trusted public key using `RS256`.
- The `iss` claim must match `ACCESS_TEAM_DOMAIN`, and `aud` must match or include
  `ACCESS_AUD`.
- `exp`, `sub`, and `email` must be present. The numeric expiration must be in the
  future. If `nbf` is present, it must be numeric and must not be in the future.
- If `iat` is present, `jose` checks that it is numeric. No maximum token age or
  additional future-`iat` check is configured. `sub` is required for presence;
  the Worker does not compare it with a separately configured user identity.
- After verification, `type` must equal `app` and `email` must be a string that
  is nonblank after trimming. There is no separate email-format check or email
  allowlist in the Worker.

Only after these checks does the Worker use the verified email in its response.
An email header alone is not accepted as identity. Cookies and `Authorization`
headers are not fallback token sources in this code. The handler does not log
tokens or return detailed verification errors.

## Configuration

The tracked `wrangler.jsonc` configures Worker `kaiorderapp-worker`, entry point
`src/index.js`, and compatibility date `2026-10-03`.

| Setting | Meaning |
| --- | --- |
| `vars.ACCESS_TEAM_DOMAIN` | Trusted Access issuer URL, including `https://`, without a trailing slash. Also supplies the base URL for the public signing keys. |
| `vars.ACCESS_AUD` | Audience identifier for the intended Access application. The AUD is an application identifier, not a credential. |
| Top-level `routes` | Selects which incoming URLs invoke the deployed Worker. It is deployment routing configuration, not a runtime environment variable. |
| `workers_dev: false` | Disables the Worker's `workers.dev` endpoint. |
| `preview_urls: false` | Disables version preview URLs. |

The team domain and AUD are non-secret configuration identifiers. They remain in
the working Wrangler configuration. Entries under `vars` are passed to the
handler through `env`; the `routes` array belongs at the top level, alongside
`vars`, rather than inside it.

The current route is `https://tunnel.kaiorderapp.com/secure*`, in zone
`kaiorderapp.com`. This pattern selects the Worker for a broader set of URLs than
the JavaScript handler accepts: a routed request for `/secure/`, for example,
receives the handler's 404 response. URLs outside this route are not handled by
this Worker through this route.

To deploy your own copy, use your own domain, Cloudflare Access application,
issuer URL, application AUD, and corresponding route/zone configuration. DNS,
Tunnel, and Access policy setup are managed separately from this repository.

## Local development and deployment

Use Node.js 22 LTS or 24+ and npm. Install the versions recorded in the existing
lockfile:

```bash
npm ci
```

The `dev` script runs `wrangler dev`. Start the local server on loopback:

```bash
npm run dev -- --ip 127.0.0.1 --port 8787
```

Direct requests to `http://127.0.0.1:8787/secure` do not pass through the deployed
Access login flow. With the checked-in Access configuration and no token header,
the Worker returns 403, `Access token is missing.` A local email header alone
does not change that result.

For a manual Cloudflare deployment, authenticate and confirm the account first:

```bash
npx wrangler login
npx wrangler whoami
```

After reviewing the target account and `wrangler.jsonc`, check the deployment
bundle without publishing it:

```bash
npx wrangler deploy --dry-run
```

Publish intentionally with the existing deployment script:

```bash
npm run deploy
```

Pushing source to GitHub is separate from running a manual Wrangler deployment.
This repository does not define a CI/CD deployment workflow. Deployment commands
above are setup instructions, not a claim that a deployment was performed while
writing this documentation.

## Verification

The project owner reported these manual verification results:

| Check | Reported result |
| --- | --- |
| Local `/secure` request without a token | 403, `Access token is missing.` |
| Local `/secure` request with only an email header | 403, `Access token is missing.` |
| Local `/secure` request with a malformed token | 403, `Access token could not be verified.` |
| Live browser request after a permitted Access login | `Verified user: <authenticated email>` |

These are owner-reported observations, not tests executed as part of the
documentation update. They do not establish that every JWT failure condition
was tested. In particular, rejecting a malformed token does not independently
demonstrate rejection of expired tokens, wrong audiences, or incorrect signatures.

With the local server running, these safe rejection checks use no real session
token or cookie:

```bash
# Expected: 403, Access token is missing.
curl -i http://127.0.0.1:8787/secure

# Expected: 403, Access token is missing.
curl -i -H 'Cf-Access-Authenticated-User-Email: user@example.com' \
  http://127.0.0.1:8787/secure

# Expected: 403, Access token could not be verified.
curl -i -H 'Cf-Access-Jwt-Assertion: not-a-jwt' \
  http://127.0.0.1:8787/secure
```

The existing automated tests in `test/index.spec.js` are still the Hello World
starter tests. They request `/` and expect `Hello World!`, whereas the current
handler returns `Not found`. They do not test Access verification and are
expected to fail until updated in a separate implementation task. The existing
test command is `npm test -- --run`.

## Current limitations

- The response is plain text; the final HTML identity page is not implemented.
- Login timestamp and country information are not displayed.
- Country links and private flag retrieval are not implemented.
- The project owner reports that an R2 bucket exists separately. This Worker has
  no R2 binding in `wrangler.jsonc` and does not read R2 objects.
- This checkpoint is not described as production-ready or fully security-tested.

## Repository hygiene

Keep `wrangler.jsonc` tracked. Do not commit actual credentials, `.env` or
`.dev.vars` files containing secrets, Wrangler OAuth credential files, API or
Tunnel tokens, JWTs, session cookies, or private keys. Any intentionally tracked
example environment files must contain only non-secret examples.

Dependencies, local Wrangler state, generated logs, and build output are excluded
by `.gitignore`. Ignore rules do not remove files already tracked by Git; review
staged file paths and contents before pushing to this public repository.
