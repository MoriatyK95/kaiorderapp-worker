# kaiorderapp-worker

A JavaScript Cloudflare Worker that verifies a Cloudflare Access application
JWT and shows an authenticated HTML identity page at the exact `/secure` path.
The page is headed **KaiOrderApp Secure** and displays:

```text
user@example.com authenticated at 2024-01-01T00:00:00.000Z from SG
```

Those values are illustrative. Each response uses the authenticated user's
actual email and recorded login details. The country links to `/secure/SG` in
this example. Country destinations and private flag retrieval are not
implemented; those paths currently return 404.

## Request flow and identity data

1. Cloudflare Access handles login and its allow policy. This repository does
   not provision the Access application or policy.
2. The Worker reads `Cf-Access-Jwt-Assertion`. `jose` verifies the RS256 signature
   using public keys from the configured team's `/cdn-cgi/access/certs`
   endpoint, checks the expected issuer and application audience, and requires
   `exp`, `sub`, and `email`. Expiration and applicable `nbf` checks remain in
   place. If present, `iat` must be numeric; no additional maximum token age is
   configured. The payload must be an `app` token with nonblank string subject
   and email fields.
3. Only after verification, the Worker makes a server-side GET to
   `${ACCESS_TEAM_DOMAIN}/cdn-cgi/access/get-identity`, sending only the verified
   token as the `CF_Authorization` cookie. It does not forward browser cookies
   or other incoming headers. The lookup has an eight-second timeout covering
   both the request and response-body read, uses `cache: "no-store"`, and rejects
   redirects without following them. Identity data is not shared between requests.
4. The response must have a successful status, a JSON content type, and a JSON
   object. Its string `user_uuid` must match the verified JWT subject. Identity
   `iat` must be a positive, safe-integer Unix timestamp convertible to UTC.
5. The page uses **email from the verified JWT** and **login time from identity
   `iat`**. For **login country**, it first accepts a usable verified JWT
   `country`, then falls back to identity `geo`, then displays **Unknown**.
   When both sources are usable but disagree, the verified JWT takes priority.
   The identity lookup and subject/timestamp checks are required in every case.
   It does not substitute page-load time, JWT issuance time, request geolocation,
   or a default country.

The public-key lookup can be reused between requests; personalised identity
responses are never cached by the application. An email header alone is not
accepted as authentication. Neither cookies nor the `Authorization` header are
fallbacks for the incoming assertion header.

Country strings are trimmed, validated as exactly two ASCII letters, and
uppercased. The existing `XX` and `ZZ` exclusions remain; values such as `T1`,
empty strings, objects, arrays, and numbers are not accepted or coerced.
Usable codes produce relative links such as `/secure/SG`. If neither source is
usable, the page displays **Unknown** without a link. The timestamp is ISO 8601
UTC. Identity-derived text is escaped before rendering.

HTML responses send `Cache-Control: private, no-store`, `nosniff`, and
`Referrer-Policy: no-referrer`. The CSP blocks scripts, external resources,
framing, forms, and base-URL changes; inline styling is allowed for the small
responsive page. Tokens and raw identity objects are never rendered.

Cloudflare documents JWT `country` and identity `geo` as the country where the
user authenticated in its [application-token and identity documentation](https://developers.cloudflare.com/cloudflare-one/access-controls/applications/http-apps/authorization-cookie/application-token/).
The [request metadata documentation](https://developers.cloudflare.com/workers/runtime-apis/request/#incomingrequestcfproperties)
describes `request.cf.country` as the incoming request's country; it is not a
fallback for historical login location. See also [JWT verification documentation](https://developers.cloudflare.com/cloudflare-one/access-controls/applications/http-apps/authorization-cookie/validating-json/).

## Configuration

`wrangler.jsonc` remains tracked with the working deployment settings:

- Worker: `kaiorderapp-worker`; entry point: `src/index.js`.
- Compatibility date: `2026-10-03`.
- `vars.ACCESS_TEAM_DOMAIN`: the trusted Access issuer URL, including `https://`
  and without a trailing slash. It supplies the public-key and identity endpoints.
- `vars.ACCESS_AUD`: the Access application's audience identifier. The AUD and
  team domain are non-secret configuration identifiers, not credentials.
- Top-level route: `https://tunnel.kaiorderapp.com/secure*`, zone `kaiorderapp.com`.
- `workers_dev: false` and `preview_urls: false`: alternate publication endpoints
  are disabled.

`vars` provides runtime values through `env`. The top-level `routes` array
selects which requests invoke the deployed Worker; it belongs outside `vars`.
The route is broader than the handler: `/secure/`, `/securely`, and `/secure/SG`
return 404 if routed here. Query strings do not change the pathname `/secure`.

Deploying your own copy requires your own domain, Access application, and
corresponding issuer, AUD, and route/zone settings. Access policies, Tunnel, and
DNS are managed separately. This Worker has no R2 binding or object-retrieval code.

## Local development and checks

Use Node.js 22 LTS or 24+ and npm. Install from the existing lockfile, then start
Wrangler locally:

```bash
npm ci
npm run dev -- --ip 127.0.0.1 --port 8787
```

Local requests do not automatically pass through Access login. These rejection
checks use no real token or session cookie:

```bash
# 403: Access token is missing.
curl -i http://127.0.0.1:8787/secure
curl -i -H 'Cf-Access-Authenticated-User-Email: user@example.com' \
  http://127.0.0.1:8787/secure

# 403: Access token could not be verified.
curl -i -H 'Cf-Access-Jwt-Assertion: not-a-jwt' \
  http://127.0.0.1:8787/secure
```

Run the tests and build check:

```bash
npm test -- --run
npx wrangler deploy --dry-run --config wrangler.jsonc
```

Tests use synthetic identities and temporary signing keys with mocked network
responses. They cover JWT rejection, verification before lookup, safe HTML,
recorded login time, country precedence/fallback/normalisation, unknown values,
injection rejection, opt-in sanitised diagnostics, response validation, timeouts,
redirect rejection, and private/no-store responses. Native Worker
request construction is exercised so mocked fetches do not hide unsupported
request options. These tests and a deployment dry run do not prove a live Access
session succeeds.

The owner previously reported missing-token, email-only, and malformed-token
rejection checks. After the country fix, the owner confirmed the live HTML page
shows the country link and retains the recorded timestamp. The displayed result
does not establish which live source supplied the country or either field's type.

## Errors and safe troubleshooting

| Condition | Response |
| --- | --- |
| Other pathname | 404, `Not found` |
| Missing issuer/audience, or placeholder audience | 500, `Access configuration is incomplete.` |
| Missing assertion header | 403, `Access token is missing.` |
| Failed JWT verification | 403, `Access token could not be verified.` |
| Verified token lacks application/user fields | 403, `A signed-in user is required.` |
| Identity retrieval, validation, or rendering fails | 502, `Unable to load login details. Please try again.` |

Error responses remain generic and use private/no-store caching. Identity-service
failures are kept separate from authentication rejection.

The previous helper used `redirect: "error"`. In the installed Workers runtime,
that option throws before sending the identity request, even though the current
Request documentation lists it. This failure was reproduced locally with
synthetic data; `redirect: "manual"` plus explicit rejection of 3xx responses
fixes that reproduced failure without forwarding the credential. Verify changes
to the authenticated page using the browser check below.

Identity errors log only the fixed message `Access identity lookup failed` and
sanitised metadata. Codes distinguish `invalid_endpoint`, `request_failed`,
`timeout`, `upstream_redirect`, `upstream_status`, `unexpected_content_type`,
`invalid_json`, `invalid_identity_shape`, `identity_mismatch`, `invalid_timestamp`,
and unexpected `render_failed` errors. Where available, logs include HTTP status,
a content-type category (`json`, `html`, `other`, or `missing`), request/body stage,
and booleans indicating whether identity fields exist. Logs omit tokens,
cookies, email addresses, user IDs, response bodies, and raw errors or objects.

A non-JSON response or upstream redirect should be investigated as an upstream
response problem. A mismatch or missing timestamp must not be worked around by
removing identity checks or inventing values. Share only the sanitised diagnostic
fields when troubleshooting, never live tokens or cookies.

The previous country renderer inspected only identity `geo`, even though it
received the full verified JWT. It discarded any usable JWT `country` when
`geo` was unusable. Synthetic tests reproduce this defect and confirm the
token-first resolver fixes it. The actual live field values remain unconfirmed;
the page must still show **Unknown** when neither source is usable.

Country diagnostics are disabled by default. For a controlled live check,
explicitly enable the `DEBUG_COUNTRY` runtime variable as the string `true`:

```bash
npx wrangler deploy --config wrangler.jsonc --var DEBUG_COUNTRY:true
npx wrangler tail kaiorderapp-worker --format pretty
```

In another terminal, open `/secure` using the browser command below and complete
Access login. The `Access login country` log records only each field's presence,
type and acceptance, plus `source` (`token`, `identity`, or `unknown`). An unknown
result includes `reason: "no_usable_login_country"`. It never logs country values,
credentials or user details, and runs only after JWT and identity validation.
Share only that sanitised diagnostic entry if further investigation is needed.
Turn the flag off after the check, without changing the tracked configuration:

```bash
npx wrangler deploy --config wrangler.jsonc --var DEBUG_COUNTRY:false
```

## Manual deployment and browser verification

Authenticate and check the target Cloudflare account, then publish deliberately:

```bash
npx wrangler login
npx wrangler whoami
npx wrangler deploy --dry-run --config wrangler.jsonc
npx wrangler deploy --config wrangler.jsonc
```

To observe the application's sanitised diagnostic messages:

```bash
npx wrangler tail kaiorderapp-worker --format pretty
```

In another terminal, open the protected page (Linux):

```bash
xdg-open 'https://tunnel.kaiorderapp.com/secure'
```

Complete the permitted Access login. Confirm HTTP 200, the heading, your own
email, a plausible recorded UTC login time, and the login country or **Unknown**.
Use the optional diagnostic check above to identify the selected source; these
logs deliberately do not reveal the values of either field.
Reload without starting a new login and check that the page is not displaying a
fresh page-load timestamp. A valid country should link to `/secure/<CODE>`; that
destination intentionally still returns 404. Inspect the response's no-store
and security headers. If a 502 remains, use its sanitised diagnostic code to
identify the next failure stage; do not copy session credentials out of the browser.

GitHub pushes are separate from manual Wrangler deployments. This repository
does not define a deployment workflow. The HTML update requires the manual
browser verification above; it is not a production-readiness or comprehensive
security-testing claim.

## Repository hygiene

Keep credentials, OAuth files, API/Tunnel tokens, session cookies, JWTs, private
keys, and private identity responses out of Git. `.env*`, `.dev.vars*`, local
Wrangler state, dependencies, generated logs, and build output are ignored;
intentionally tracked example files must contain only non-secret examples.
Ignore rules do not remove already tracked files, so review staged contents.
