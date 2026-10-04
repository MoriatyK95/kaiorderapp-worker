# kaiorderapp-worker

A JavaScript Cloudflare Worker that verifies a Cloudflare Access application
JWT, shows an authenticated HTML identity page at the exact `/secure` path,
and serves country flags from private R2 storage at `/secure/<COUNTRY>`.
The page is headed **KaiOrderApp Secure** and displays:

```text
user@example.com authenticated at 2024-01-01T00:00:00.000Z from SG
```

Those values are illustrative. Each response uses the authenticated user's
actual email and recorded login details. The country links to `/secure/SG` in
this example, which returns the Singapore SVG when that object exists in R2.
The page invites the user to select the country code to view its flag.

## Request flow and identity data

1. Cloudflare Access handles login and authorisation for the protected routes.
   This repository does not provision the Access application or policy.
2. The Worker reads `Cf-Access-Jwt-Assertion`. `jose` verifies the RS256 signature
   using public keys from the configured team's `/cdn-cgi/access/certs`
   endpoint, checks the expected issuer and application audience, and requires
   `exp`, `sub`, and `email`. Expiration and applicable `nbf` checks remain in
   place. If present, `iat` must be numeric; no additional maximum token age is
   configured. The payload must be an `app` token with nonblank string subject
   and email fields. These checks run before returning identity information or
   reading a flag from R2.
3. For `/secure`, only after verification, the Worker makes a server-side GET to
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
   The identity lookup and subject/timestamp checks are required for every
   identity-page response. Flag requests do not perform this identity lookup.
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

## Private flag responses

After Access token verification, `GET /secure/<COUNTRY>` reads
`flags/<COUNTRY>.svg` through the `FLAGS` binding. For example, `/secure/SG`
reads `flags/SG.svg` in `kaiorderapp-flags`. Paths require exactly two uppercase
ASCII letters; `XX` and `ZZ` are rejected. The requested country does not have
to match the authenticated user's login country.

The bucket remains private. The Worker returns the stored SVG body directly,
without redirecting visitors to a public R2 URL. A successful response is HTTP
200 with `Content-Type: image/svg+xml`, `Cache-Control: private, no-store`,
`X-Content-Type-Options: nosniff`, and `Referrer-Policy: no-referrer`. Its CSP is
`default-src 'none'; style-src 'unsafe-inline'; sandbox`.

`HEAD` is supported: the handler calls `FLAGS.head()` and returns the same
success headers without downloading or returning the SVG body. Errors from
the flag handler also have no body for HEAD. Other methods return 405 with
`Allow: GET, HEAD`, after authentication. Missing objects, invalid paths, and
storage failures are described in the error table below.

## Configuration

`wrangler.jsonc` remains tracked with the working deployment settings:

- Worker: `kaiorderapp-worker`; entry point: `src/index.js`.
- Compatibility date: `2026-10-03`.
- `vars.ACCESS_TEAM_DOMAIN`: the trusted Access issuer URL, including `https://`
  and without a trailing slash. It supplies the public-key and identity endpoints.
- `vars.ACCESS_AUD`: the Access application's audience identifier. The AUD and
  team domain are non-secret configuration identifiers, not credentials.
- Top-level route: `https://tunnel.kaiorderapp.com/secure*`, zone `kaiorderapp.com`.
- Top-level `r2_buckets`: binding `FLAGS` targets `kaiorderapp-flags`.
- `workers_dev: false` and `preview_urls: false`: alternate publication endpoints
  are disabled.

`vars` provides runtime values through `env`. Both `routes` and `r2_buckets`
belong at the top level, outside `vars`. The route selects which requests invoke
the deployed Worker and is broader than its handlers: `/secure/`, `/securely`,
`/secure/sg`, and `/secure/SG/` return 404 if they reach the Worker. Query strings
do not affect pathname matching or the R2 object key.

Deploying your own copy requires your own domain, Access application, and
corresponding issuer, AUD, route/zone settings, and private R2 bucket binding.
Access policies, Tunnel, DNS, and bucket settings are managed separately.

## Flag assets and uploads

The existing development dependency `flag-icons` supplies SVG artwork. Installed
version 7.5.0 has lowercase source filenames in `node_modules/flag-icons/flags/4x3/`
and `node_modules/flag-icons/flags/1x1/`. R2 keys use uppercase country codes,
such as `flags/SG.svg`. The source image's aspect ratio does not change the key.

No upload script is checked into this repository. Use the installed Wrangler
tooling for manual uploads, choosing the intended source SVG. For example, to
write the 4:3 Singapore asset to the remote bucket:

```bash
npx wrangler r2 object put kaiorderapp-flags/flags/SG.svg \
  --file node_modules/flag-icons/flags/4x3/sg.svg \
  --content-type image/svg+xml \
  --remote \
  --config wrangler.jsonc
```

This command creates or replaces that object; it is a manual maintenance step,
not part of tests, Git pushes, or the Worker deployment. The example does not
establish which aspect ratio is already stored. R2 objects are managed separately
from Git source; installing the dependency or pushing this repository does not
upload them. Keep bucket public access disabled.

Artwork attribution: [flag-icons](https://github.com/lipis/flag-icons),
Copyright (c) 2013 Panayiotis Lipiridis, MIT licence. The full notice is included
in `node_modules/flag-icons/LICENSE`; preserve its copyright and permission
notice when copying or redistributing the artwork.

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
request options. Flag tests cover missing/malformed authentication before R2
reads, a successful SVG response with its content type and no-store header,
and a missing-object 404. They use mocked R2 reads. HEAD and the remaining flag
error branches are implemented but are not covered by the existing flag tests.
These tests and a deployment dry run do not prove live R2 access or authentication.

## Owner-reported live verification

The project owner manually reported these results; they were not live checks
performed as part of this documentation cleanup:

- An approved Access login displays the HTML identity sentence with a clickable
  SG country code, and following it displays the Singapore flag.
- The authenticated flag response is HTTP 200 with `Content-Type: image/svg+xml`
  and `Cache-Control: private, no-store`.
- An anonymous GET to `/secure/SG` returns HTTP 302 to Access login. An anonymous
  HEAD request also returns an Access login redirect.
- Additional country assets have been uploaded to the remote R2 bucket.

These observations do not establish coverage of every country or security
scenario, or the contents of every remote object. They do not certify the
application as production-ready. Locally edited page wording appears live only
after the corresponding Worker version is deployed.

## Errors and safe troubleshooting

| Condition | Response |
| --- | --- |
| Unmatched pathname, including lowercase or malformed flag paths | 404, `Not found` |
| Missing issuer/audience, or placeholder audience | 500, `Access configuration is incomplete.` |
| Missing assertion header | 403, `Access token is missing.` |
| Failed JWT verification | 403, `Access token could not be verified.` |
| Verified token lacks application/user fields | 403, `A signed-in user is required.` |
| Identity retrieval, validation, or rendering fails | 502, `Unable to load login details. Please try again.` |
| Authenticated flag request with a method other than GET/HEAD | 405, `Method not allowed.`, with `Allow: GET, HEAD` |
| Authenticated flag request for `XX`, `ZZ`, or a missing object | 404, `Flag not found.` |
| Authenticated flag request without a `FLAGS` binding | 500, `Flag storage is not configured.` |
| R2 read throws | 502, `Unable to load the flag. Please try again.` |

These are Worker responses; Cloudflare Access can redirect a request to login
before it reaches the Worker. Worker errors use `Content-Type: text/plain;
charset=utf-8`, `Cache-Control: private, no-store`, and `nosniff`. Identity-service
and R2 failures remain separate from authentication rejection. An R2 exception
logs only the fixed message `R2 flag read failed.`.

The identity lookup uses `redirect: "manual"` and explicitly rejects 3xx
responses so the credential is not forwarded to a redirect destination.

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

The country resolver prefers a usable verified JWT `country`, then identity
`geo`. The page still shows **Unknown** when neither source is usable.

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
fresh page-load timestamp. Follow the country link: an existing flag should
return HTTP 200 and display as SVG, while a missing object returns 404. Inspect
the content type, no-store header, and security headers. If a 502 occurs, use
the sanitised log message to distinguish identity and R2 failures; do not copy
session credentials out of the browser.

This repository does not define a deployment workflow. Publishing source to
GitHub is separate from the manual Wrangler deployment above. Check any
externally configured build integration before pushing; a dry run only builds
the Worker and does not publish it or verify remote bucket contents.

## Repository hygiene

Keep credentials, OAuth files, API/Tunnel tokens, session cookies, JWTs, private
keys, and private identity responses out of Git. `.env*`, `.dev.vars*`, local
Wrangler state, dependencies, generated logs, and build output are ignored;
intentionally tracked example files must contain only non-secret examples.
Ignore rules do not remove already tracked files, so review staged contents.
