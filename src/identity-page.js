const IDENTITY_TIMEOUT_MS = 8000;

// Diagnostics contain only fixed codes, HTTP status, media-type categories and booleans.
export class IdentityLookupError extends Error {
  constructor(code, details = {}) {
    super(code);
    this.name = "IdentityLookupError";
    this.diagnostic = { code, ...details };
  }
}

function escapeHtml(value) {
  return String(value)
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#39;");
}

function normalizeCountryCode(value) {
  if (typeof value !== "string") return "";
  const trimmed = value.trim();
  // Validate ASCII before uppercasing so Unicode cannot expand into a code.
  if (!/^[A-Za-z]{2}$/.test(trimmed)) return "";
  const code = trimmed.toUpperCase();
  return code === "XX" || code === "ZZ" ? "" : code;
}

function countryFieldMetadata(record, key, normalized) {
  const present = Object.hasOwn(record, key);
  const value = record[key];
  const type = !present ? "missing"
    : value === null ? "null"
    : Array.isArray(value) ? "array"
    : typeof value;
  return { present, type, accepted: Boolean(normalized) };
}

function resolveLoginCountry(verifiedUser, identity, debugCountry) {
  // Both are documented login-country sources; the verified token takes priority.
  const tokenCountry = normalizeCountryCode(verifiedUser.country);
  const identityCountry = normalizeCountryCode(identity.geo);
  const country = tokenCountry || identityCountry;
  if (debugCountry === true) {
    console.info("Access login country", {
      token: countryFieldMetadata(verifiedUser, "country", tokenCountry),
      identity: countryFieldMetadata(identity, "geo", identityCountry),
      source: tokenCountry ? "token" : identityCountry ? "identity" : "unknown",
      ...(country ? {} : { reason: "no_usable_login_country" }),
    });
  }
  return country;
}

function contentTypeCategory(response) {
  const type = (response.headers.get("Content-Type") || "")
    .split(";", 1)[0].trim().toLowerCase();
  if (type === "application/json" || /^application\/[a-z0-9.+-]+\+json$/.test(type)) {
    return "json";
  }
  if (type === "text/html") return "html";
  return type ? "other" : "missing";
}

async function loadIdentity(issuer, token) {
  let endpoint;
  try {
    endpoint = new URL("/cdn-cgi/access/get-identity", issuer);
    if (endpoint.protocol !== "https:" || endpoint.username || endpoint.password) {
      throw new Error();
    }
  } catch {
    throw new IdentityLookupError("invalid_endpoint");
  }

  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), IDENTITY_TIMEOUT_MS);
  let stage = "request";
  let details = {};
  try {
    const response = await fetch(endpoint, {
      method: "GET",
      headers: {
        Cookie: `CF_Authorization=${token}`,
        Accept: "application/json",
      },
      // workerd rejects redirect:"error"; inspect 3xx without forwarding credentials.
      redirect: "manual",
      cache: "no-store",
      signal: controller.signal,
    });

    details = { status: response.status, contentType: contentTypeCategory(response) };
    if (response.status >= 300 && response.status < 400) {
      throw new IdentityLookupError("upstream_redirect", details);
    }
    if (!response.ok) {
      throw new IdentityLookupError("upstream_status", details);
    }
    if (details.contentType !== "json") {
      throw new IdentityLookupError("unexpected_content_type", details);
    }

    stage = "body";
    return await response.json();
  } catch (error) {
    if (error instanceof IdentityLookupError) throw error;
    if (controller.signal.aborted) {
      throw new IdentityLookupError("timeout", { stage, ...details });
    }
    const code = error instanceof SyntaxError ? "invalid_json" : "request_failed";
    throw new IdentityLookupError(code, { stage, ...details });
  } finally {
    clearTimeout(timer);
    // Release any unread response body on status/content-type failures.
    controller.abort();
  }
}

// Call only after JWT verification; never cache the identity between requests.
export async function createIdentityPage(issuer, token, verifiedUser, { debugCountry = false } = {}) {
  const identity = await loadIdentity(issuer, token);
  if (!identity || typeof identity !== "object" || Array.isArray(identity)) {
    throw new IdentityLookupError("invalid_identity_shape");
  }

  const fields = {
    hasSubject: Object.hasOwn(identity, "user_uuid"),
    hasTimestamp: Object.hasOwn(identity, "iat"),
    hasCountry: Object.hasOwn(identity, "geo"),
  };
  if (typeof identity.user_uuid !== "string" || identity.user_uuid !== verifiedUser.sub) {
    throw new IdentityLookupError("identity_mismatch", fields);
  }

  // Access identity.iat is recorded login time, not the JWT's issuance time.
  if (!Number.isSafeInteger(identity.iat) || identity.iat <= 0) {
    throw new IdentityLookupError("invalid_timestamp", fields);
  }
  const loginDate = new Date(identity.iat * 1000);
  if (!Number.isFinite(loginDate.getTime())) {
    throw new IdentityLookupError("invalid_timestamp", fields);
  }
  const timestamp = escapeHtml(loginDate.toISOString());

  const country = resolveLoginCountry(verifiedUser, identity, debugCountry);
  const countryHtml = country
    ? `<a href="/secure/${country}">${country}</a>`
    : "Unknown";
  const email = escapeHtml(verifiedUser.email);

  const html = `<!DOCTYPE html>
<html lang="en">
  <head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>KaiOrderApp Secure</title>
    <style>
      body { margin: 0; padding: 2rem 1rem; font: 1rem/1.6 system-ui, sans-serif; color: #172b3a; background: #f5f7f9; }
      main { max-width: 44rem; margin: 0 auto; overflow-wrap: anywhere; }
      h1 { line-height: 1.2; }
      .identity { padding: 1.25rem; background: white; border: 1px solid #d5dfe7; border-radius: .5rem; }
      a { color: #075c9e; text-underline-offset: .2em; }
      a:focus-visible { outline: 2px solid currentColor; outline-offset: 3px; }
    </style>
  </head>
  <body>
    <main>
      <h1>KaiOrderApp Secure</h1>
      <p class="identity">${email} authenticated at <time datetime="${timestamp}">${timestamp}</time> from ${countryHtml}</p>
      <p>The timestamp is the recorded login time in UTC. The country represents the login location.</p>
      <p> Select the country code to view its flag. </p>
    </main>
  </body>
</html>`;

  return new Response(html, {
    headers: {
      "Content-Type": "text/html; charset=utf-8",
      "Cache-Control": "private, no-store",
      "X-Content-Type-Options": "nosniff",
      "Referrer-Policy": "no-referrer",
      "Content-Security-Policy":
        "default-src 'none'; style-src 'unsafe-inline'; script-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'none'",
    },
  });
}
