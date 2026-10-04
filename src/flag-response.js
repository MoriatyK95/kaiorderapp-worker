// Call only after the caller has verified the Access user token.
export async function createFlagResponse(country, env, method = "GET") {
  // Keep error responses private too.
  function errorResponse(message, status, extraHeaders = {}) {
    return new Response(method === "HEAD" ? null : message, {
      status,
      headers: {
        "Content-Type": "text/plain; charset=utf-8",
        "Cache-Control": "private, no-store",
        "X-Content-Type-Options": "nosniff",
        ...extraHeaders,
      },
    });
  }

  // This endpoint reads flags; it never uploads or deletes them.
  if (method !== "GET" && method !== "HEAD") {
    return errorResponse("Method not allowed.", 405, {
      Allow: "GET, HEAD",
    });
  }

  // Accept only the expected two-letter, uppercase path value.
  if (
    !/^[A-Z]{2}$/.test(country) ||
    country === "XX" ||
    country === "ZZ"
  ) {
    return errorResponse("Flag not found.", 404);
  }

  if (!env.FLAGS) {
    return errorResponse("Flag storage is not configured.", 500);
  }

  try {
    // Example: SG becomes flags/SG.svg.
    const key = `flags/${country}.svg`;

    // HEAD checks the object without downloading its body.
    const object =
      method === "HEAD"
        ? await env.FLAGS.head(key)
        : await env.FLAGS.get(key);

    if (object === null) {
      return errorResponse("Flag not found.", 404);
    }

    // Return the image itself, not an HTML page or a public R2 URL.
    return new Response(method === "HEAD" ? null : object.body, {
      headers: {
        "Content-Type": "image/svg+xml",
        "Cache-Control": "private, no-store",
        "X-Content-Type-Options": "nosniff",
        "Referrer-Policy": "no-referrer",
        "Content-Security-Policy":
          "default-src 'none'; style-src 'unsafe-inline'; sandbox",
      },
    });
  } catch {
    // Do not print credentials, request headers, or raw error objects.
    console.warn("R2 flag read failed.");

    return errorResponse(
      "Unable to load the flag. Please try again.",
      502,
    );
  }
}