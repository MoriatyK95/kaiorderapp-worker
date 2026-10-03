/**
 * Welcome to Cloudflare Workers! This is your first worker.
 *
 * - Run `npm run dev` in your terminal to start a development server
 * - Open a browser tab at http://localhost:8787/ to see your worker in action
 * - Run `npm run deploy` to publish your worker
 *
 * Learn more at https://developers.cloudflare.com/workers/
 */

import { createRemoteJWKSet, jwtVerify } from "jose";

// Reuse the public-key lookup between requests.
let publicKeys;
let cachedIssuer;

// A helper for returning a plain-text response.
function textResponse(message, status = 200) {
  return new Response(message, {
    status,
    headers: {
      "Content-Type": "text/plain; charset=utf-8",
      "Cache-Control": "no-store",
    },
  });
}

export default {
  async fetch(request, env) {
    const url = new URL(request.url);

    // 1. Handle only the page we are building.
    if (url.pathname !== "/secure") {
      return textResponse("Not found", 404);
    }

    // 2. Check that our trusted application is configured.
    const issuer = env.ACCESS_TEAM_DOMAIN;
    const audience = env.ACCESS_AUD;

    if (
      !issuer ||
      !audience ||
      audience === "REPLACE_WITH_YOUR_APPLICATION_AUD"
    ) {
      return textResponse("Access configuration is incomplete.", 500);
    }

    // 3. Read the signed token supplied by Cloudflare Access.
    const token = request.headers.get("Cf-Access-Jwt-Assertion");

    if (!token) {
      return textResponse("Access token is missing.", 403);
    }

    try {
      // 4. Locate the public keys for our trusted Access organisation.
      if (!publicKeys || cachedIssuer !== issuer) {
        publicKeys = createRemoteJWKSet(
          new URL(`${issuer}/cdn-cgi/access/certs`)
        );
        cachedIssuer = issuer;
      }

      // 5. Verify the signature and the required token claims.
      const { payload } = await jwtVerify(token, publicKeys, {
        issuer,
        audience,
        algorithms: ["RS256"],
        requiredClaims: ["exp", "sub", "email"],
      });

      // 6. Require an application token containing a user email.
      if (
        payload.type !== "app" ||
        typeof payload.email !== "string" ||
        payload.email.trim() === ""
      ) {
        return textResponse("A signed-in user is required.", 403);
      }

      // 7. Only use the email after verification succeeds.
      return textResponse(`Verified user: ${payload.email}`);
    } catch {
      // Never return private content when verification fails.
      // Do not print tokens or detailed verification errors.
      return textResponse("Access token could not be verified.", 403);
    }
  },
};