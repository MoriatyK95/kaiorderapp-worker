import { env, exports } from "cloudflare:workers";
import { exportJWK, generateKeyPair, SignJWT } from "jose";
import { afterEach, beforeAll, beforeEach, describe, expect, it, vi } from "vitest";
import worker from "../src/index.js";

const SUBJECT = "synthetic-user-id";
const EMAIL = "verified-user@example.test";
const LOGIN_SECONDS = 1_700_000_000;
const IDENTITY_PATH = "/cdn-cgi/access/get-identity";
const KEY_ID = "temporary-test-key";

let trustedKeys;
let untrustedKeys;
let publicJwk;
let config;
let outbound;
let identity;
let identityReply;
let warnings;
let caseNumber = 0;

beforeAll(async () => {
	// Private keys and signed credentials exist only in memory for this test run.
	[trustedKeys, untrustedKeys] = await Promise.all([
		generateKeyPair("RS256"),
		generateKeyPair("RS256"),
	]);
	publicJwk = {
		...(await exportJWK(trustedKeys.publicKey)),
		kid: KEY_ID,
		alg: "RS256",
		use: "sig",
	};
});

beforeEach(() => {
	// A distinct issuer resets the Worker's cached remote key set between tests.
	config = {
		ACCESS_TEAM_DOMAIN: `https://access-${++caseNumber}.example.test`,
		ACCESS_AUD: "synthetic-application-audience",
	};
	identity = {
		user_uuid: SUBJECT,
		iat: LOGIN_SECONDS,
		geo: "SG",
		email: "untrusted-identity-email@example.test",
	};
	identityReply = () => Response.json(identity);
	warnings = vi.spyOn(console, "warn").mockImplementation(() => {});

	// Only outbound HTTP is intercepted; jose performs real RSA verification.
	// No unhandled request can reach the network, including a different issuer.
	outbound = vi.fn(async (input, init) => {
		const request = new Request(input, init);
		if (request.url === `${config.ACCESS_TEAM_DOMAIN}/cdn-cgi/access/certs`) {
			return Response.json({ keys: [publicJwk] });
		}
		if (request.url === `${config.ACCESS_TEAM_DOMAIN}${IDENTITY_PATH}`) {
			return identityReply(request);
		}
		throw new Error("Unexpected outbound request in test.");
	});
	vi.stubGlobal("fetch", outbound);
});

afterEach(() => {
	try {
		const allowedUrls = [
			`${config.ACCESS_TEAM_DOMAIN}/cdn-cgi/access/certs`,
			`${config.ACCESS_TEAM_DOMAIN}${IDENTITY_PATH}`,
		];
		for (const [input] of outbound.mock.calls) {
			const url = input instanceof Request ? input.url : String(input);
			expect(allowedUrls).toContain(url);
		}
	} finally {
		vi.unstubAllGlobals();
		vi.restoreAllMocks();
	}
});

function claims(overrides = {}) {
	const now = Math.floor(Date.now() / 1000);
	return {
		iss: config.ACCESS_TEAM_DOMAIN,
		aud: config.ACCESS_AUD,
		sub: SUBJECT,
		email: EMAIL,
		type: "app",
		iat: now - 60,
		exp: now + 600,
		...overrides,
	};
}

function sign(payload = claims(), key = trustedKeys.privateKey) {
	return new SignJWT(payload)
		.setProtectedHeader({ alg: "RS256", kid: KEY_ID })
		.sign(key);
}

function request(token, path = "/secure", extraHeaders = {}) {
	const headers = new Headers(extraHeaders);
	if (token !== undefined) headers.set("Cf-Access-Jwt-Assertion", token);
	return new Request(`https://worker.example.test${path}`, { headers });
}

function identityRequests() {
	return outbound.mock.calls
		.map(([input, init]) => new Request(input, init))
		.filter((request) => new URL(request.url).pathname === IDENTITY_PATH);
}

async function expectRejection(response, message) {
	expect(response.status).toBe(403);
	expect(response.headers.get("Content-Type")).toBe("text/plain; charset=utf-8");
	expect(response.headers.get("Cache-Control")).toContain("no-store");
	if (message) expect(await response.text()).toBe(message);
	expect(identityRequests()).toHaveLength(0);
}

describe("Access authentication", () => {
	it.each([
		["without a token", {}],
		["with only an email header", { "Cf-Access-Authenticated-User-Email": EMAIL }],
		["with only a cookie", { Cookie: "CF_Authorization=synthetic-cookie" }],
		["with only an Authorization header", { Authorization: "Bearer synthetic-token" }],
	])("rejects requests %s before making outbound requests", async (_, headers) => {
		const response = await worker.fetch(request(undefined, "/secure", headers), config);
		await expectRejection(response, "Access token is missing.");
		expect(outbound).not.toHaveBeenCalled();
	});

	it("rejects a malformed token without looking up identity", async () => {
		const response = await worker.fetch(request("not-a-jwt"), config);
		await expectRejection(response, "Access token could not be verified.");
	});

	it.each([
		["an expired token", () => ({ exp: Math.floor(Date.now() / 1000) - 60 })],
		["the wrong audience", () => ({ aud: "different-application" })],
		["the wrong issuer", () => ({ iss: "https://untrusted.example.test" })],
		["a nonnumeric expiration", () => ({ exp: "tomorrow" })],
		["a future not-before claim", () => ({ nbf: Math.floor(Date.now() / 1000) + 600 })],
		["a nonnumeric not-before claim", () => ({ nbf: "yesterday" })],
		["a nonnumeric issued-at claim", () => ({ iat: "yesterday" })],
	])("rejects %s before looking up identity", async (_, overrides) => {
		const token = await sign(claims(overrides()));
		const response = await worker.fetch(request(token), config);
		await expectRejection(response, "Access token could not be verified.");
	});

	it.each(["exp", "sub", "email", "iss", "aud"])(
		"rejects a token missing the %s claim before looking up identity",
		async (claim) => {
			const payload = claims();
			delete payload[claim];
			const response = await worker.fetch(request(await sign(payload)), config);
			await expectRejection(response, "Access token could not be verified.");
		},
	);

	it("rejects a token signed by a different key", async () => {
		const token = await sign(claims(), untrustedKeys.privateKey);
		const response = await worker.fetch(request(token), config);
		await expectRejection(response, "Access token could not be verified.");
	});

	it.each([
		["a service token", { type: "service" }],
		["a missing application type", { type: undefined }],
		["a nonstring email", { email: 42 }],
		["an empty email", { email: "" }],
		["a blank email", { email: " \t " }],
		["a nonstring subject", { sub: 42 }],
		["an empty subject", { sub: "" }],
		["a blank subject", { sub: " \t " }],
	])("rejects %s before looking up identity", async (_, overrides) => {
		const response = await worker.fetch(request(await sign(claims(overrides))), config);
		await expectRejection(response);
	});

	it("fails closed when trusted signing keys cannot be retrieved", async () => {
		outbound.mockRejectedValue(new Error("Synthetic signing-key outage."));
		const response = await worker.fetch(request(await sign()), config);
		await expectRejection(response, "Access token could not be verified.");
	});

	it.each([
		{ ACCESS_TEAM_DOMAIN: "" },
		{ ACCESS_AUD: "" },
		{ ACCESS_AUD: "REPLACE_WITH_YOUR_APPLICATION_AUD" },
	])("checks incomplete configuration before any lookup: %j", async (missing) => {
		const response = await worker.fetch(request(), { ...config, ...missing });
		expect(response.status).toBe(500);
		expect(await response.text()).toBe("Access configuration is incomplete.");
		expect(response.headers.get("Cache-Control")).toContain("no-store");
		expect(outbound).not.toHaveBeenCalled();
	});
});

describe("Authenticated identity page", () => {
	it("renders only the verified email with the identity login time and country", async () => {
		const token = await sign();
		const response = await worker.fetch(
			request(token, "/secure?from=test", {
				"Cf-Access-Authenticated-User-Email": "forged-header@example.test",
			}),
			config,
		);
		const html = await response.text();

		expect(response.status).toBe(200);
		expect(response.headers.get("Content-Type")).toBe("text/html; charset=utf-8");
		expect(response.headers.get("Cache-Control")).toContain("no-store");
		expect(html).toContain(EMAIL);
		expect(html).toContain("2023-11-14T22:13:20.000Z");
		expect(html).toContain('href="/secure/SG"');
		expect(html).not.toContain(identity.email);
		expect(html).not.toContain("forged-header@example.test");
		expect(html).not.toContain(token);
		expect(html).not.toContain(SUBJECT);

		const [identityRequest] = identityRequests();
		expect(identityRequests()).toHaveLength(1);
		expect(identityRequest.url).toBe(`${config.ACCESS_TEAM_DOMAIN}${IDENTITY_PATH}`);
		expect(identityRequest.headers.get("Cookie")).toBe(`CF_Authorization=${token}`);
		expect(identityRequest.headers.get("Accept")).toBe("application/json");
		expect(identityRequest.redirect).toBe("manual");
	});

	it("escapes HTML contained in a verified email", async () => {
		const email = '<img src=x onerror="alert(1)">@example.test';
		const response = await worker.fetch(request(await sign(claims({ email }))), config);
		const html = await response.text();
		expect(response.status).toBe(200);
		expect(html).toContain("&lt;img");
		expect(html).not.toContain("<img");
		expect(html).not.toContain(email);
	});

	it.each([
		[
			"an upstream HTTP failure",
			() => new Response("Sensitive upstream detail", { status: 500 }),
			{ code: "upstream_status", status: 500, contentType: "other" },
		],
		[
			"invalid JSON",
			() => new Response("not-json", { headers: { "Content-Type": "application/json" } }),
			{ code: "invalid_json", stage: "body", status: 200, contentType: "json" },
		],
		[
			"a mismatched identity",
			() => Response.json({ ...identity, user_uuid: "other-user" }),
			{ code: "identity_mismatch", hasSubject: true, hasTimestamp: true, hasCountry: true },
		],
		[
			"a missing login timestamp",
			() => Response.json({ user_uuid: SUBJECT, geo: "SG" }),
			{ code: "invalid_timestamp", hasSubject: true, hasTimestamp: false, hasCountry: true },
		],
		[
			"a network error",
			() => { throw new Error("Sensitive network detail"); },
			{ code: "request_failed", stage: "request" },
		],
	])("returns a generic 502 after authentication for %s", async (_, reply, diagnostic) => {
		identityReply = reply;
		const token = await sign();
		const response = await worker.fetch(request(token), config);
		expect(response.status).toBe(502);
		expect(response.headers.get("Cache-Control")).toContain("no-store");
		expect(await response.text()).toBe("Unable to load login details. Please try again.");
		expect(identityRequests()).toHaveLength(1);
		expect(warnings.mock.calls).toEqual([["Access identity lookup failed", diagnostic]]);
		const logged = JSON.stringify(warnings.mock.calls);
		for (const sensitive of [
			token, EMAIL, SUBJECT, identity.email, JSON.stringify(identity),
			"Sensitive upstream detail", "Sensitive network detail", "not-json", "user_uuid",
		]) {
			expect(logged).not.toContain(sensitive);
		}
	});

	it("runs real JWT verification through the Worker service entrypoint", async () => {
		config = {
			ACCESS_TEAM_DOMAIN: env.ACCESS_TEAM_DOMAIN,
			ACCESS_AUD: env.ACCESS_AUD,
		};
		const response = await exports.default.fetch(request(await sign()));
		expect(response.status).toBe(200);
		expect(response.headers.get("Content-Type")).toBe("text/html; charset=utf-8");
		expect(response.headers.get("Cache-Control")).toContain("no-store");
		expect(await response.text()).toContain(EMAIL);
		expect(identityRequests()).toHaveLength(1);
	});
});

describe("Exact route matching", () => {
	it.each(["/", "/securely", "/secure/"])(
		"keeps %s outside the identity handler",
		async (path) => {
			const response = await worker.fetch(request(undefined, path), config);
			expect(response.status).toBe(404);
			expect(await response.text()).toBe("Not found");
			expect(response.headers.get("Cache-Control")).toContain("no-store");
			expect(outbound).not.toHaveBeenCalled();
		},
	);
});

describe("verified token country integration", () => {
	it.each([
		["signed country without identity geo", "SG", undefined, "SG"],
		["signed country over conflicting identity geo", " jp ", "SG", "JP"],
		["identity geo when signed country is malformed", "T1", " gb ", "GB"],
	])("renders %s after actual JWT verification", async (_, country, geo, expectedCountry) => {
		identity.geo = geo;
		const response = await worker.fetch(request(await sign(claims({ country }))), config);
		const html = await response.text();
		expect(response.status).toBe(200);
		expect(html).toContain(`from <a href="/secure/${expectedCountry}">${expectedCountry}</a>`);
		expect(html).toContain("2023-11-14T22:13:20.000Z");
		expect(identityRequests()).toHaveLength(1);
	});

	it("ignores country from request headers, query parameters, and current-request geolocation", async () => {
		delete identity.geo;
		const incoming = new Request(request(await sign(), "/secure?country=JP", {
			"Cf-Ipcountry": "SG",
			"Cf-Access-Country": "GB",
			"X-Country": "CA",
		}), { cf: { country: "US" } });
		expect(incoming.cf.country).toBe("US");
		const response = await worker.fetch(incoming, config);
		const html = await response.text();
		expect(response.status).toBe(200);
		expect(html).toContain("from Unknown</p>");
		expect(html).not.toContain("<a ");
		expect(identityRequests()).toHaveLength(1);
	});

	it.each([
		["expired token", () => ({ exp: Math.floor(Date.now() / 1000) - 60 })],
		["wrong audience", () => ({ aud: "another-application" })],
		["wrong issuer", () => ({ iss: "https://untrusted.example.test" })],
		["non-application token", () => ({ type: "org" })],
		["missing subject", () => ({ sub: undefined })],
	])("does not let a country claim bypass authentication for %s", async (_, invalid) => {
		const token = await sign(claims({ country: "SG", ...invalid() }));
		await expectRejection(await worker.fetch(request(token), config));
	});

	it("rejects a country-bearing token signed by an untrusted key", async () => {
		const token = await sign(claims({ country: "SG" }), untrustedKeys.privateKey);
		await expectRejection(await worker.fetch(request(token), config), "Access token could not be verified.");
	});

	it.each([undefined, "false", "TRUE", true])("keeps country debug off for environment value %j", async (setting) => {
		const info = vi.spyOn(console, "info").mockImplementation(() => {});
		const response = await worker.fetch(request(await sign(claims({ country: "SG" }))), {
			...config, DEBUG_COUNTRY: setting,
		});
		expect(response.status).toBe(200);
		expect(info).not.toHaveBeenCalled();
	});

	it("enables only sanitized country diagnostics with DEBUG_COUNTRY=true", async () => {
		const info = vi.spyOn(console, "info").mockImplementation(() => {});
		delete identity.geo;
		const token = await sign(claims({ country: "SG" }));
		const response = await worker.fetch(request(token), { ...config, DEBUG_COUNTRY: "true" });
		expect(response.status).toBe(200);
		expect(info.mock.calls).toEqual([["Access login country", {
			token: { present: true, type: "string", accepted: true },
			identity: { present: false, type: "missing", accepted: false },
			source: "token",
		}]]);
		const logged = JSON.stringify(info.mock.calls);
		for (const value of [token, EMAIL, SUBJECT, "SG", JSON.stringify(identity)]) {
			expect(logged).not.toContain(value);
		}
	});

	it("never emits country diagnostics before JWT verification", async () => {
		const info = vi.spyOn(console, "info").mockImplementation(() => {});
		const token = await sign(claims({ country: "SG" }), untrustedKeys.privateKey);
		await expectRejection(await worker.fetch(request(token), { ...config, DEBUG_COUNTRY: "true" }));
		expect(info).not.toHaveBeenCalled();
	});
});


describe("Private flag responses", () => {
  it.each([undefined, "not-a-jwt"])(
    "rejects missing or malformed credentials before reading R2: %s",
    async (token) => {
      const get = vi.fn();

      const response = await worker.fetch(
        request(token, "/secure/SG"),
        { ...config, FLAGS: { get } },
      );

      expect(response.status).toBe(403);
      expect(get).not.toHaveBeenCalled();
    },
  );

  it("returns the stored SVG after successful token verification", async () => {
    const svg = '<svg xmlns="http://www.w3.org/2000/svg"></svg>';
    const get = vi.fn().mockResolvedValue({
      body: new Response(svg).body,
    });

    const response = await worker.fetch(
      request(await sign(), "/secure/SG"),
      { ...config, FLAGS: { get } },
    );

    expect(response.status).toBe(200);
    expect(get).toHaveBeenCalledWith("flags/SG.svg");
    expect(response.headers.get("Content-Type")).toBe("image/svg+xml");
    expect(response.headers.get("Cache-Control")).toBe("private, no-store");
    expect(await response.text()).toBe(svg);
    expect(identityRequests()).toHaveLength(0);
  });

  it("returns 404 when the requested flag is absent", async () => {
    const get = vi.fn().mockResolvedValue(null);

    const response = await worker.fetch(
      request(await sign(), "/secure/US"),
      { ...config, FLAGS: { get } },
    );

    expect(response.status).toBe(404);
    expect(await response.text()).toBe("Flag not found.");
  });
});
