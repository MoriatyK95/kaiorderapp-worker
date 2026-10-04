import { afterEach, describe, expect, it, vi } from "vitest";
import { createIdentityPage, IdentityLookupError } from "../src/identity-page.js";

const ISSUER = "https://access.example.test";
const TOKEN = "synthetic-token-not-a-real-jwt";
const USER = { sub: "synthetic-user", email: "user@example.test", iat: 1800000000 };
const LOGIN_TIME = 1700000000;

function identity(overrides = {}) {
	return { user_uuid: USER.sub, iat: LOGIN_TIME, geo: "SG", ...overrides };
}

function jsonResponse(value, init = {}) {
	return new Response(JSON.stringify(value), {
		headers: { "Content-Type": "application/json" },
		...init,
	});
}

// Construct a real workerd Request before responding. A plain fetch mock would
// hide unsupported options such as redirect: "error", the original 502 cause.
function stubIdentityFetch(responder = () => jsonResponse(identity())) {
	const requests = [];
	const fetchMock = vi.fn(async (url, options) => {
		const request = new Request(url, options);
		requests.push(request);
		return responder(request);
	});
	vi.stubGlobal("fetch", fetchMock);
	return { requests, fetchMock };
}

async function lookupFailure(expectedCode, options = {}) {
	const { issuer = ISSUER, token = TOKEN, user = USER } = options;
	let caught;
	try {
		await createIdentityPage(issuer, token, user);
	} catch (error) {
		caught = error;
	}
	expect(caught).toBeInstanceOf(IdentityLookupError);
	expect(caught.diagnostic.code).toBe(expectedCode);
	return caught;
}

afterEach(() => {
	vi.useRealTimers();
	vi.unstubAllGlobals();
	vi.restoreAllMocks();
});

describe("authenticated identity page", () => {
	it("uses the fixed identity endpoint and fetch options accepted by workerd", async () => {
		const { requests, fetchMock } = stubIdentityFetch();
		const response = await createIdentityPage(ISSUER, TOKEN, USER);
		expect(response.status).toBe(200);
		expect(fetchMock).toHaveBeenCalledTimes(1);
		expect(requests[0].url).toBe(`${ISSUER}/cdn-cgi/access/get-identity`);
		expect(requests[0].method).toBe("GET");
		expect(requests[0].redirect).toBe("manual");
		expect(requests[0].cache).toBe("no-store");
		expect(requests[0].headers.get("Cookie")).toBe(`CF_Authorization=${TOKEN}`);
		expect(requests[0].headers.get("Accept")).toBe("application/json");
		expect(requests[0].headers.get("Authorization")).toBeNull();
		expect(requests[0].signal).toBeInstanceOf(AbortSignal);
	});

	it("shows verified email, recorded login time in UTC, and a normalized country link", async () => {
		vi.useFakeTimers();
		vi.setSystemTime(new Date("2040-01-01T00:00:00.000Z"));
		stubIdentityFetch(() => jsonResponse(identity({
			geo: " sg ",
			email: "untrusted-identity-email@example.test",
		})));
		const response = await createIdentityPage(ISSUER, TOKEN, USER);
		const html = await response.text();
		expect(html).toContain(`${USER.email} authenticated at`);
		expect(html).toContain('<time datetime="2023-11-14T22:13:20.000Z">2023-11-14T22:13:20.000Z</time>');
		expect(html).toContain('from <a href="/secure/SG">SG</a>');
		expect(html).toContain("recorded login time in UTC");
		expect(html).toContain("login location");
		expect(html).not.toContain("2040-01-01");
		expect(html).not.toContain(new Date(USER.iat * 1000).toISOString());
		expect(html).not.toContain("untrusted-identity-email");
		expect(vi.getTimerCount()).toBe(0);
	});

	it("escapes user text and does not embed credentials or unrelated identity fields", async () => {
		const email = `<img src=x onerror=alert(1)> & "double" 'single'`;
		stubIdentityFetch(() => jsonResponse(identity({
			ip: "192.0.2.123",
			account_id: "synthetic-private-account",
			identity_nonce: "synthetic-private-nonce",
		})));
		const response = await createIdentityPage(ISSUER, TOKEN, { ...USER, email });
		const html = await response.text();
		expect(html).toContain("&lt;img src=x onerror=alert(1)&gt; &amp; &quot;double&quot; &#39;single&#39;");
		expect(html).not.toContain("<img");
		expect(html).not.toContain("<script");
		for (const privateValue of [TOKEN, USER.sub, "192.0.2.123", "synthetic-private-account", "synthetic-private-nonce", "CF_Authorization"]) {
			expect(html).not.toContain(privateValue);
		}
	});

	it("sets non-caching, content-type, referrer and script restrictions", async () => {
		stubIdentityFetch();
		const { headers } = await createIdentityPage(ISSUER, TOKEN, USER);
		expect(headers.get("Content-Type")).toBe("text/html; charset=utf-8");
		expect(headers.get("Cache-Control")).toBe("private, no-store");
		expect(headers.get("X-Content-Type-Options")).toBe("nosniff");
		expect(headers.get("Referrer-Policy")).toBe("no-referrer");
		for (const directive of ["default-src 'none'", "script-src 'none'", "base-uri 'none'", "frame-ancestors 'none'", "form-action 'none'"]) {
			expect(headers.get("Content-Security-Policy")).toContain(directive);
		}
		expect(headers.get("Content-Security-Policy")).toContain("style-src 'unsafe-inline'");
		expect(headers.get("Set-Cookie")).toBeNull();
	});

	it.each([
		undefined, null, "", "   ", "XX", "zz", "Singapore", "SG/US", "ß", "ＳＧ", "🇸🇬",
		'\"><script>alert(1)</script>', "1A", "123", { code: "SG" }, ["SG"],
	])("renders unknown country without a link for %j", async (geo) => {
		stubIdentityFetch(() => jsonResponse(identity({ geo })));
		const html = await (await createIdentityPage(ISSUER, TOKEN, USER)).text();
		expect(html).toContain("from Unknown</p>");
		expect(html).not.toContain("<a ");
		expect(html).not.toContain("<script");
	});

	it("fetches identity for each request and never mixes two users' details", async () => {
		const otherUser = { sub: "another-synthetic-user", email: "other@example.test" };
		let firstUserCalls = 0;
		const { fetchMock } = stubIdentityFetch((request) => {
			if (request.headers.get("Cookie") === "CF_Authorization=second-synthetic-token") {
				return jsonResponse({ user_uuid: otherUser.sub, iat: LOGIN_TIME + 60, geo: "GB" });
			}
			firstUserCalls += 1;
			return jsonResponse(identity({ geo: firstUserCalls === 1 ? "SG" : "JP" }));
		});
		const [first, second] = await Promise.all([
			createIdentityPage(ISSUER, TOKEN, USER),
			createIdentityPage(ISSUER, "second-synthetic-token", otherUser),
		]);
		const firstHtml = await first.text();
		const secondHtml = await second.text();
		const refreshedHtml = await (await createIdentityPage(ISSUER, TOKEN, USER)).text();
		expect(firstHtml).toContain(USER.email);
		expect(firstHtml).toContain('href="/secure/SG"');
		expect(firstHtml).not.toContain(otherUser.email);
		expect(secondHtml).toContain(otherUser.email);
		expect(secondHtml).toContain('href="/secure/GB"');
		expect(secondHtml).not.toContain(`${USER.email} authenticated`);
		expect(refreshedHtml).toContain('href="/secure/JP"');
		expect(fetchMock).toHaveBeenCalledTimes(3);
	});
});

describe("identity lookup failures", () => {
	it.each(["http://access.example.test", "not a URL", "https://user:password@access.example.test"])(
		"rejects unsafe or invalid issuer %s before sending credentials", async (issuer) => {
			const { fetchMock } = stubIdentityFetch();
			await lookupFailure("invalid_endpoint", { issuer });
			expect(fetchMock).not.toHaveBeenCalled();
		},
	);

	it.each([null, [], [identity()], "identity", 0, false])("rejects invalid identity shape %j", async (value) => {
		stubIdentityFetch(() => jsonResponse(value));
		await lookupFailure("invalid_identity_shape");
	});

	it.each([undefined, null, 123, "", "different-user"])("rejects missing or mismatched subject %j", async (user_uuid) => {
		stubIdentityFetch(() => jsonResponse(identity({ user_uuid })));
		const error = await lookupFailure("identity_mismatch");
		expect(error.diagnostic).toEqual({
			code: "identity_mismatch", hasSubject: user_uuid !== undefined,
			hasTimestamp: true, hasCountry: true,
		});
	});

	it.each([undefined, null, "1700000000", 0, -1, 1.5, 8640000000001, Number.MAX_SAFE_INTEGER + 1])(
		"rejects missing, invalid, or out-of-range login timestamp %j", async (iat) => {
			stubIdentityFetch(() => jsonResponse(identity({ iat })));
			const error = await lookupFailure("invalid_timestamp");
			expect(error.diagnostic).toEqual({
				code: "invalid_timestamp", hasSubject: true,
				hasTimestamp: iat !== undefined, hasCountry: true,
			});
		},
	);

	it.each([301, 302, 307, 308])("rejects HTTP %i without following its Location", async (status) => {
		const { fetchMock } = stubIdentityFetch(() => new Response(null, {
			status,
			headers: { Location: "https://untrusted.example.test/token-receiver" },
		}));
		const error = await lookupFailure("upstream_redirect");
		expect(error.diagnostic).toEqual({ code: "upstream_redirect", status, contentType: "missing" });
		expect(fetchMock).toHaveBeenCalledTimes(1);
		expect(JSON.stringify(error.diagnostic)).not.toContain("untrusted");
	});

	it.each([400, 401, 403, 429, 500, 503])("rejects unsuccessful HTTP %i with metadata only", async (status) => {
		stubIdentityFetch(() => new Response(`private upstream body ${TOKEN}`, {
			status, headers: { "Content-Type": "text/html" },
		}));
		const error = await lookupFailure("upstream_status");
		expect(error.diagnostic).toEqual({ code: "upstream_status", status, contentType: "html" });
		expect(error.message).toBe("upstream_status");
		expect(JSON.stringify(error)).not.toContain(TOKEN);
	});

	it.each([
		[undefined, "missing"], ["text/html; private=synthetic-token", "html"], ["text/plain", "other"],
	])("rejects content type %j and records only its category", async (contentType, category) => {
		stubIdentityFetch(() => new Response(new TextEncoder().encode(JSON.stringify(identity())), {
			headers: contentType ? { "Content-Type": contentType } : {},
		}));
		const error = await lookupFailure("unexpected_content_type");
		expect(error.diagnostic).toEqual({ code: "unexpected_content_type", status: 200, contentType: category });
		expect(JSON.stringify(error)).not.toContain("private=");
	});

	it.each(["application/json; charset=utf-8", "Application/JSON", "application/identity+json"])(
		"accepts JSON media type %s", async (contentType) => {
			stubIdentityFetch(() => jsonResponse(identity(), { headers: { "Content-Type": contentType } }));
			expect((await createIdentityPage(ISSUER, TOKEN, USER)).status).toBe(200);
		},
	);

	it("rejects invalid JSON without exposing the body", async () => {
		stubIdentityFetch(() => new Response(`invalid JSON: ${TOKEN}`, { headers: { "Content-Type": "application/json" } }));
		const error = await lookupFailure("invalid_json");
		expect(error.diagnostic).toEqual({ code: "invalid_json", stage: "body", status: 200, contentType: "json" });
		expect(JSON.stringify(error)).not.toContain(TOKEN);
	});

	it("sanitizes network errors and clears its timer", async () => {
		vi.useFakeTimers();
		stubIdentityFetch(() => { throw new Error(`private network message ${TOKEN} ${USER.email}`); });
		const error = await lookupFailure("request_failed");
		expect(error.diagnostic).toEqual({ code: "request_failed", stage: "request" });
		expect(JSON.stringify(error)).not.toContain(TOKEN);
		expect(JSON.stringify(error)).not.toContain(USER.email);
		expect(vi.getTimerCount()).toBe(0);
	});

	it("aborts an unresolved request at eight seconds and clears its timer", async () => {
		vi.useFakeTimers();
		let signal;
		stubIdentityFetch((request) => {
			signal = request.signal;
			return new Promise((resolve, reject) => signal.addEventListener("abort", () => reject(signal.reason), { once: true }));
		});
		const failure = lookupFailure("timeout");
		await vi.advanceTimersByTimeAsync(7999);
		expect(signal.aborted).toBe(false);
		await vi.advanceTimersByTimeAsync(1);
		expect((await failure).diagnostic).toEqual({ code: "timeout", stage: "request" });
		expect(signal.aborted).toBe(true);
		expect(vi.getTimerCount()).toBe(0);
	});

	it("keeps the deadline active while a JSON response body is stalled", async () => {
		vi.useFakeTimers();
		let signal;
		stubIdentityFetch((request) => {
			signal = request.signal;
			return new Response(new ReadableStream({
				start(controller) {
					controller.enqueue(new TextEncoder().encode('{"user_uuid":'));
					signal.addEventListener("abort", () => controller.error(signal.reason), { once: true });
				},
			}), { headers: { "Content-Type": "application/json" } });
		});
		const failure = lookupFailure("timeout");
		await vi.advanceTimersByTimeAsync(7999);
		expect(signal.aborted).toBe(false);
		await vi.advanceTimersByTimeAsync(1);
		expect((await failure).diagnostic).toEqual({ code: "timeout", stage: "body", status: 200, contentType: "json" });
		expect(signal.aborted).toBe(true);
		expect(vi.getTimerCount()).toBe(0);
	});
});

describe("verified login country selection", () => {
	it.each([
		["token country with absent identity geo", "SG", undefined, "SG"],
		["token wins conflicting identity geo", "JP", "SG", "JP"],
		["token whitespace and lowercase", " \tgb\n", "SG", "GB"],
		["missing token falls back to identity geo", undefined, " sg ", "SG"],
		["invalid token falls back to identity geo", "T1", " jp ", "JP"],
	])("uses %s", async (_, country, geo, expectedCountry) => {
		stubIdentityFetch(() => jsonResponse(identity({ geo })));
		const response = await createIdentityPage(ISSUER, TOKEN, { ...USER, country });
		const html = await response.text();
		expect(response.status).toBe(200);
		expect(html).toContain(`from <a href="/secure/${expectedCountry}">${expectedCountry}</a>`);
		expect(html).toContain('<time datetime="2023-11-14T22:13:20.000Z">');
		expect(html).not.toContain(new Date(USER.iat * 1000).toISOString());
		if (geo === "SG" && expectedCountry !== "SG") {
			expect(html).not.toContain('href="/secure/SG"');
		}
	});

	it.each([
		undefined, null, "", " \t ", "XX", "zz", "T1", "USA", "SG/US", "ß", "ıg", "ＳＧ",
		'<script>alert(1)</script>', 42, { code: "SG" }, ["SG"],
	])("does not accept malformed token country %j instead of valid identity geo", async (country) => {
		stubIdentityFetch(() => jsonResponse(identity({ geo: "CA" })));
		const html = await (await createIdentityPage(ISSUER, TOKEN, { ...USER, country })).text();
		expect(html).toContain('from <a href="/secure/CA">CA</a>');
		expect(html).not.toContain("<script");
	});

	it.each([
		[undefined, undefined], ["XX", "ZZ"], ["T1", "T1"], [42, 42],
		[{ code: "SG" }, ["SG"]], ["ß", "ıg"], ["SG/US", '<script>alert(1)</script>'],
	])("shows Unknown when token %j and identity geo %j are both unusable", async (country, geo) => {
		stubIdentityFetch(() => jsonResponse(identity({ geo })));
		const html = await (await createIdentityPage(ISSUER, TOKEN, { ...USER, country })).text();
		expect(html).toContain("from Unknown</p>");
		expect(html).not.toContain("<a ");
		expect(html).not.toContain("<script");
	});

	it.each([
		["identity_mismatch", { user_uuid: "different-synthetic-user" }],
		["invalid_timestamp", { iat: undefined }],
		["invalid_timestamp", { iat: "1700000000" }],
	])("still requires %s validation when the verified token has a valid country", async (code, invalid) => {
		const { fetchMock } = stubIdentityFetch(() => jsonResponse(identity(invalid)));
		await lookupFailure(code, { user: { ...USER, country: "SG" } });
		expect(fetchMock).toHaveBeenCalledTimes(1);
	});
});

describe("opt-in country diagnostics", () => {
	it.each([undefined, false, "true", 1])("does not log country diagnostics for option %j", async (debugCountry) => {
		const info = vi.spyOn(console, "info").mockImplementation(() => {});
		stubIdentityFetch();
		await createIdentityPage(ISSUER, TOKEN, { ...USER, country: "SG" },
			debugCountry === undefined ? undefined : { debugCountry });
		expect(info).not.toHaveBeenCalled();
	});

	it.each([
		[
			"token source with absent identity geo", { country: "SG" }, undefined,
			{ token: { present: true, type: "string", accepted: true }, identity: { present: false, type: "missing", accepted: false }, source: "token" },
		],
		[
			"token source when both values are accepted", { country: "SG" }, "JP",
			{ token: { present: true, type: "string", accepted: true }, identity: { present: true, type: "string", accepted: true }, source: "token" },
		],
		[
			"identity fallback", { country: "T1" }, " sg ",
			{ token: { present: true, type: "string", accepted: false }, identity: { present: true, type: "string", accepted: true }, source: "identity" },
		],
		[
			"missing fields", {}, undefined,
			{ token: { present: false, type: "missing", accepted: false }, identity: { present: false, type: "missing", accepted: false }, source: "unknown", reason: "no_usable_login_country" },
		],
		[
			"explicit undefined token field", { country: undefined }, undefined,
			{ token: { present: true, type: "undefined", accepted: false }, identity: { present: false, type: "missing", accepted: false }, source: "unknown", reason: "no_usable_login_country" },
		],
		[
			"array and object fields", { country: ["SG"] }, { country: "JP" },
			{ token: { present: true, type: "array", accepted: false }, identity: { present: true, type: "object", accepted: false }, source: "unknown", reason: "no_usable_login_country" },
		],
		[
			"null and number fields", { country: null }, 42,
			{ token: { present: true, type: "null", accepted: false }, identity: { present: true, type: "number", accepted: false }, source: "unknown", reason: "no_usable_login_country" },
		],
	])("logs only sanitized metadata for %s", async (_, tokenFields, geo, diagnostic) => {
		const info = vi.spyOn(console, "info").mockImplementation(() => {});
		const user = { ...USER, ...tokenFields };
		const details = identity({ geo, ip: "192.0.2.23", account_id: "synthetic-private-account" });
		stubIdentityFetch(() => jsonResponse(details));
		await createIdentityPage(ISSUER, TOKEN, user, { debugCountry: true });
		expect(info.mock.calls).toEqual([["Access login country", diagnostic]]);
		const logged = JSON.stringify(info.mock.calls);
		for (const value of [TOKEN, USER.email, USER.sub, "SG", "JP", "192.0.2.23", "synthetic-private-account", JSON.stringify(details)]) {
			expect(logged).not.toContain(value);
		}
	});

	it.each([
		["identity_mismatch", { user_uuid: "other-user" }],
		["invalid_timestamp", { iat: undefined }],
	])("does not resolve or log country before %s is rejected", async (code, invalid) => {
		const info = vi.spyOn(console, "info").mockImplementation(() => {});
		stubIdentityFetch(() => jsonResponse(identity(invalid)));
		await expect(createIdentityPage(ISSUER, TOKEN, { ...USER, country: "SG" }, { debugCountry: true }))
			.rejects.toMatchObject({ diagnostic: { code } });
		expect(info).not.toHaveBeenCalled();
	});
});
