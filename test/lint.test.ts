import { describe, expect, it } from "vitest";
import { eip55, lintEndpoint, lintPaymentRequired, parsePaymentRequired } from "../src/lint/lint";
import { b64, fixture, GOOD_PR, json, stubFetch, USDC } from "./helpers";

const ids = (r: { findings: any[] }, sev?: string) => r.findings.filter((f) => !sev || f.severity === sev).map((f) => f.id);
const lp = (pr: any, o: any = { url: "https://api.example.com/data", from: "header" }) => lintPaymentRequired(pr, o);
const acc = (over: Record<string, any>) => GOOD_PR({ accepts: [{ ...GOOD_PR().accepts[0], ...over }] });

describe("eip55", () => {
  it("matches the EIP-55 test vectors", () => {
    for (const a of ["0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed", "0xfB6916095ca1df60bB79Ce92cE3Ea74c37c5d359", "0xdbF03B407c01E7cD3CBea99509d93f8DDDC8C6FB", "0xD1220A0cf47c7B9Be7A2E6BA89F429762e7b9aDb"]) expect(eip55(a.toLowerCase())).toBe(a);
  });
});

describe("lintPaymentRequired", () => {
  it("a clean v2 challenge has no findings", () => { expect(lp(GOOD_PR()).findings).toEqual([]); expect(lp(GOOD_PR()).summary.prices).toEqual(["0.01 USDC"]); });
  it("v1 is a warning and reads maxAmountRequired", () => {
    const r = lp({ x402Version: 1, accepts: [{ scheme: "exact", network: "base", asset: USDC, payTo: "0x209693Bc6afc0C5328bA36FaF03C514EF312287C", maxAmountRequired: "10000", maxTimeoutSeconds: 60, extra: { name: "USD Coin", version: "2" } }] });
    expect(ids(r, "error")).toEqual([]); expect(ids(r, "warn")).toContain("X102");
  });
  it("unknown version is an error", () => expect(ids(lp({ ...GOOD_PR(), x402Version: 3 }), "error")).toContain("X102"));
  it("empty or missing accepts", () => { expect(ids(lp(GOOD_PR({ accepts: [] })), "error")).toContain("X110"); expect(ids(lp({ x402Version: 2 }), "error")).toContain("X110"); });
  it("missing required fields are named", () => {
    const r = lp(acc({ payTo: undefined, amount: undefined })); const f = r.findings.find((x) => x.id === "X110")!;
    expect(f.message).toContain("payTo"); expect(f.message).toContain("amount"); expect(f.where).toBe("accepts[0]");
  });
  it("v1 field in a v2 challenge", () => { const r = lp(acc({ amount: undefined, maxAmountRequired: "10000" })); expect(r.findings.find((x) => x.id === "X110")!.message).toMatch(/v1 field|Missing/); });
  it("legacy network name in v2 is an error; CAIP-2 is fine", () => { expect(ids(lp(acc({ network: "base" })), "error")).toContain("X111"); expect(ids(lp(acc({ network: "eip155:8453" })))).not.toContain("X111"); });
  it("testnet warns", () => expect(ids(lp(acc({ network: "eip155:84532", asset: "0x036CbD53842c5426634e7929541eC2318f3dCF7e", extra: { name: "USDC", version: "2" } })), "warn")).toContain("X112"));
  it("payTo: malformed, short, zero, burn, bad checksum, ok lowercase", () => {
    expect(ids(lp(acc({ payTo: "0x1234" })), "error")).toContain("X113");
    expect(ids(lp(acc({ payTo: "0x" + "0".repeat(40) })), "error")).toContain("X113");
    expect(ids(lp(acc({ payTo: "0x000000000000000000000000000000000000dEaD" })), "error")).toContain("X113");
    const good = "0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed";
    const bad = good.slice(0, 5) + good[5].toUpperCase() + good.slice(6); // flip one letter's case
    expect(bad).not.toBe(good);
    const r = lp(acc({ payTo: bad.replace(/[a-f]/, (c) => c === c.toUpperCase() ? c.toLowerCase() : c.toUpperCase()) }));
    expect(ids(lp(acc({ payTo: good.toLowerCase() })), "error")).toEqual([]);
    expect(ids(lp(acc({ payTo: good })), "error")).toEqual([]);
    const flipped = "0x5AAeb6053F3E94C9b9A09f33669435E7Ef1BeAed";
    const rr = lp(acc({ payTo: flipped })); expect(rr.findings.find((x) => x.id === "X113")!.message).toContain(good); expect(r).toBeTruthy();
  });
  it("payTo equal to the asset contract", () => expect(ids(lp(acc({ payTo: USDC })), "error")).toContain("X114"));
  it("solana payTo: valid mint-length address ok, garbage rejected", () => {
    const sol = { network: "solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp", asset: "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v", scheme: "exact", extra: { feePayer: "x" } };
    expect(ids(lp(acc({ ...sol, payTo: "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v" })), "error")).toEqual([]);
    expect(ids(lp(acc({ ...sol, payTo: "not-base58-0OIl" })), "error")).toContain("X113");
    expect(ids(lp(acc({ ...sol, payTo: "abc" })), "error")).toContain("X113");
  });
  it("amount must be an integer string in base units", () => {
    expect(ids(lp(acc({ amount: "0.01" })), "error")).toContain("X115");
    expect(ids(lp(acc({ amount: "-5" })), "error")).toContain("X115");
    expect(ids(lp(acc({ amount: "0" })), "warn")).toContain("X115");
    expect(ids(lp(acc({ amount: "10000" })))).not.toContain("X115");
    expect(ids(lp(acc({ amount: "25000000" })), "info")).toContain("X115"); // $25
    expect(lp(acc({ amount: "25000000" })).summary.prices).toEqual(["25 USDC"]);
    expect(ids(lp(acc({ amount: "10" })), "warn")).toContain("X115"); // 0.00001
  });
  it("asset on the wrong network, unknown asset", () => {
    expect(ids(lp(acc({ network: "eip155:1" })), "warn")).toContain("X116");
    expect(ids(lp(acc({ asset: "0x1111111111111111111111111111111111111111" })), "info")).toContain("X116");
  });
  it("scheme", () => { expect(ids(lp(acc({ scheme: "magic" })), "warn")).toContain("X117"); expect(ids(lp(acc({ scheme: "upto" })))).not.toContain("X117"); });
  it("EVM exact needs extra.name/version; wrong values for a known USDC warn", () => {
    expect(ids(lp(acc({ extra: undefined })), "error")).toContain("X118");
    expect(ids(lp(acc({ extra: { name: "USD Coin" } })), "error")).toContain("X118");
    expect(ids(lp(acc({ extra: { name: "USDC", version: "2" } })), "warn")).toContain("X118"); // Base mainnet is "USD Coin"
    const fix = lp(acc({ extra: undefined })).findings.find((x) => x.id === "X118")!.fix!; expect(fix).toContain("USD Coin");
    expect(ids(lp(acc({ network: "eip155:84532", asset: "0x036CbD53842c5426634e7929541eC2318f3dCF7e", extra: { name: "USDC", version: "2" } })), "warn")).not.toContain("X118");
  });
  it("maxTimeoutSeconds", () => {
    expect(ids(lp(acc({ maxTimeoutSeconds: undefined })), "warn")).toContain("X119");
    expect(ids(lp(acc({ maxTimeoutSeconds: 5 })), "warn")).toContain("X119");
    expect(ids(lp(acc({ maxTimeoutSeconds: 99999 })), "warn")).toContain("X119");
    expect(ids(lp(acc({ maxTimeoutSeconds: "60" })), "warn")).toContain("X119");
  });
  it("resource checks (v2)", () => {
    expect(ids(lp(GOOD_PR({ resource: undefined })), "warn")).toContain("X130");
    expect(ids(lp(GOOD_PR({ resource: { url: "https://other.example/x", description: "d" } })), "warn")).toContain("X130");
    expect(ids(lp(GOOD_PR({ resource: { url: "https://api.example.com/data" } })), "info")).toContain("X130");
  });
  it("body-only v2 challenge warns; bazaar absence is info", () => {
    expect(ids(lp(GOOD_PR(), { url: "https://api.example.com/data", from: "body" }), "warn")).toContain("X103");
    expect(ids(lp(GOOD_PR({ extensions: {} })), "info")).toContain("X131");
  });
});

describe("parsePaymentRequired", () => {
  const enc = (s: string) => new TextEncoder().encode(s);
  it("reads the header, falls back to the body, explains failures", () => {
    expect(parsePaymentRequired({ "payment-required": b64(GOOD_PR()) }, enc("")).from).toBe("header");
    expect(parsePaymentRequired({}, enc(JSON.stringify(GOOD_PR()))).from).toBe("body");
    expect(parsePaymentRequired({ "payment-required": "%%%" }, enc("not json")).error).toMatch(/not base64/);
    expect(parsePaymentRequired({}, enc("{}")).error).toMatch(/no accepts/);
    expect(parsePaymentRequired({}, enc("<html>")).pr).toBeNull();
  });
});

const H = "https://api.example.com/data";
const challenge = (pr: any = GOOD_PR(), headers: Record<string, string> = {}) => new Response(JSON.stringify(pr), { status: 402, headers: { "content-type": "application/json", "payment-required": b64(pr), ...headers } });
const onlyPaid = (resp: () => Response, o: { methods?: string[] } = {}) => (url: string, init?: RequestInit) => url === H && (init?.method === "OPTIONS" ? false : (o.methods ?? ["GET", "POST"]).includes(init?.method ?? "GET")) ? resp() : undefined;

describe("lintEndpoint", () => {
  it("clean endpoint with discovery files: ok, ~6 subrequests", async () => {
    const s = stubFetch([onlyPaid(() => challenge(GOOD_PR(), { "access-control-allow-origin": "*", "access-control-expose-headers": "PAYMENT-REQUIRED", "cache-control": "no-store" })),
      (u) => u.endsWith("/.well-known/x402") ? json({ payTo: ["0x209693Bc6afc0C5328bA36FaF03C514EF312287C"] }) : undefined,
      (u) => u.endsWith("/llms.txt") ? new Response("# api\nlong enough docs here") : u.endsWith("/openapi.json") ? json({ openapi: "3.1.0", info: {} }) : undefined,
      (u, i) => i?.method === "OPTIONS" ? new Response(null, { status: 204, headers: { "access-control-allow-headers": "content-type, payment-signature" } }) : undefined]);
    const r = await lintEndpoint(H, {}, { fetchImpl: s.f });
    expect(r.verdict).toBe("ok"); expect(r.findings).toEqual([]); expect(s.calls.length).toBe(6);
    expect(r.not_tested.join(" ")).toMatch(/settlement/);
    // a clean lint must never read as "revenue works" (vina, jarviscooper)
    expect(r.scope).toBe("unpaid_path_only"); expect(r.verdict_meaning).toMatch(/says nothing about whether payments settle/);
    expect(r.paid_path_checks.map((x: any) => x.name)).toEqual(["paid-replay", "settle-not-called", "paid-200-cacheable", "paid-response-delivered"]);
    for (const x of r.paid_path_checks) expect(x.how_to_test.length).toBeGreaterThan(40);
  });
  it("200 without payment is an error", async () => {
    const s = stubFetch([(u, i) => u === H ? json({ data: 1 }) : undefined]);
    const r = await lintEndpoint(H, {}, { fetchImpl: s.f });
    expect(r.verdict).toBe("fail"); expect(ids(r, "error")).toContain("X002");
  });
  it("POST-only 402: warns about GET (directory probes)", async () => {
    const s = stubFetch([onlyPaid(() => challenge(), { methods: ["POST"] }), (u, i) => u === H && i?.method === "GET" ? new Response("nope", { status: 405 }) : undefined]);
    const r = await lintEndpoint(H, {}, { fetchImpl: s.f });
    const f = r.findings.find((x) => x.id === "X002")!; expect(f.severity).toBe("warn"); expect(f.message).toMatch(/Only POST/); expect(f.message).toContain("GET returns 405");
  });
  it("GET-only 402 whose bazaar extension declares GET: X002 is info, not warn (found linting a real GET API)", async () => {
    const pr = GOOD_PR({ extensions: { bazaar: { info: { input: { type: "http", method: "GET" } } } } });
    const s = stubFetch([onlyPaid(() => challenge(pr), { methods: ["GET"] }), (u, i) => u === H && i?.method === "POST" ? new Response("nope", { status: 404 }) : undefined]);
    const r = await lintEndpoint(H, {}, { fetchImpl: s.f });
    const f = r.findings.find((x) => x.id === "X002")!; expect(f.severity).toBe("info"); expect(f.message).toMatch(/declares method GET/); expect(f.fix).toMatch(/405/);
    // without the declaration it stays a warning
    const s2 = stubFetch([onlyPaid(() => challenge(), { methods: ["GET"] }), (u, i) => u === H && i?.method === "POST" ? new Response("nope", { status: 404 }) : undefined]);
    expect((await lintEndpoint(H, {}, { fetchImpl: s2.f })).findings.find((x) => x.id === "X002")!.severity).toBe("warn");
  });
  it("method=POST probes only POST", async () => {
    const s = stubFetch([onlyPaid(() => challenge())]);
    await lintEndpoint(H, { method: "POST" }, { fetchImpl: s.f });
    expect(s.calls.filter((c) => c.url === H).map((c) => c.method).sort()).toEqual(["OPTIONS", "POST"]);
  });
  it("unreachable host", async () => {
    const f = (async () => { throw new TypeError("fetch failed"); }) as unknown as typeof fetch;
    const r = await lintEndpoint(H, {}, { fetchImpl: f });
    expect(r.verdict).toBe("fail"); expect(ids(r, "error")).toEqual(["X001"]);
  });
  it("redirect, plain http, cacheable 402, wrong content-type, body-only", async () => {
    const pr = GOOD_PR();
    const s = stubFetch([(u, i) => u === "http://api.example.com/data" && i?.method !== "OPTIONS" ? new Response(null, { status: 301, headers: { location: H } }) : undefined,
      (u, i) => u === H && i?.method !== "OPTIONS" ? new Response(JSON.stringify(pr), { status: 402, headers: { "content-type": "text/html", "cache-control": "public, max-age=300" } }) : undefined]);
    const r = await lintEndpoint("http://api.example.com/data", {}, { fetchImpl: s.f });
    for (const id of ["X004", "X007", "X006", "X103"]) expect(ids(r, "warn")).toContain(id);
    // jarviscooper: the risk is a stale challenge (payTo/amount outliving a rotation), not a leak
    expect(JSON.stringify(r.findings.find((x: any) => x.id === "X007"))).toMatch(/stale challenge/);
  });
  it("402 that is not x402", async () => {
    const s = stubFetch([(u, i) => u === H && i?.method !== "OPTIONS" ? new Response("<html>pay me</html>", { status: 402 }) : undefined]);
    const r = await lintEndpoint(H, {}, { fetchImpl: s.f });
    expect(ids(r, "error")).toContain("X101");
  });
  it("well-known payTo mismatch; CORS without expose", async () => {
    const s = stubFetch([onlyPaid(() => challenge(GOOD_PR(), { "access-control-allow-origin": "*" })), (u) => u.endsWith("/.well-known/x402") ? json({ payTo: "0x1111111111111111111111111111111111111111" }) : undefined]);
    const r = await lintEndpoint(H, {}, { fetchImpl: s.f });
    expect(ids(r, "warn")).toContain("X010"); expect(ids(r, "info")).toContain("X009");
  });
  it("well-known payTo match is recorded; extra addresses are info (overwatch-dominion)", async () => {
    const pt = (GOOD_PR() as any).accepts[0].payTo;
    const s1 = stubFetch([onlyPaid(() => challenge()), (u) => u.endsWith("/.well-known/x402") ? json({ payTo: pt }) : undefined]);
    const r1: any = await lintEndpoint(H, {}, { fetchImpl: s1.f });
    expect(r1.probes.well_known_payto).toBe("match"); expect(ids(r1, "warn")).not.toContain("X010"); expect(ids(r1, "info")).not.toContain("X010");
    const s2 = stubFetch([onlyPaid(() => challenge()), (u) => u.endsWith("/.well-known/x402") ? json({ payTo: [pt, "0x1111111111111111111111111111111111111111"] }) : undefined]);
    const r2: any = await lintEndpoint(H, {}, { fetchImpl: s2.f });
    expect(r2.probes.well_known_payto).toBe("match"); expect(ids(r2, "warn")).not.toContain("X010"); expect(ids(r2, "info")).toContain("X010");
  });
  it("well-known without any address is only info", async () => {
    const s = stubFetch([onlyPaid(() => challenge()), (u) => u.endsWith("/.well-known/x402") ? json({ service: "x", paid_endpoints: ["/data"] }) : undefined]);
    const r = await lintEndpoint(H, {}, { fetchImpl: s.f });
    expect(ids(r, "warn")).not.toContain("X010"); expect(ids(r, "info")).toContain("X010");
  });
  it("GET and POST disagreeing on terms", async () => {
    const s = stubFetch([(u, i) => u === H && i?.method === "POST" ? challenge(acc({ amount: "20000" })) : u === H && i?.method === "GET" ? challenge() : undefined]);
    const r = await lintEndpoint(H, {}, { fetchImpl: s.f });
    expect(ids(r, "warn")).toContain("X132");
  });
  it("slow challenge", async () => {
    const f = (async (u: any, i?: RequestInit) => { if (String(u) === H && i?.method === "GET") await new Promise((r) => setTimeout(r, 30)); return challenge(); }) as unknown as typeof fetch;
    const r = await lintEndpoint(H, { method: "GET" }, { fetchImpl: f });
    expect(r.probes.get.ms).toBeGreaterThanOrEqual(25);
  });
  it("blocks non-public targets", async () => {
    for (const u of ["https://localhost/x", "https://127.0.0.1/x", "https://10.0.0.1/x", "ftp://x.com/a", "https://user:pw@x.com/a", "https://x.com:8443/a"]) await expect(lintEndpoint(u, {}, { fetchImpl: stubFetch([]).f })).rejects.toThrow();
  });
});

describe("real captured 402s (fixtures from 2026-10-27)", () => {
  const cases: [string, string][] = [["mart402", "https://mart402.com/v1/extract"], ["otto", "https://x402.ottoai.services/v1/x"], ["tap", "https://x402tap.com/api/x"], ["guild", "https://agent-guild-5d5r.onrender.com/x"]];
  for (const [name, url] of cases) it(`${name}: parses, no errors, no host mismatch`, async () => {
    const s = stubFetch([(u, i) => (i?.method === "OPTIONS" || new URL(u).pathname !== new URL(url).pathname) ? undefined : fixture(name)]);
    const r = await lintEndpoint(url, {}, { fetchImpl: s.f });
    expect(r.summary.x402_version).toBe(2);
    expect(ids(r, "error")).toEqual([]);
    expect(r.findings.some((f) => f.id === "X130" && f.severity === "warn")).toBe(false);
    expect(r.verdict).toBe("ok");
  });
  it("otto: two accepts with different payTo noted", async () => {
    const s = stubFetch([(u, i) => i?.method === "OPTIONS" || !u.endsWith("/v1/x") ? undefined : fixture("otto")]);
    const r = await lintEndpoint("https://x402.ottoai.services/v1/x", {}, { fetchImpl: s.f });
    expect(ids(r)).toContain("X120");
  });
});
