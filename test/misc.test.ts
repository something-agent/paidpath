import { describe, expect, it } from "vitest";
import { parseUsdc, assertNoSecret, fmtUsdc } from "../src/util";
import { directoryReadiness } from "../src/lint/directories";
import { verifyTransfer } from "../src/onchain";
import { main } from "../src/cli";

describe("util", () => {
  it("parses USDC amounts", () => { expect(parseUsdc("0.01")).toBe(10000n); expect(parseUsdc("1")).toBe(1000000n); expect(() => parseUsdc("0.0000001")).toThrow(); expect(() => parseUsdc("-1")).toThrow(); expect(fmtUsdc(9999n)).toBe("0.009999"); });
  it("leak guard trips on the key or its tail", () => {
    const k = "0x" + "ab".repeat(32);
    expect(() => assertNoSecret("hello " + k, k)).toThrow(/leak guard/);
    expect(() => assertNoSecret("tail " + "ab".repeat(8), k)).toThrow();
    expect(() => assertNoSecret("clean", k)).not.toThrow();
  });
});

const PR = (over: any = {}) => ({ x402Version: 2, resource: { url: "https://a.example/x", description: "d" }, accepts: [{ scheme: "exact", network: "eip155:8453" }],
  extensions: { bazaar: { info: { input: { method: "POST" }, output: {} }, schema: {} } }, ...over });
const OAPI = JSON.stringify({ info: { "x-guidance": "call it" }, paths: { "/x": { post: { "x-payment-info": { protocols: [{ x402: {} }] }, requestBody: {} } } } });
const by = (r: any[], d: string) => r.find((x) => x.directory.startsWith(d));

describe("directoryReadiness", () => {
  it("a complete route is ready everywhere (Bazaar still needs a settled payment)", () => {
    const r = directoryReadiness({ url: "https://a.example/x", getStatus: 402, postStatus: 402, pr: PR(), challengeFrom: "header", lintErrors: 0, openapiText: OAPI });
    expect(r.map((x) => x.status)).toEqual(["ready", "ready", "ready", "needs_payment"]);
  });
  it("POST-only route fails the x402dash GET probe", () => {
    const r = directoryReadiness({ url: "https://a.example/x", getStatus: 405, postStatus: 402, pr: PR(), challengeFrom: "header", lintErrors: 0, openapiText: OAPI });
    expect(by(r, "x402dash").status).toBe("not_ready");
  });
  it("tunnel host and missing bazaar fail the Bazaar checks; no discovery fails x402scan", () => {
    const r = directoryReadiness({ url: "https://abc.trycloudflare.com/x", getStatus: 402, postStatus: 402, pr: PR({ extensions: {} }), challengeFrom: "body", lintErrors: 1 });
    expect(by(r, "Bazaar").status).toBe("not_ready");
    expect(by(r, "x402scan").status).toBe("not_ready");
    expect(by(r, "the402").status).toBe("not_ready");
  });
  it("a well-known listing is enough for x402scan discovery", () => {
    const r = directoryReadiness({ url: "https://a.example/x", getStatus: 402, postStatus: 402, pr: PR(), challengeFrom: "header", lintErrors: 0, wellKnownText: '{"resources":["https://a.example/x"]}' });
    expect(by(r, "x402scan").status).toBe("ready");
  });
});

describe("verifyTransfer RPC fallback", () => {
  it("falls back to the next RPC and reads the receipt", async () => {
    const f = (async (url: string, init: any) => {
      if (url === "https://down.test") return new Response("x", { status: 503 });
      const { method } = JSON.parse(init.body);
      const result = method === "eth_blockNumber" ? "0x10" : { status: "0x1", blockNumber: "0x10", logs: [] };
      return new Response(JSON.stringify({ result }));
    }) as any;
    const r = await verifyTransfer({ tx: "0x" + "1".repeat(64), network: "eip155:8453", asset: "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913", from: "0x" + "a".repeat(40), to: "0x" + "b".repeat(40), amount: 1n, rpcUrls: ["https://down.test", "https://up.test"], fetchImpl: f, waitMs: 0 });
    expect(r.rpc).toBe("https://up.test"); expect(r.checks.find((c) => c.id === "P222")!.ok).toBe(false);
  });
  it("rejects a malformed hash", async () => { expect((await verifyTransfer({ tx: "0x12", network: "eip155:8453", asset: "", from: "", to: "", amount: 1n })).ok).toBe(false); });
});

describe("cli", () => {
  const cap = () => { const lines: string[] = []; return { lines, out: (s: string) => lines.push(s) }; };
  it("pay requires --pay-to and --max-usdc", async () => {
    const c = cap(); expect(await main(["pay", "https://a.example/x"], {}, c.out)).toBe(2); expect(c.lines.join()).toMatch(/--pay-to/);
    const d = cap(); expect(await main(["pay", "https://a.example/x", "--pay-to", "0x" + "a".repeat(40)], {}, d.out)).toBe(2);
  });
  it("--yes without a key is a usage error", async () => {
    const c = cap(); expect(await main(["pay", "https://a.example/x", "--pay-to", "0x" + "a".repeat(40), "--max-usdc", "0.01", "--yes"], {}, c.out)).toBe(2);
    expect(c.lines.join()).toMatch(/PAIDPATH_PRIVATE_KEY/);
  });
  it("never prints the key, even in an error that would echo it", async () => {
    const key = "0x" + "cd".repeat(32);
    const c = cap();
    await expect(main(["lint", key], { PAIDPATH_PRIVATE_KEY: key }, c.out)).rejects.toThrow(/leak guard|valid absolute URL/);
    expect(c.lines.join()).not.toContain("cd".repeat(16));
  });
  it("help and version", async () => { const c = cap(); expect(await main(["version"], {}, c.out)).toBe(0); expect(c.lines[0]).toBe("0.1.4"); });
});

import { lintEndpoint } from "../src/lint/lint";
describe("lintEndpoint directories mode", () => {
  it("prefers the POST challenge the bazaar extension declares, flags X133, returns directories", async () => {
    const b64 = (o: unknown) => Buffer.from(JSON.stringify(o)).toString("base64");
    const base = { x402Version: 2, resource: { url: "https://a.example/x", description: "d", mimeType: "application/json" },
      accepts: [{ scheme: "exact", network: "eip155:8453", asset: "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913", payTo: "0x209693Bc6afc0C5328bA36FaF03C514EF312287C", amount: "10000", maxTimeoutSeconds: 60, extra: { name: "USD Coin", version: "2" } }] };
    const withBz = { ...base, extensions: { bazaar: { info: { input: { type: "http", method: "POST" }, output: { type: "json" } }, schema: {} } } };
    const f = (async (url: string, init: any) => {
      const m = init?.method ?? "GET";
      if (url === "https://a.example/x" && (m === "GET" || m === "POST")) return new Response("{}", { status: 402, headers: { "content-type": "application/json", "cache-control": "no-store", "payment-required": b64(m === "POST" ? withBz : base) } });
      if (url.endsWith("/openapi.json")) return new Response(JSON.stringify({ info: { "x-guidance": "g" }, paths: { "/x": { post: { "x-payment-info": { protocols: [{ x402: {} }] } } } } }), { status: 200 });
      return new Response("nf", { status: 404 });
    }) as any;
    const r: any = await lintEndpoint("https://a.example/x", { method: "auto", directories: true }, { fetchImpl: f });
    expect(r.summary.method).toBe("POST");
    expect(r.findings.some((x: any) => x.id === "X133")).toBe(true);
    expect(r.directories.map((d: any) => d.status)).toEqual(["ready", "ready", "ready", "needs_payment"]);
  });
});
