import { describe, expect, it } from "vitest";
import { generatePrivateKey, privateKeyToAccount } from "viem/accounts";
import { runPaidTest } from "../src/paid";
import { loadTiers, runTiers } from "../src/tiers";
import { main } from "../src/cli";
import { seller, PAYTO, URL_, RPC } from "./seller";
import { writeFileSync, mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

const account = privateKeyToAccount(generatePrivateKey());
const check = (r: any, id: string) => r.checks.find((c: any) => c.id === id);
const multi = (prices: Record<string, string>) => {
  const s = Object.fromEntries(Object.entries(prices).map(([u, p]) => [u, seller({ price: p })]));
  return (async (input: any, init?: RequestInit) => { const u = typeof input === "string" ? input : input.url; return (s[u] ?? Object.values(s)[0]).f(s[u] ? URL_ : input, init); }) as typeof fetch;
};

describe("--expect-price (P207)", () => {
  it("matching price passes and pays", async () => {
    const s = seller();
    const r = await runPaidTest({ url: URL_, payTo: PAYTO, maxAmount: 10000n, expectPrice: 10000n, account, fetchImpl: s.f, rpcUrls: [RPC], waitMs: 0, pollMs: 1, sleep: async () => {} });
    expect(check(r, "P207").ok).toBe(true); expect(r.verdict).toBe("pass");
  });
  it("a different quote is refused before anything is signed", async () => {
    const s = seller({ price: "1000" });
    const r = await runPaidTest({ url: URL_, payTo: PAYTO, maxAmount: 10000n, expectPrice: 10000n, account, fetchImpl: s.f, rpcUrls: [RPC] });
    expect(check(r, "P207").ok).toBe(false); expect(r.verdict).toBe("refused"); expect(r.signed).toHaveLength(0); expect(s.used.size).toBe(0);
  });
});

describe("tiers", () => {
  const A = "https://seller.example/basic", B = "https://seller.example/pro", C = "https://seller.example/max";
  it("loads and validates the file", () => {
    expect(loadTiers(JSON.stringify({ [A]: { price: "0.001", body: { q: 1 } } }))[0]).toMatchObject({ url: A, price: "0.001", body: '{"q":1}' });
    expect(() => loadTiers('{"/rel": {"price": "0.01"}}')).toThrow(/full http/);
    expect(() => loadTiers(JSON.stringify({ [A]: {} }))).toThrow(/price/);
  });
  it("all three tiers quote their own price: pass, nothing signed", async () => {
    const r = await runTiers(loadTiers(JSON.stringify({ [A]: { price: "0.001" }, [B]: { price: "0.01" }, [C]: { price: "0.05" } })), PAYTO, { fetchImpl: multi({ [A]: "1000", [B]: "10000", [C]: "50000" }) });
    expect(r.verdict).toBe("pass"); expect(r.routes.map((x) => x.quoted)).toEqual(["1000", "10000", "50000"]); expect(check(r, "P208").ok).toBe(true);
  });
  it("a swapped tier fails P207 and P208 flags the duplicate price", async () => {
    const r = await runTiers(loadTiers(JSON.stringify({ [A]: { price: "0.001" }, [B]: { price: "0.01" }, [C]: { price: "0.05" } })), PAYTO, { fetchImpl: multi({ [A]: "1000", [B]: "10000", [C]: "10000" }) });
    expect(r.verdict).toBe("fail"); expect(check(r.routes[2], "P207").ok).toBe(false); expect(check(r, "P208").ok).toBe(false);
  });
  it("CLI: tiers command and pay --tiers", async () => {
    const d = mkdtempSync(join(tmpdir(), "pp-")); const f = join(d, "t.json");
    writeFileSync(f, JSON.stringify({ [URL_]: { price: "0.02" } }));
    const out2: string[] = [];
    expect(await main(["pay", "https://other.example/x", "--pay-to", PAYTO, "--max-usdc", "0.05", "--tiers", f], {}, (s) => out2.push(s))).toBe(2);
    expect(out2.join("\n")).toMatch(/not in the tiers file/);
    const out3: string[] = [];
    expect(await main(["tiers", f], {}, (s) => out3.push(s))).toBe(2);
  });
});
