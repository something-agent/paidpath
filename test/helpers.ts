import { readFileSync } from "node:fs";
import { join } from "node:path";
export type Route = (url: string, init?: RequestInit) => Response | undefined | Promise<Response | undefined>;
export function stubFetch(routes: Route[]) {
  const calls: { url: string; method: string }[] = [];
  const f = (async (input: any, init?: RequestInit) => {
    const url = typeof input === "string" ? input : input.url;
    calls.push({ url, method: init?.method ?? "GET" });
    for (const r of routes) { const res = await r(url, init); if (res) return res; }
    return new Response("not found", { status: 404 });
  }) as typeof fetch;
  return { f, calls };
}
export const json = (o: unknown, status = 200, headers: Record<string, string> = {}) => new Response(JSON.stringify(o), { status, headers: { "content-type": "application/json", ...headers } });
/** Load a real captured 402 (headers + body) from test/fixtures. */
export function fixture(name: string, status = 402): Response {
  const h = readFileSync(join(__dirname, "fixtures", name + ".headers"), "utf8").split("\n").slice(1);
  const headers = new Headers();
  for (const line of h) { const i = line.indexOf(":"); if (i > 0) { const k = line.slice(0, i).trim().toLowerCase(); if (!["content-length", "content-encoding", "transfer-encoding", "alt-svc"].includes(k)) headers.set(k, line.slice(i + 1).trim()); } }
  return new Response(readFileSync(join(__dirname, "fixtures", name + ".body")), { status, headers });
}
export function b64(o: unknown) { return Buffer.from(JSON.stringify(o)).toString("base64"); }
export const USDC = "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913";
export const GOOD_PR = (over: Record<string, any> = {}) => ({
  x402Version: 2,
  resource: { url: "https://api.example.com/data", description: "Example", mimeType: "application/json" },
  accepts: [{ scheme: "exact", network: "eip155:8453", asset: USDC, payTo: "0x209693Bc6afc0C5328bA36FaF03C514EF312287C", amount: "10000", maxTimeoutSeconds: 60, extra: { name: "USD Coin", version: "2" } }],
  extensions: { bazaar: {} },
  ...over,
});
