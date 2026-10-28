// Tiered sellers: several routes at different prices. Reads each route's unpaid 402 (plan mode: nothing is signed)
// and checks the quoted price against the seller's own tiers file (P207), then flags two routes that quote the same
// price (P208), a common copy-paste slip when a seller adds a tier. Idea: overwatch-dominion (three routes, three prices).
import { runPaidTest, planAccount, Check } from "./paid";
import { parseUsdc } from "./util";

export interface Tier { url: string; price: string; method?: string; body?: string; status?: number; contains?: string }
export interface TiersResult { verdict: "pass" | "fail"; routes: { url: string; expected: string; quoted?: string; verdict: string; checks: Check[] }[]; checks: Check[] }

export function loadTiers(text: string): Tier[] {
  const j = JSON.parse(text);
  if (!j || typeof j !== "object" || Array.isArray(j)) throw new Error('expected an object: {"<url>": {"price": "0.01", ...}}');
  return Object.entries(j).map(([url, v]: [string, any]) => {
    if (!/^https?:\/\//.test(url)) throw new Error(`${url}: keys must be full http(s) URLs`);
    if (!v || v.price === undefined) throw new Error(`${url}: "price" (USDC, e.g. "0.01") is required`);
    parseUsdc(String(v.price));
    return { url, price: String(v.price), method: v.method, body: v.body === undefined ? undefined : typeof v.body === "string" ? v.body : JSON.stringify(v.body), status: v.status, contains: v.contains };
  });
}

export async function runTiers(tiers: Tier[], payTo: string, opt: { network?: string; asset?: string; fetchImpl?: typeof fetch } = {}): Promise<TiersResult> {
  const routes: TiersResult["routes"] = [];
  for (const t of tiers) {
    const exp = parseUsdc(t.price);
    const r = await runPaidTest({ url: t.url, method: t.method ?? "POST", body: t.body, payTo, network: opt.network, asset: opt.asset,
      maxAmount: exp, expectPrice: exp, account: planAccount(), replay: false, underpay: false, fetchImpl: opt.fetchImpl });
    const checks = r.checks.filter((c) => c.id !== "P202");
    routes.push({ url: t.url, expected: exp.toString(), quoted: r.amount, verdict: r.verdict, checks });
  }
  const checks: Check[] = [];
  const byPrice = new Map<string, string[]>();
  for (const r of routes) if (r.quoted) byPrice.set(r.quoted, [...(byPrice.get(r.quoted) ?? []), r.url]);
  const dup = [...byPrice.entries()].filter(([, u]) => u.length > 1);
  const declaredDistinct = new Set(tiers.map((t) => parseUsdc(t.price).toString())).size === tiers.length;
  if (routes.length > 1) checks.push({ id: "P208", ok: dup.length === 0 || !declaredDistinct, severity: "warn",
    text: dup.length === 0 ? "every route quotes a different price" : `${dup.map(([p, u]) => `${u.length} routes quote ${p} base units (${u.join(", ")})`).join("; ")}${declaredDistinct ? " although your tiers file prices them differently" : " (your tiers file prices them the same, so this is expected)"}` });
  const failed = routes.some((r) => r.verdict !== "plan") || checks.some((c) => c.ok === false && c.severity === "error");
  return { verdict: failed ? "fail" : "pass", routes, checks };
}
