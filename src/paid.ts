// The paid path, end to end, against the seller's OWN endpoint:
//   unpaid 402 -> pick the requirement that pays YOUR payTo -> sign one exact EIP-3009 authorization (guarded)
//   -> paid request -> delivery checks -> PAYMENT-RESPONSE checks -> on-chain Transfer checks
//   -> replay the same payment header (refused, or an idempotent re-delivery) -> same header + different request (must be refused)
//   -> optional race: one fresh authorization sent twice at once (at most one delivers) -> sign 1 unit less (must be refused).
import { x402Client, x402HTTPClient } from "@x402/core/client";
import { decodePaymentResponseHeader } from "@x402/core/http";
import { ExactEvmScheme } from "@x402/evm";
import { guardSigner, GuardRefused, MinimalAccount, SignedAuth } from "./guard";
import { verifyTransfer, rpcCall, DEFAULT_RPCS } from "./onchain";
import { KNOWN_ASSETS } from "./lint/known";

export type Sev = "error" | "warn" | "info";
export interface Check { id: string; ok: boolean | null; severity: Sev; text: string }
export interface Exchange { step: string; method: string; url: string; status: number | null; sent_payment?: any; payment_response?: any; body_preview?: string; body_bytes?: number; ms: number; error?: string }
export interface Settlement { purpose: string; tx: string; network: string; amount: string; asset: string; from: string; to: string; block?: number }
export interface PaidOptions {
  url: string; method?: string; body?: string; headers?: Record<string, string>;
  payTo: string; network?: string; asset?: string;
  maxAmount: bigint; maxTotal?: bigint; maxSignatures?: number;
  account: MinimalAccount;
  replay?: boolean; underpay?: boolean;
  /** A different request body sent with the already-used payment header (P231). Must be refused. */
  replayBody?: string;
  /** Opt-in: sign one more authorization and send it twice at the same time (P232). At most one may deliver. */
  race?: boolean;
  expectStatus?: number; expectContains?: string;
  rpcUrls?: string[]; fetchImpl?: typeof fetch; waitMs?: number; pollMs?: number; sleep?: (ms: number) => Promise<void>;
  now?: () => number;
}
export interface PaidResult {
  verdict: "pass" | "fail" | "refused" | "plan"; url: string; method: string; network?: string; payTo?: string; amount?: string; asset?: string;
  checks: Check[]; settlements: Settlement[]; signed: SignedAuth[]; exchanges: Exchange[]; started_at: string; took_ms: number;
}

const is2xx = (s: number | null) => s !== null && s >= 200 && s < 300;
const redactPayment = (hdrVal: string | undefined) => {
  if (!hdrVal) return undefined;
  try {
    const j = JSON.parse(Buffer.from(hdrVal, "base64").toString("utf8"));
    const p = j?.payload ?? {};
    return { x402Version: j.x402Version, accepted: j.accepted ? { network: j.accepted.network, amount: j.accepted.amount, payTo: j.accepted.payTo, asset: j.accepted.asset } : undefined,
      authorization: p.authorization, signature: p.signature ? `${String(p.signature).slice(0, 10)}…(redacted)` : undefined };
  } catch { return { undecodable: true }; }
};

/** Thrown by a plan-only account: the guard approved the authorization, nothing was signed. */
export class PlanStop extends Error {}
export const planAccount = (address: `0x${string}` = "0x000000000000000000000000000000000000dEaD"): MinimalAccount => ({ address, signTypedData: async () => { throw new PlanStop("plan only"); } });

export async function runPaidTest(o: PaidOptions): Promise<PaidResult> {
  const t0 = Date.now();
  const f = o.fetchImpl ?? fetch;
  const method = (o.method ?? "POST").toUpperCase();
  const network = o.network ?? "eip155:8453";
  const checks: Check[] = [];
  const exchanges: Exchange[] = [];
  const settlements: Settlement[] = [];
  const add = (id: string, ok: boolean | null, severity: Sev, text: string) => checks.push({ id, ok, severity, text });
  const result = (verdict: PaidResult["verdict"], extra: Partial<PaidResult> = {}): PaidResult => ({
    verdict, url: o.url, method, checks, settlements, signed: guard?.state.signed ?? [], exchanges, started_at: new Date(t0).toISOString(), took_ms: Date.now() - t0, ...extra });
  let guard: ReturnType<typeof guardSigner> | undefined;

  const send = async (step: string, extraHeaders: Record<string, string> = {}, bodyOverride?: string) => {
    const s = Date.now();
    const headers: Record<string, string> = { "user-agent": "paidpath/0.1 (+https://github.com/something-agent/paidpath)", accept: "application/json, */*;q=0.5", ...(o.body && method !== "GET" ? { "content-type": "application/json" } : {}), ...(o.headers ?? {}), ...extraHeaders };
    const ex: Exchange = { step, method, url: o.url, status: null, ms: 0, sent_payment: redactPayment(extraHeaders["PAYMENT-SIGNATURE"] ?? extraHeaders["X-PAYMENT"]) };
    exchanges.push(ex);
    try {
      const r = await f(o.url, { method, headers, body: method === "GET" || method === "HEAD" ? undefined : (bodyOverride ?? o.body ?? "{}"), redirect: "manual", signal: AbortSignal.timeout(60_000) });
      const text = await r.text();
      ex.status = r.status; ex.ms = Date.now() - s; ex.body_bytes = Buffer.byteLength(text); ex.body_preview = text.slice(0, 300);
      const prh = r.headers.get("payment-response") ?? r.headers.get("x-payment-response");
      if (prh) { try { ex.payment_response = decodePaymentResponseHeader(prh); } catch { ex.payment_response = { undecodable: prh.slice(0, 40) }; } }
      return { r, text, prh, ex };
    } catch (e) { ex.ms = Date.now() - s; ex.error = (e as Error).message; return { r: null, text: "", prh: null, ex }; }
  };

  // 1. Unpaid request: must be a 402 we can parse.
  const u = await send("unpaid");
  if (!u.r) { add("P200", false, "error", `unpaid request failed: ${u.ex.error}`); return result("fail"); }
  add("P200", u.r.status === 402, "error", `unpaid ${method} returns ${u.r.status}${u.r.status === 402 ? "" : " (expected 402)"}`);
  if (u.r.status !== 402) return result("fail");
  const client0 = new x402HTTPClient(new x402Client());
  let pr: any;
  try { let body: any; try { body = JSON.parse(u.text); } catch { /* header only */ } pr = client0.getPaymentRequiredResponse((n) => u.r!.headers.get(n), body); }
  catch (e) { add("P200", false, "error", `could not parse the 402 with the official x402 client: ${(e as Error).message}`); return result("fail"); }

  // 2. Pick the requirement that pays the seller's own payTo. Anything else: refuse before signing.
  const accepts: any[] = pr.accepts ?? [];
  const req = accepts.find((a) => a.scheme === "exact" && a.network === network && String(a.payTo).toLowerCase() === o.payTo.toLowerCase());
  if (!req) { add("P201", false, "error", `no 'exact' requirement on ${network} pays your declared payTo ${o.payTo} (challenge offers: ${accepts.map((a) => `${a.network}->${String(a.payTo).slice(0, 10)}…`).join(", ") || "nothing"}). Refusing to pay.`); return result("refused"); }
  const asset = String(req.asset);
  const known = KNOWN_ASSETS.get(asset.toLowerCase());
  if (o.asset ? asset.toLowerCase() !== o.asset.toLowerCase() : !(known && known.network === network)) { add("P201", false, "error", `asset ${asset} is not ${o.asset ? "the asset you passed" : "the known USDC on " + network}. Refusing to pay (pass --asset to override).`); return result("refused"); }
  const amount = BigInt(req.amount ?? req.maxAmountRequired);
  if (amount > o.maxAmount) { add("P201", false, "error", `price ${amount} base units exceeds your cap ${o.maxAmount}. Refusing to pay.`); return result("refused"); }
  add("P201", true, "info", `requirement selected: ${network}, ${amount} base units of ${asset.slice(0, 10)}… to ${req.payTo}`);
  const chainId = Number(network.split(":")[1]);
  const maxSignatures = o.maxSignatures ?? ((o.underpay === false ? 1 : 2) + (o.race ? 1 : 0));
  guard = guardSigner(o.account, { payTo: o.payTo, asset, chainId, maxPerPayment: o.maxAmount, maxTotal: o.maxTotal ?? amount * (o.race ? 3n : 2n), maxSignatures });
  const client = new x402Client();
  client.register(network as `${string}:${string}`, new ExactEvmScheme(guard.signer as any));
  const http = new x402HTTPClient(client);
  const only = (r: any) => ({ ...pr, accepts: [r] });

  // 3. Pay once.
  let payHeaders: Record<string, string>;
  try { guard.state.purpose = "payment"; payHeaders = http.encodePaymentSignatureHeader(await client.createPaymentPayload(only(req))); }
  catch (e) {
    if (e instanceof PlanStop) {
      add("P202", null, "info", `plan only: the guard would allow 1 payment authorization of ${amount} to ${req.payTo}${o.underpay === false || amount <= 1n ? "" : ` and 1 underpayment probe of ${amount - 1n} (refused by a correct seller, so it should never settle)`}${o.race ? ` and 1 race probe of ${amount} (sent twice at once; settles once, to you)` : ""}. Nothing was signed. Re-run with --yes and PAIDPATH_PRIVATE_KEY to pay.`);
      guard.state.signed = []; return result("plan", { network, payTo: req.payTo, amount: amount.toString(), asset });
    }
    add("P202", false, "error", `could not create the payment: ${(e as Error).message}`); return result(e instanceof GuardRefused ? "refused" : "fail");
  }
  const p = await send("paid", payHeaders);
  const st = p.r?.status ?? null;
  add("P203", is2xx(st) && (o.expectStatus === undefined || st === o.expectStatus), "error", `paid request returns ${st ?? p.ex.error}${o.expectStatus ? ` (expected ${o.expectStatus})` : ""}`);
  add("P204", p.text.trim().length > 0, "error", `paid response delivers a body (${Buffer.byteLength(p.text)} bytes)`);
  if (o.expectContains !== undefined) add("P205", p.text.includes(o.expectContains), "error", `paid body contains ${JSON.stringify(o.expectContains)}`);
  const ct = p.r?.headers.get("content-type") ?? "";
  if (ct.includes("json")) { let okj = true; try { JSON.parse(p.text); } catch { okj = false; } add("P206", okj, "warn", `paid body parses as JSON (content-type ${ct})`); }

  // 4. PAYMENT-RESPONSE header.
  const settle: any = p.ex.payment_response;
  add("P210", !!p.prh, "error", p.prh ? "PAYMENT-RESPONSE header present" : "no PAYMENT-RESPONSE (or X-PAYMENT-RESPONSE) header on the paid response: the buyer gets no receipt");
  if (settle && !settle.undecodable) {
    add("P211", settle.success === true, "error", `settlement success=${settle.success}${settle.errorReason ? ` (${settle.errorReason})` : ""}`);
    add("P212", settle.network === network, "error", `settlement network ${settle.network} ${settle.network === network ? "matches" : "differs from"} the requirement (${network})`);
    add("P213", String(settle.payer ?? "").toLowerCase() === o.account.address.toLowerCase(), "warn", `settlement payer ${settle.payer ?? "missing"} ${String(settle.payer ?? "").toLowerCase() === o.account.address.toLowerCase() ? "is" : "is not"} the paying wallet`);
    add("P214", /^0x[0-9a-fA-F]{64}$/.test(String(settle.transaction ?? "")), "error", `settlement transaction ${settle.transaction || "missing"}`);
  } else if (p.prh) add("P211", false, "error", "PAYMENT-RESPONSE header is not decodable base64 JSON");

  // 5. On-chain.
  const tx = String(settle?.transaction ?? "");
  if (/^0x[0-9a-fA-F]{64}$/.test(tx)) {
    const rpcUrls = o.rpcUrls ?? DEFAULT_RPCS[network];
    if (rpcUrls?.length) {
      try { const cid = await rpcCall(rpcUrls, "eth_chainId", [], f); add("P224", parseInt(cid.result, 16) === chainId, "error", `RPC chain id ${parseInt(cid.result, 16)} ${parseInt(cid.result, 16) === chainId ? "matches" : "differs from"} ${network}`); } catch (e) { add("P224", null, "warn", `could not read chain id: ${(e as Error).message}`); }
    }
    const oc = await verifyTransfer({ tx, network, asset, from: o.account.address, to: req.payTo, amount, rpcUrls, fetchImpl: f, waitMs: o.waitMs, pollMs: o.pollMs, sleep: o.sleep });
    for (const c of oc.checks) add(c.id, c.ok, c.ok === null ? "warn" : "error", c.text);
    settlements.push({ purpose: "payment", tx, network, amount: amount.toString(), asset, from: o.account.address, to: req.payTo, block: oc.block });
  }

  // 6. Replay: the exact same payment header again. No new signature.
  //    Refused (402) is safe for the seller. A 2xx is only acceptable as an idempotent re-delivery: the same
  //    request gets the same response and nothing new settles (that is what a buyer whose response was lost
  //    needs). Anything else (a new settlement, or a different body) means one payment buys many responses.
  let replayIdempotent = false;
  if (o.replay !== false && is2xx(st)) {
    const r = await send("replay", payHeaders);
    const rs = r.r?.status ?? null;
    const newTx = r.ex.payment_response?.transaction;
    const sameBody = r.text === p.text;
    const noNewSettle = !newTx || newTx === tx;
    if (!is2xx(rs)) add("P230", true, "error", `replayed payment header refused with ${rs ?? r.ex.error}${rs === 402 ? "" : " (402 is the clearest answer)"}. Note: a buyer whose paid response was lost (timeout, 5xx after settle) cannot recover it with this header; consider re-serving the stored response for an identical retry keyed on the authorization nonce`);
    else if (sameBody && noNewSettle) { replayIdempotent = true; add("P230", true, "warn", `replay of the identical request got ${rs} with a byte-identical body and no new settlement: idempotent re-delivery (good for lost-response retries). This is only safe if the header is bound to the request; P231 checks that`); }
    else add("P230", false, "error", `REPLAY ACCEPTED: the same payment header got ${rs} again${newTx ? ` (PAYMENT-RESPONSE tx ${newTx})` : ""}${sameBody ? "" : " with a different body"}. One payment buys more than one response.`);
    if (is2xx(rs) && newTx && newTx !== tx) settlements.push({ purpose: "replay (unexpected)", tx: newTx, network, amount: amount.toString(), asset, from: o.account.address, to: req.payTo });
  }

  // 6b. Same header, different request. Must be refused, whatever the seller does for identical retries.
  if (o.replay !== false && is2xx(st)) {
    if (o.replayBody !== undefined && method !== "GET" && method !== "HEAD") {
      const r = await send("replay-different-request", payHeaders, o.replayBody);
      const rs = r.r?.status ?? null;
      add("P231", !is2xx(rs), "error", is2xx(rs) ? `PAYMENT NOT BOUND TO THE REQUEST: the used payment header bought a different request (${rs}). One payment buys any number of different answers.` : `used payment header with a different request body refused with ${rs ?? r.ex.error}`);
      const t2 = r.ex.payment_response?.transaction;
      if (is2xx(rs) && t2 && t2 !== tx) settlements.push({ purpose: "replay with different request (unexpected)", tx: t2, network, amount: amount.toString(), asset, from: o.account.address, to: req.payTo });
    } else if (replayIdempotent) add("P231", null, "warn", "not tested: the identical replay was re-delivered, so binding to the request matters. Pass --replay-body '<a different valid request>' to check that the used header cannot buy a different answer");
  }

  // 6c. Race (opt-in): one fresh authorization sent twice at the same moment, before the first has settled.
  //     The EIP-3009 nonce lets it settle at most once, so at most one response may deliver.
  if (o.race && is2xx(st)) {
    let h: Record<string, string> | null = null;
    try { guard.state.purpose = "race probe"; h = http.encodePaymentSignatureHeader(await client.createPaymentPayload(only(req))); }
    catch (e) { add("P232", null, "warn", `race probe not sent: ${(e as Error).message}`); }
    if (h) {
      const [a1, a2] = await Promise.all([send("race-1", h), send("race-2", h)]);
      const ok2 = [a1, a2].filter((x) => is2xx(x.r?.status ?? null));
      const txs = [...new Set(ok2.map((x) => x.ex.payment_response?.transaction).filter(Boolean))] as string[];
      if (ok2.length === 2 && ok2[0].text === ok2[1].text && txs.length <= 1) add("P232", true, "warn", `both concurrent copies got 2xx with byte-identical bodies and ${txs.length ? "one settlement" : "no settlement reported"}: treated as idempotent re-delivery, not double delivery`);
      else add("P232", ok2.length <= 1, "error", ok2.length <= 1 ? `concurrent double-submit: ${ok2.length} of 2 delivered (${a1.r?.status ?? a1.ex.error} / ${a2.r?.status ?? a2.ex.error})` : `DOUBLE DELIVERY: both concurrent copies of one authorization got 2xx with different bodies; the nonce lets it settle once, so one of them was free`);
      for (const t of txs) settlements.push({ purpose: "race probe", tx: t, network, amount: amount.toString(), asset, from: o.account.address, to: req.payTo });
    }
  }

  // 7. Underpayment: a fresh authorization for 1 base unit less than the price. Must be refused.
  if (o.underpay !== false && is2xx(st)) {
    if (amount <= 1n) add("P240", null, "info", "price is 1 base unit; underpayment test skipped");
    else {
      const under = { ...req, amount: (amount - 1n).toString() };
      let h: Record<string, string> | null = null;
      try { guard.state.purpose = "underpayment probe"; h = http.encodePaymentSignatureHeader(await client.createPaymentPayload(only(under))); }
      catch (e) { add("P240", null, "warn", `underpayment probe not sent: ${(e as Error).message}`); }
      if (h) {
        const r = await send("underpay", h);
        const rs = r.r?.status ?? null;
        const utx = r.ex.payment_response?.transaction;
        add("P240", !is2xx(rs), "error", is2xx(rs) ? `UNDERPAYMENT ACCEPTED: an authorization for ${amount - 1n} (< ${amount}) got ${rs}${utx ? `, settled in ${utx}` : ""}` : `underpayment (${amount - 1n} < ${amount}) refused with ${rs ?? r.ex.error}`);
        if (is2xx(rs) && utx) settlements.push({ purpose: "underpayment (unexpected)", tx: utx, network, amount: (amount - 1n).toString(), asset, from: o.account.address, to: req.payTo });
      }
    }
  }
  const failed = checks.some((c) => c.ok === false && c.severity === "error");
  return result(failed ? "fail" : "pass", { network, payTo: req.payTo, amount: amount.toString(), asset });
}
