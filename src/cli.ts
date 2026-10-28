#!/usr/bin/env node
import { readFileSync, writeFileSync } from "node:fs";
import { privateKeyToAccount } from "viem/accounts";
import { lintEndpoint } from "./lint/lint";
import { runPaidTest, planAccount, PaidResult } from "./paid";
import { loadTiers, runTiers } from "./tiers";
import { cdpValidate } from "./cdp";
import { assertNoSecret, parseUsdc, fmtUsdc } from "./util";

export const VERSION = "0.1.3";
const KEY_ENV = "PAIDPATH_PRIVATE_KEY";
const HELP = `paidpath ${VERSION}: self-test kit for x402 sellers. Test YOUR OWN paid endpoint, unpaid and paid.

  paidpath lint <url> [--method auto|GET|POST] [--cdp-validate] [--allow-private] [--json]
      No key, no payment. Lints the unpaid 402 (x402lint rules) and checks directory readiness
      (x402dash, x402scan, the402, CDP/PayAI Bazaar). --cdp-validate also asks Coinbase's free validator.

  paidpath pay <url> --pay-to <your payTo> --max-usdc <cap> [options]
      Without --yes: a plan. Reads the 402 and shows exactly what would be signed. No key needed.
      With --yes and ${KEY_ENV} set: pays your endpoint ONCE, then checks delivery, the PAYMENT-RESPONSE
      header, the on-chain Transfer (payTo, amount, token, chain), that a replay of the same payment is
      refused (or is an idempotent re-delivery of the identical request), and that an authorization for
      1 unit less is refused.
      --replay-body '<json>'  also send the USED payment header with a different request (must be refused)
      --race                  sign one more authorization and send it twice at once (at most one may deliver;
                              costs one more payment of the price, to your own payTo)
      --method POST|GET (default POST)   --body '<json>' | --body-file <path>   --header 'Name: value' (repeatable)
      --network eip155:8453 (default)    --asset <token>   --rpc <url> (repeatable)
      --expect-status <n>   --expect-contains <text>   --expect-price <usdc>   --no-replay   --no-underpay
      --tiers <tiers.json>    take this URL's expect-price/status/contains/method/body from a tiers file
      --max-signatures <n> (default 2, 3 with --race)   --max-total-usdc <cap> (default 2x price, 3x with --race)
      --out <transcript.json>   --json   --allow-private

  paidpath tiers <tiers.json> --pay-to <your payTo> [--json]
      No key, no payment. For a seller with several routes at different prices: reads each route's 402
      and checks the quoted price against the file (P207), and flags two routes quoting the same price (P208).
      tiers.json: {"https://api.example/basic": {"price": "0.001"}, "https://api.example/pro": {"price": "0.01",
      "method": "POST", "body": {"q": 1}, "status": 200, "contains": "result"}}

  The key is read only from the ${KEY_ENV} env var, used in-process to sign, never sent or written.
  Every signature passes a guard: only an EIP-3009 transferWithAuthorization of the expected token,
  on the expected chain, to --pay-to, within the caps. Use a test wallet with a few cents in it.
  Exit codes: 0 pass, 1 fail, 2 refused / usage error, 3 plan only.`;

function parseArgs(argv: string[]) {
  const pos: string[] = []; const opt: Record<string, string[]> = {};
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a.startsWith("--")) {
      const [k, inline] = a.slice(2).split(/=(.*)/s, 2);
      const flag = ["json", "yes", "race", "no-replay", "no-underpay", "allow-private", "cdp-validate", "help"].includes(k);
      const v = flag ? "true" : inline ?? argv[++i];
      if (v === undefined) throw new Error(`--${k} needs a value`);
      (opt[k] ??= []).push(v);
    } else pos.push(a);
  }
  return { pos, opt, one: (k: string) => opt[k]?.[opt[k].length - 1], has: (k: string) => !!opt[k] };
}

const mark = (ok: boolean | null) => ok === true ? "PASS" : ok === false ? "FAIL" : "----";

export async function main(argv: string[], env: Record<string, string | undefined> = process.env, out: (s: string) => void = (s) => process.stdout.write(s + "\n")): Promise<number> {
  const secret = env[KEY_ENV];
  const emit = (s: string) => { assertNoSecret(s, secret); out(s); };
  let a: ReturnType<typeof parseArgs>;
  try { a = parseArgs(argv); } catch (e) { emit((e as Error).message); return 2; }
  const [cmd, url] = a.pos;
  if (!cmd || a.has("help") || cmd === "help") { emit(HELP); return cmd ? 0 : 2; }
  if (cmd === "version" || cmd === "--version") { emit(VERSION); return 0; }
  if (!url) { emit("missing <url>\n\n" + HELP); return 2; }

  if (cmd === "lint" || cmd === "dry-run") {
    const m = (a.one("method") ?? "auto").toUpperCase();
    const r: any = await lintEndpoint(url, { method: m === "AUTO" ? "auto" : (m as "GET" | "POST"), directories: true }, { allowPrivate: a.has("allow-private") });
    if (a.has("cdp-validate")) { try { r.cdp_validator = await cdpValidate(url, r.summary?.method ?? (m === "GET" ? "GET" : "POST")); } catch (e) { r.cdp_validator = { error: (e as Error).message }; } }
    if (a.has("json")) emit(JSON.stringify(r, null, 2));
    else {
      emit(`paidpath lint ${r.url}\nunpaid verdict: ${r.verdict.toUpperCase()}  (${r.counts?.error ?? 0} error, ${r.counts?.warn ?? 0} warn, ${r.counts?.info ?? 0} info)`);
      if (r.summary) emit(`challenge: ${r.summary.method} -> 402 in ${r.summary.challenge_in}, x402 v${r.summary.x402_version ?? "?"}`);
      for (const f of r.findings) emit(`  [${f.severity}] ${f.id} ${f.message}${f.fix ? `\n          fix: ${f.fix}` : ""}`);
      emit("\ndirectory readiness (what each directory was known to check; not a listing guarantee):");
      for (const d of r.directories ?? []) {
        emit(`  ${d.directory}: ${d.status.toUpperCase().replace("_", " ")}`);
        for (const c of d.checks) emit(`    ${mark(c.ok)} ${c.text}`);
        emit(`    note: ${d.note}`);
      }
      if (r.cdp_validator) emit(`\nCDP validator: ${JSON.stringify(r.cdp_validator)}`);
      emit(`\nnot tested here: ${r.not_tested.join("; ")}. Run 'paidpath pay' for the paid path.`);
    }
    return r.verdict === "fail" ? 1 : 0;
  }

  if (cmd === "tiers") {
    const payTo = a.one("pay-to");
    if (!payTo || !/^0x[0-9a-fA-F]{40}$/.test(payTo)) { emit("--pay-to <0x… your own receiving address> is required."); return 2; }
    let tiers;
    try { tiers = loadTiers(readFileSync(url, "utf8")); } catch (e) { emit(`tiers file: ${(e as Error).message}`); return 2; }
    const r = await runTiers(tiers, payTo, { network: a.one("network"), asset: a.one("asset") });
    if (a.has("json")) emit(JSON.stringify({ tool: `paidpath ${VERSION}`, ...r }, null, 2));
    else {
      emit(`paidpath tiers (${r.routes.length} routes, unpaid only, nothing signed)`);
      for (const t of r.routes) { emit(`  ${t.url}  expected ${t.expected}  quoted ${t.quoted ?? "?"}`); for (const c of t.checks) emit(`    ${mark(c.ok)} ${c.id} ${c.text}`); }
      for (const c of r.checks) emit(`  ${mark(c.ok)} ${c.id} ${c.text}`);
      emit(`verdict: ${r.verdict.toUpperCase()}`);
    }
    return r.verdict === "pass" ? 0 : 1;
  }

  if (cmd === "pay") {
    const payTo = a.one("pay-to"); const cap = a.one("max-usdc");
    if (!payTo || !/^0x[0-9a-fA-F]{40}$/.test(payTo)) { emit("--pay-to <0x… your own receiving address> is required: paidpath only pays the address you say is yours."); return 2; }
    if (!cap) { emit("--max-usdc <cap per payment, e.g. 0.01> is required."); return 2; }
    let tier: any;
    if (a.one("tiers")) {
      try { tier = loadTiers(readFileSync(a.one("tiers")!, "utf8")).find((t) => t.url === url); } catch (e) { emit(`tiers file: ${(e as Error).message}`); return 2; }
      if (!tier) { emit(`--tiers: ${url} is not in the tiers file.`); return 2; }
    }
    let body = a.one("body") ?? tier?.body;
    const bf = a.one("body-file"); if (bf) body = readFileSync(bf, "utf8");
    const headers: Record<string, string> = {};
    for (const h of a.opt["header"] ?? []) { const i = h.indexOf(":"); if (i > 0) headers[h.slice(0, i).trim()] = h.slice(i + 1).trim(); }
    const live = a.has("yes");
    let account;
    if (live) {
      if (!secret) { emit(`--yes needs the ${KEY_ENV} env var (a 0x-prefixed private key of a TEST wallet).`); return 2; }
      try { account = privateKeyToAccount((secret.startsWith("0x") ? secret : "0x" + secret) as `0x${string}`); } catch { emit(`${KEY_ENV} is not a valid private key.`); return 2; }
      if (account.address.toLowerCase() === payTo.toLowerCase()) emit("note: paying from the payTo wallet itself (the money comes straight back; the facilitator pays gas).");
    } else account = planAccount();
    let r: PaidResult;
    try {
      const ep = a.one("expect-price") ?? tier?.price;
      r = await runPaidTest({ url, method: a.one("method") ?? tier?.method ?? "POST", expectPrice: ep !== undefined ? parseUsdc(String(ep)) : undefined, body, headers, payTo, network: a.one("network"), asset: a.one("asset"),
        maxAmount: parseUsdc(cap), maxTotal: a.one("max-total-usdc") ? parseUsdc(a.one("max-total-usdc")!) : undefined,
        maxSignatures: a.one("max-signatures") ? Number(a.one("max-signatures")) : undefined, account,
        replay: !a.has("no-replay"), underpay: !a.has("no-underpay"), replayBody: a.one("replay-body"), race: a.has("race"),
        expectStatus: a.one("expect-status") ? Number(a.one("expect-status")) : tier?.status, expectContains: a.one("expect-contains") ?? tier?.contains, rpcUrls: a.opt["rpc"] });
    } catch (e) { emit(`error: ${(e as Error).message}`); return 1; }
    const transcript = JSON.stringify({ tool: `paidpath ${VERSION}`, ...r, payer: live ? account.address : undefined }, null, 2);
    const o = a.one("out"); if (o) { assertNoSecret(transcript, secret); writeFileSync(o, transcript + "\n"); }
    if (a.has("json")) emit(transcript);
    else {
      emit(`paidpath pay ${r.url} (${r.method})${live ? "" : "  [PLAN ONLY: nothing signed]"}`);
      if (r.amount) emit(`price ${fmtUsdc(r.amount)} on ${r.network}, payTo ${r.payTo}`);
      for (const c of r.checks) emit(`  ${mark(c.ok)} ${c.id} ${c.text}`);
      for (const s of r.settlements) emit(`  settled (${s.purpose}): ${s.tx} ${fmtUsdc(s.amount)} ${s.from.slice(0, 8)}… -> ${s.to.slice(0, 8)}…${s.block ? ` block ${s.block}` : ""}`);
      if (live) emit(`  authorizations signed: ${r.signed.length} (${r.signed.map((x) => `${x.purpose} ${fmtUsdc(x.value)}`).join(", ") || "none"})`);
      emit(`verdict: ${r.verdict.toUpperCase()}${o ? `  transcript: ${o}` : ""}`);
    }
    return r.verdict === "pass" ? 0 : r.verdict === "fail" ? 1 : r.verdict === "plan" ? 3 : 2;
  }
  emit(`unknown command '${cmd}'\n\n` + HELP); return 2;
}

const isMain = process.argv[1] && /paidpath|cli\.(m?js|ts)$/.test(process.argv[1]);
if (isMain && !process.env.VITEST) main(process.argv.slice(2)).then((c) => process.exit(c), (e) => { console.error(`error: ${e?.message ?? e}`); process.exit(1); });
