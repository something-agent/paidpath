#!/usr/bin/env node

// src/cli.ts
import { readFileSync, writeFileSync } from "node:fs";
import { privateKeyToAccount } from "viem/accounts";

// src/lint/lint.ts
import { keccak_256 } from "@noble/hashes/sha3";

// src/lint/bytes.ts
var dec = new TextDecoder();
var enc = new TextEncoder();
function b64Decode(s) {
  const bin = atob(s.replace(/-/g, "+").replace(/_/g, "/").replace(/\s/g, ""));
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}
var B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
function base58Decode(s) {
  let n = 0n;
  for (const ch of s) {
    const i = B58.indexOf(ch);
    if (i < 0) throw new Error("invalid base58");
    n = n * 58n + BigInt(i);
  }
  const bytes = [];
  while (n > 0n) {
    bytes.push(Number(n & 0xffn));
    n >>= 8n;
  }
  let zeros = 0;
  for (const ch of s) {
    if (ch === "1") zeros++;
    else break;
  }
  return new Uint8Array([...new Array(zeros).fill(0), ...bytes.reverse()]);
}

// src/lint/known.ts
var A = (address, network, eip712) => [address.toLowerCase(), { symbol: "USDC", decimals: 6, network, eip712 }];
var KNOWN_ASSETS = new Map([
  A("0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913", "eip155:8453", { name: "USD Coin", version: "2" }),
  A("0x036CbD53842c5426634e7929541eC2318f3dCF7e", "eip155:84532", { name: "USDC", version: "2" }),
  A("0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48", "eip155:1", { name: "USD Coin", version: "2" }),
  A("0x3c499c542cEF5E3811e1192ce70d8cC03d5c3359", "eip155:137", { name: "USD Coin", version: "2" }),
  A("0xaf88d065e77c8cC2239327C5EDb3A432268e5831", "eip155:42161", { name: "USD Coin", version: "2" }),
  A("0x0b2C639c533813f4Aa9D7837CAf62653d097Ff85", "eip155:10", { name: "USD Coin", version: "2" }),
  ["epjfwdd5aufqssqem2qn1xzybapc8g4weggkzwytdt1v", { symbol: "USDC", decimals: 6, network: "solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp" }]
]);
var TESTNETS = /* @__PURE__ */ new Set(["eip155:84532", "eip155:11155111", "eip155:80002", "eip155:421614", "eip155:11155420", "solana:EtWTRABZaYq6iMfeYKouRu166VU2xqa1", "solana:4uhcVJyU9pJkvQyS88uRDiswHXSCkY3z", "base-sepolia", "solana-devnet", "sepolia"]);
var V1_NETWORKS = /* @__PURE__ */ new Set(["base", "base-sepolia", "ethereum", "sepolia", "polygon", "polygon-amoy", "avalanche", "avalanche-fuji", "solana", "solana-devnet", "iotex", "sei", "peaq", "abstract"]);
var CAIP2 = /^[a-z0-9-]{3,8}:[-_a-zA-Z0-9]{1,32}$/;

// src/lint/safe.ts
var UA = "x402lint/0.1 (+https://github.com/something-agent/x402lint; read-only x402 linter)";
var BlockedTarget = class extends Error {
};
function v4(ip) {
  const m = ip.match(/^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/);
  if (!m) return null;
  const p = m.slice(1).map(Number);
  return p.some((x) => x > 255) ? null : p;
}
function publicV4(p) {
  const [a, b] = p;
  if (a === 0 || a === 10 || a === 127 || a >= 224) return false;
  if (a === 100 && b >= 64 && b <= 127) return false;
  if (a === 169 && b === 254) return false;
  if (a === 172 && b >= 16 && b <= 31) return false;
  if (a === 192 && (b === 168 || b === 0 && p[2] <= 2 || b === 88 && p[2] === 99)) return false;
  if (a === 198 && (b === 18 || b === 19 || b === 51 && p[2] === 100)) return false;
  if (a === 203 && b === 0 && p[2] === 113) return false;
  return true;
}
function assertPublicUrl(raw, allowHttp = false, allowPrivate = false) {
  let u;
  try {
    u = new URL(raw);
  } catch {
    throw new BlockedTarget("not a valid absolute URL");
  }
  const scheme = u.protocol.replace(":", "");
  if (scheme !== "https" && !(allowHttp && scheme === "http")) throw new BlockedTarget(`scheme '${scheme}' not allowed (https only${allowHttp ? " or http" : ""})`);
  if (allowPrivate) return u;
  if (u.username || u.password) throw new BlockedTarget("credentials in URL are not allowed");
  if (u.port && !(scheme === "https" && u.port === "443" || scheme === "http" && u.port === "80")) throw new BlockedTarget("non-default ports are not allowed");
  const host = u.hostname.toLowerCase().replace(/\.$/, "");
  if (!host || host === "localhost" || /\.(local|internal|localhost|lan|home|corp|onion)$/.test(host)) throw new BlockedTarget("local hostnames are not allowed");
  if (host.startsWith("[") || host.includes(":")) throw new BlockedTarget("IPv6 literals are not allowed");
  const ip = v4(host);
  if (ip) {
    if (!publicV4(ip)) throw new BlockedTarget("host is a non-public address");
    throw new BlockedTarget("IP-literal hosts are not allowed; use a hostname");
  }
  if (/^[0-9.x]+$/i.test(host) || /^\d+$/.test(host)) throw new BlockedTarget("numeric host forms are not allowed");
  if (!host.includes(".")) throw new BlockedTarget("single-label hostnames are not allowed");
  return u;
}
async function safeFetch(raw, o = {}) {
  const f = o.fetchImpl ?? fetch;
  const max = o.maxBytes ?? 262144;
  let url = assertPublicUrl(raw, o.allowHttp, o.allowPrivate).href;
  const redirects = [];
  for (let hop = 0; hop <= (o.maxRedirects ?? 3); hop++) {
    const r = await f(url, {
      method: o.method ?? "GET",
      body: o.body,
      redirect: "manual",
      signal: AbortSignal.timeout(o.timeoutMs ?? 8e3),
      headers: { "user-agent": UA, accept: "application/json, text/plain;q=0.8, */*;q=0.5", ...o.headers ?? {} }
    });
    if ([301, 302, 303, 307, 308].includes(r.status)) {
      const loc = r.headers.get("location");
      try {
        await r.body?.cancel();
      } catch {
      }
      if (!loc) throw new Error("redirect without location");
      url = assertPublicUrl(new URL(loc, url).href, o.allowHttp, o.allowPrivate).href;
      redirects.push(url);
      continue;
    }
    const reader = r.body?.getReader();
    const chunks = [];
    let n = 0, truncated = false;
    if (reader) {
      for (; ; ) {
        const { done, value } = await reader.read();
        if (done) break;
        n += value.length;
        if (n > max) {
          truncated = true;
          try {
            await reader.cancel();
          } catch {
          }
          chunks.push(value.slice(0, value.length - (n - max)));
          break;
        }
        chunks.push(value);
      }
    }
    const body = new Uint8Array(chunks.reduce((a, c) => a + c.length, 0));
    let off = 0;
    for (const c of chunks) {
      body.set(c, off);
      off += c.length;
    }
    const headers = {};
    r.headers.forEach((v, k) => {
      headers[k.toLowerCase()] = v;
    });
    return { url, status: r.status, headers, body, truncated, redirects };
  }
  throw new Error("too many redirects");
}

// src/lint/directories.ts
var EPHEMERAL = /(^|\.)(trycloudflare\.com|ngrok(-free)?\.(app|io|dev)|ngrok\.io|serveo\.net|loca\.lt|localhost\.run|replit\.dev|repl\.co|pinggy\.link|tunnelmole\.net)$/i;
function oapiPathInfo(oapiText, url) {
  if (!oapiText) return { parsed: false, op: null, guidance: false };
  let d;
  try {
    d = JSON.parse(oapiText);
  } catch {
    return { parsed: false, op: null, guidance: false };
  }
  const p = d?.paths?.[url.pathname] ?? d?.paths?.[url.pathname.replace(/\/$/, "")];
  const op = p ? p.post ?? p.get ?? null : null;
  return { parsed: true, op, guidance: typeof d?.info?.["x-guidance"] === "string" && d.info["x-guidance"].length > 0 };
}
function directoryReadiness(i) {
  const u = new URL(i.url);
  const v2 = i.pr?.x402Version === 2;
  const accepts = Array.isArray(i.pr?.accepts) ? i.pr.accepts : [];
  const bz = i.pr?.extensions?.bazaar;
  const declared = String(bz?.info?.input?.method ?? "").toUpperCase();
  const desc = String(i.pr?.resource?.description ?? i.pr?.accepts?.[0]?.description ?? "");
  const oa = oapiPathInfo(i.openapiText, u);
  const xpi = oa.op?.["x-payment-info"];
  const xpiOk = !!xpi && Array.isArray(xpi.protocols) && xpi.protocols.some((p) => p && typeof p === "object" && "x402" in p);
  const wkListed = !!i.wellKnownText && i.wellKnownText.includes(u.origin + u.pathname);
  const status = (cs, pay = false) => cs.some((c) => c.ok === false) ? "not_ready" : pay ? "needs_payment" : "ready";
  const out = [];
  const dash = [
    { ok: i.getStatus === 402, text: `unpaid GET returns 402 (got ${i.getStatus ?? "no response"})` },
    { ok: accepts.length > 0, text: "402 carries a parseable accepts[] list" }
  ];
  out.push({
    directory: "x402dash",
    status: status(dash),
    checks: dash,
    source: "observed 2026-10-26: its register endpoint probes the URL with GET and rejects anything that is not a 402",
    note: "If your paid route is POST-only, also answer unpaid GET with the same 402 (never serve or settle on GET)."
  });
  const scan = [
    { ok: (i.getStatus === 402 || i.postStatus === 402) && v2 && accepts.length > 0, text: "runtime probe gets a v2 402 with accepts[]" },
    { ok: oa.parsed && xpiOk || wkListed, text: "discoverable from the origin: /openapi.json operation with x-payment-info.protocols[{x402}] or the URL listed in /.well-known/x402" },
    { ok: !!bz?.info?.input || !!oa.op?.requestBody || declared === "GET", text: "an input schema is published (bazaar info.input or an OpenAPI requestBody)" },
    { ok: oa.parsed ? oa.guidance : null, text: "OpenAPI info.x-guidance present (recommended, tells agents how to call you)" }
  ];
  out.push({
    directory: "x402scan",
    status: status(scan.filter((c) => c.text.indexOf("recommended") < 0)),
    checks: scan,
    source: "x402scan.com/resources/register docs as read 2026-10-21",
    note: "Register at https://x402scan.com/resources/register; it reads /openapi.json first and falls back to /.well-known/x402."
  });
  const the402 = [
    { ok: v2, text: "x402Version 2 challenge" },
    { ok: i.lintErrors === 0, text: `no error-level x402lint findings (${i.lintErrors})` },
    { ok: i.challengeFrom === "header", text: "challenge in the PAYMENT-REQUIRED header (v2 clients read the header)" }
  ];
  out.push({
    directory: "the402",
    status: status(the402),
    checks: the402,
    source: "observed 2026-10-25: listing runs a validator that must return verdict 'payable' for a v2 route",
    note: "A clean x402lint run is a good proxy for its validator, not a guarantee."
  });
  const bazaar = [
    { ok: !!bz, text: "extensions.bazaar present in the 402" },
    { ok: bz ? !!bz.info?.input && !!bz.info?.output : false, text: "bazaar info.input and info.output examples present" },
    { ok: bz ? !!bz.schema : false, text: "bazaar JSON schema present" },
    { ok: desc.length > 0 && desc.length <= 500, text: `resource description 1-500 chars (${desc.length})` },
    { ok: !EPHEMERAL.test(u.hostname), text: `host is not a tunnel/preview domain (${u.hostname})` },
    { ok: u.protocol === "https:", text: "https" },
    { ok: declared !== "POST" || i.getStatus === 402 || i.getStatus === 405 ? true : null, text: "GET/HEAD health probes get a 402 or 405 (PayAI hides resources after 3 failed probes in 48 h)" }
  ];
  out.push({
    directory: "Bazaar (CDP / PayAI)",
    status: status(bazaar, true),
    checks: bazaar,
    source: "docs.cdp.coinbase.com x402 Bazaar and facilitator.payai.network discovery, as read 2026-10-20",
    note: "Both Bazaars index a resource only after a real payment settles through their facilitator with the bazaar extension echoed. Run `paidpath pay` once (to your own wallet) to trigger it. CDP also needs a CDP facilitator account."
  });
  return out;
}

// src/lint/lint.ts
var F = (id, severity, message, fix, where) => ({ id, severity, message, ...fix ? { fix } : {}, ...where ? { where } : {} });
var bytesToHex = (b) => Array.from(b, (x) => x.toString(16).padStart(2, "0")).join("");
function eip55(addr) {
  const a = addr.slice(2).toLowerCase();
  const h = bytesToHex(keccak_256(enc.encode(a)));
  let out = "0x";
  for (let i = 0; i < a.length; i++) out += parseInt(h[i], 16) >= 8 ? a[i].toUpperCase() : a[i];
  return out;
}
function parsePaymentRequired(headers, body) {
  const h = headers["payment-required"];
  let headerErr;
  if (h) {
    try {
      return { pr: JSON.parse(dec.decode(b64Decode(h))), from: "header" };
    } catch {
      headerErr = "PAYMENT-REQUIRED header is present but is not base64-encoded JSON";
    }
  }
  try {
    const j = JSON.parse(dec.decode(body));
    if (j && typeof j === "object" && Array.isArray(j.accepts)) return { pr: j, from: "body", error: headerErr };
    return { pr: null, from: null, error: headerErr ?? "402 body is JSON but has no accepts[]" };
  } catch {
    return { pr: null, from: null, error: headerErr ?? "no PAYMENT-REQUIRED header and the 402 body is not JSON" };
  }
}
function lintPaymentRequired(pr, o = {}) {
  const f = [];
  const ver = pr?.x402Version;
  if (ver === 2) {
  } else if (ver === 1) f.push(F("X102", "warn", "x402Version is 1 (legacy). v2 clients expect the PAYMENT-REQUIRED header and CAIP-2 network ids.", "Serve x402Version 2 (keep v1 behind a separate path if you still need it)."));
  else f.push(F("X102", "error", `x402Version is ${JSON.stringify(ver)}; expected 2 (or 1 for legacy).`, "Set x402Version: 2."));
  if (o.from === "body" && ver === 2) f.push(F("X103", "warn", "The v2 challenge was found in the response body only, with no PAYMENT-REQUIRED header. Some v2 clients read only the header.", "Also send the base64-encoded PaymentRequired JSON in a PAYMENT-REQUIRED response header."));
  const accepts = Array.isArray(pr?.accepts) ? pr.accepts : [];
  if (!accepts.length) f.push(F("X110", "error", "accepts[] is missing or empty: a client has nothing to pay.", "List at least one payment option in accepts[]."));
  const amountKey = ver === 1 ? "maxAmountRequired" : "amount";
  const prices = [];
  const payTos = /* @__PURE__ */ new Set();
  accepts.forEach((a, i) => {
    const w = `accepts[${i}]`;
    const need = ["scheme", "network", "asset", "payTo", amountKey];
    const missing = need.filter((k) => a?.[k] === void 0 || a?.[k] === null || a?.[k] === "");
    if (missing.length) f.push(F("X110", "error", `Missing required field(s): ${missing.join(", ")}.`, ver === 1 ? "v1 uses maxAmountRequired." : "v2 uses amount (not maxAmountRequired).", w));
    if (ver === 2 && a?.maxAmountRequired !== void 0 && a?.amount === void 0) f.push(F("X110", "error", "Uses v1 field maxAmountRequired in a v2 challenge; v2 clients read amount.", "Rename to amount.", w));
    const net = String(a?.network ?? "");
    if (net) {
      if (ver === 2 && !CAIP2.test(net)) f.push(F("X111", "error", `network '${net}' is not a CAIP-2 id (e.g. eip155:8453).`, "Use CAIP-2 ids in v2.", w));
      else if (ver === 1 && !CAIP2.test(net) && !V1_NETWORKS.has(net)) f.push(F("X111", "warn", `network '${net}' is not a known v1 network name.`, void 0, w));
      if (TESTNETS.has(net)) f.push(F("X112", "warn", `network '${net}' is a testnet. Fine for staging; real agents will not pay it.`, "Offer a mainnet option before announcing.", w));
    }
    const scheme = String(a?.scheme ?? "");
    if (scheme && !["exact", "upto"].includes(scheme)) f.push(F("X117", "warn", `scheme '${scheme}' is not 'exact' or 'upto'; most clients and facilitators will not support it.`, void 0, w));
    const payTo = String(a?.payTo ?? "");
    const isEvm = net.startsWith("eip155:") || ver === 1 && !net.startsWith("solana") && net !== "solana";
    const isSol = net.startsWith("solana");
    if (payTo) {
      payTos.add(payTo.toLowerCase());
      if (isEvm) {
        if (!/^0x[0-9a-fA-F]{40}$/.test(payTo)) f.push(F("X113", "error", `payTo '${payTo}' is not a 20-byte 0x address.`, void 0, w));
        else {
          if (/^0x0{40}$/i.test(payTo) || /^0x0{39}1$/i.test(payTo) || /^0x0{36}dead$/i.test(payTo) || /^0xdead0{32}dead$/i.test(payTo)) f.push(F("X113", "error", "payTo is the zero/burn address: payments would be lost.", void 0, w));
          const body = payTo.slice(2);
          if (body !== body.toLowerCase() && body !== body.toUpperCase() && eip55(payTo) !== payTo) f.push(F("X113", "error", `payTo has mixed case but fails the EIP-55 checksum (expected ${eip55(payTo)}). Likely a typo.`, "Use the checksummed address.", w));
          if (String(a?.asset ?? "").toLowerCase() === payTo.toLowerCase()) f.push(F("X114", "error", "payTo equals the asset contract address: funds would be sent to the token contract.", void 0, w));
        }
      } else if (isSol) {
        try {
          if (base58Decode(payTo).length !== 32) throw new Error();
        } catch {
          f.push(F("X113", "error", `payTo '${payTo.slice(0, 12)}\u2026' is not a valid Solana address (base58, 32 bytes).`, void 0, w));
        }
      }
    }
    const amt = a?.[amountKey];
    const asset = String(a?.asset ?? "");
    const known = KNOWN_ASSETS.get(asset.toLowerCase());
    if (amt !== void 0 && amt !== null && amt !== "") {
      if (!/^\d+$/.test(String(amt))) f.push(F("X115", "error", `${amountKey} '${amt}' must be a non-negative integer string in the asset's smallest unit.`, 'Use e.g. "10000" for 0.01 USDC.', w));
      else if (BigInt(String(amt)) === 0n) f.push(F("X115", "warn", `${amountKey} is 0: this is a free route; no payment is needed.`, "Drop the 402 for free routes.", w));
      else if (known) {
        const usd = Number(BigInt(String(amt))) / 10 ** known.decimals;
        prices.push(`${usd} ${known.symbol}`);
        if (usd >= 5) f.push(F("X115", "info", `Price is ${usd} ${known.symbol} per call. Agents with per-call caps may refuse; consider a lower per-call price.`, void 0, w));
        if (usd < 1e-4) f.push(F("X115", "warn", `Price is ${usd} ${known.symbol}: below the point where gas/facilitator costs usually matter.`, void 0, w));
      }
    }
    if (asset) {
      if (known && known.network !== net && ver === 2) f.push(F("X116", "warn", `asset ${asset} is ${known.symbol} on ${known.network}, but network is ${net}.`, "Check the network/asset pair.", w));
      else if (!known) f.push(F("X116", "info", `asset ${asset.length > 20 ? asset.slice(0, 10) + "\u2026" : asset} is not a USDC deployment I recognise; clients must trust and support it.`, void 0, w));
    }
    if (isEvm && scheme === "exact") {
      const ex = a?.extra ?? {};
      if (!ex?.name || !ex?.version) f.push(F("X118", "error", "EVM 'exact' needs extra.name and extra.version (the token's EIP-712 domain). Without them, EIP-3009 clients cannot build the typed data to sign.", `Add "extra": {"name":"${known?.eip712?.name ?? "<token name>"}","version":"${known?.eip712?.version ?? "<token version>"}"}.`, w));
      else if (known?.eip712 && (String(ex.name) !== known.eip712.name || String(ex.version) !== known.eip712.version)) f.push(F("X118", "warn", `extra.name/version is "${ex.name}"/"${ex.version}" but this USDC's EIP-712 domain is "${known.eip712.name}"/"${known.eip712.version}". A wrong domain makes every signature fail on-chain.`, void 0, w));
    }
    const t = a?.maxTimeoutSeconds;
    if (t === void 0) f.push(F("X119", "warn", "maxTimeoutSeconds is missing.", "Set it (e.g. 60).", w));
    else if (typeof t !== "number" || !(t > 0) || t > 3600) f.push(F("X119", "warn", `maxTimeoutSeconds ${JSON.stringify(t)} looks wrong (expected 1..3600).`, void 0, w));
    else if (t < 10) f.push(F("X119", "warn", `maxTimeoutSeconds is ${t}: very short for a facilitator round trip.`, void 0, w));
  });
  if (payTos.size > 1) f.push(F("X120", "info", `accepts[] uses ${payTos.size} different payTo addresses; make sure that is intentional.`));
  if (ver === 2) {
    const res = pr?.resource;
    if (!res || typeof res !== "object") f.push(F("X130", "warn", "No resource object in the v2 challenge; clients and signed offers have nothing to bind to.", "Add resource: {url, description, mimeType}."));
    else {
      if (!res.url) f.push(F("X130", "warn", "resource.url is missing.", void 0, "resource"));
      else if (o.url) {
        try {
          const a = new URL(res.url), b = new URL(o.url);
          if (a.host !== b.host) f.push(F("X130", "warn", `resource.url host (${a.host}) differs from the requested host (${b.host}).`, void 0, "resource"));
        } catch {
          f.push(F("X130", "warn", "resource.url is not a valid URL.", void 0, "resource"));
        }
      }
      if (!res.description) f.push(F("X130", "info", "resource.description is empty: discovery catalogs show it to agents choosing what to call.", void 0, "resource"));
    }
  }
  const ext = Object.keys(pr?.extensions ?? {});
  if (!ext.includes("bazaar")) f.push(F("X131", "info", "No bazaar extension: Bazaar-style discovery catalogs may not list this endpoint (input/output schema lives there).", "Declare extensions.bazaar with an input example and output schema if you want discovery."));
  return { findings: f, summary: { x402_version: ver ?? null, accepts: accepts.length, prices, extensions: ext } };
}
var sevRank = { error: 0, warn: 1, info: 2 };
function verdictOf(f) {
  return f.some((x) => x.severity === "error") ? "fail" : f.some((x) => x.severity === "warn") ? "warn" : "ok";
}
var NOT_TESTED = ["settlement (we never pay)", "facilitator verify/settle behaviour", "that the paid response is delivered", "uptime or latency under load"];
var SCOPE = "unpaid_path_only";
var VERDICT_MEANING = "ok means the unpaid 402 challenge and discovery look well-formed to a client or directory. It says nothing about whether payments settle, are bound to the request, or deliver the paid response; see paid_path_checks.";
var PAID_PATH_CHECKS = [
  { id: "P001", name: "paid-replay", risk: "The same payment header (X-PAYMENT / PAYMENT-SIGNATURE) is accepted for more than one request: one payment, many paid responses.", how_to_test: "Pay once, then send the identical payment header a second time (ideally with a different body). A second paid 200 is a revenue leak. Key settled payments on (tx_hash, log_index) or the EIP-3009 nonce." },
  { id: "P002", name: "settle-not-called", risk: "The server asks the facilitator to verify but never calls settle: the paid 200 is served and no funds move.", how_to_test: "After one paid call, look for the USDC Transfer to your payTo on-chain (or check the PAYMENT-RESPONSE tx hash). No transfer means verify-only." },
  { id: "P003", name: "paid-200-cacheable", risk: "A paid 200 is heuristically cacheable (RFC 9111) unless it says otherwise, so a CDN or shared proxy can hand the paid body to the next unpaid caller.", how_to_test: "Check the paid response for cache-control: private, no-store; then repeat the same request without payment and confirm you get a 402, not the cached body." },
  { id: "P004", name: "paid-response-delivered", risk: "Settlement succeeds but the handler fails or times out, so the buyer pays and gets an error.", how_to_test: "Make one paid call per route and check the body against your docs; return an explicit not-charged error before settling when the work cannot be done." }
];
function openapiDoc(x) {
  if (!x?.r || x.r.status !== 200 || x.r.truncated) return null;
  try {
    const j = JSON.parse(dec.decode(x.r.body));
    return j && typeof j === "object" ? j : null;
  } catch {
    return null;
  }
}
function openapiOps(doc, pathname) {
  const paths = doc?.paths;
  if (!paths || typeof paths !== "object") return null;
  const key = Object.keys(paths).find((k) => k === pathname || k.length > 1 && pathname.endsWith(k));
  if (!key) return null;
  return new Set(Object.keys(paths[key] ?? {}).map((m) => m.toLowerCase()).filter((m) => ["get", "post", "put", "patch", "delete"].includes(m)));
}
function altAuth(doc, wkText) {
  const out = [];
  const ss = doc?.components?.securitySchemes ?? doc?.securityDefinitions;
  if (ss && typeof ss === "object") {
    for (const [name, v] of Object.entries(ss)) if (!/x402/i.test(`${name} ${v?.scheme ?? ""}`)) out.push(`${name} (${v?.type ?? "?"}${v?.in && v?.name ? `: ${v.in} ${v.name}` : v?.scheme ? `: ${v.scheme}` : ""})`);
  }
  if (wkText) {
    try {
      const w = JSON.parse(wkText);
      for (const k of Object.keys(w ?? {})) if (/^(alt_?auth|auth(entication)?|api_?keys?|credits|prepaid|alternate_?(auth|payment)s?)$/i.test(k)) out.push(`/.well-known/x402 "${k}"`);
    } catch {
    }
  }
  return [...new Set(out)].slice(0, 6);
}
async function tryFetch(url, o) {
  const t = Date.now();
  try {
    return { r: await safeFetch(url, o), ms: Date.now() - t };
  } catch (e) {
    return { ms: Date.now() - t, err: e.message.slice(0, 160) };
  }
}
async function lintEndpoint(rawUrl, o, ctx = {}) {
  const u = assertPublicUrl(rawUrl, true, ctx.allowPrivate);
  const method = o.method ?? "auto";
  const f = [];
  const base = { fetchImpl: ctx.fetchImpl, allowHttp: true, maxBytes: 262144, allowPrivate: ctx.allowPrivate };
  const post = { ...base, method: "POST", body: "{}", headers: { "content-type": "application/json" } };
  const origin = u.origin;
  const [g, p, wk, llms, oapi, pre] = await Promise.all([
    method === "POST" ? Promise.resolve(void 0) : tryFetch(u.href, { ...base, method: "GET" }),
    method === "GET" ? Promise.resolve(void 0) : tryFetch(u.href, post),
    tryFetch(origin + "/.well-known/x402", { ...base, maxBytes: 65536, maxRedirects: 1 }),
    tryFetch(origin + "/llms.txt", { ...base, maxBytes: 4096, maxRedirects: 1 }),
    tryFetch(origin + "/openapi.json", { ...base, maxBytes: 524288, maxRedirects: 1 }),
    tryFetch(u.href, { ...base, method: "OPTIONS", headers: { origin: "https://agent.example", "access-control-request-method": "POST", "access-control-request-headers": "content-type,payment-signature,x-payment" } })
  ]);
  const probes = {};
  const desc = (x) => x ? x.r ? { status: x.r.status, ms: x.ms, redirects: x.r.redirects.length } : { error: x.err, ms: x.ms } : void 0;
  if (g) probes.get = desc(g);
  if (p) probes.post = desc(p);
  const tries = [["GET", g], ["POST", p]];
  const reachable = tries.filter(([, x]) => x?.r);
  if (!reachable.length) {
    f.push(F("X001", "error", `Could not fetch the endpoint: ${g?.err ?? p?.err ?? "no response"}.`, "Check DNS/TLS and that the Worker/server answers unauthenticated requests."));
    return { url: u.href, verdict: "fail", summary: null, probes, findings: f, not_tested: NOT_TESTED, scope: SCOPE, verdict_meaning: VERDICT_MEANING, paid_path_checks: PAID_PATH_CHECKS };
  }
  const c402 = reachable.filter(([, x]) => x.r.status === 402);
  if (!c402.length) {
    f.push(F("X002", "error", `Unpaid ${reachable.map(([m, x]) => `${m} -> ${x.r.status}`).join(", ")}: no HTTP 402 challenge.`, "An unpaid request to a paid route must return 402 with the payment requirements."));
  } else if (c402.length === 1 && method === "auto") {
    const other = reachable.find(([m]) => m !== c402[0][0]);
    if (other) f.push(F("X002", "warn", `Only ${c402[0][0]} returns a 402; ${other[0]} returns ${other[1].r.status}. Some directories and probes use ${other[0]}, and will report the route as not an x402 endpoint.`, `Also serve the 402 challenge for ${other[0]} (never settle or serve paid content on it).`));
  }
  const declaredOf = (x) => {
    try {
      return String(parsePaymentRequired(x.r.headers, x.r.body).pr?.extensions?.bazaar?.info?.input?.method ?? "").toUpperCase();
    } catch {
      return "";
    }
  };
  if (c402.length === 2 && c402[0][0] === "GET" && declaredOf(c402[1][1]) === "POST" && declaredOf(c402[0][1]) !== "GET") c402.reverse();
  const [pm, pick] = c402[0] ?? reachable[0];
  const r = pick.r;
  if (r.redirects.length) f.push(F("X004", "warn", `The unpaid request was redirected ${r.redirects.length} time(s) (${r.redirects[0]}). Clients often drop the payment header or turn POST into GET on redirect.`, "Serve the 402 at the canonical URL."));
  if (r.url.startsWith("http://") || u.protocol === "http:") f.push(F("X005", "warn", "Endpoint is plain http: payment terms can be tampered with in transit.", "Serve x402 over https only."));
  if (pick.ms > 5e3) f.push(F("X008", "warn", `Slow challenge: ${pick.ms} ms.`, "A 402 should be near-instant; do the heavy work only after payment."));
  let summary = null;
  if (r.status === 402) {
    const ct = (r.headers["content-type"] ?? "").toLowerCase();
    const cc = (r.headers["cache-control"] ?? "").toLowerCase();
    if (/\b(public|max-age=[1-9])/.test(cc) || /s-maxage=[1-9]/.test(cc)) f.push(F("X007", "warn", `402 challenge is cacheable: stale challenge risk (cache-control: ${cc}). A cached 402 whose payTo or amount predates a key or price rotation still looks valid to a client that cannot tell.`, "Send cache-control: no-store on 402s; if an edge must cache, add Vary on the payment header and purge on rotation."));
    const parsed = parsePaymentRequired(r.headers, r.body);
    if (!parsed.pr) f.push(F("X101", "error", parsed.error ?? "Could not parse a PaymentRequired object.", "Return JSON with x402Version and accepts[], and/or the base64 PAYMENT-REQUIRED header."));
    else {
      if (parsed.error) f.push(F("X101", "warn", parsed.error + "; used the body instead."));
      if (parsed.from === "body" && !ct.includes("json")) f.push(F("X006", "warn", `402 body is JSON but content-type is '${ct || "missing"}'.`, "Send content-type: application/json."));
      const lr = lintPaymentRequired(parsed.pr, { url: u.href, from: parsed.from });
      f.push(...lr.findings);
      summary = { ...lr.summary, method: pm, challenge_in: parsed.from };
      const declared = String(parsed.pr?.extensions?.bazaar?.info?.input?.method ?? "").toUpperCase();
      const x2 = f.findIndex((x) => x.id === "X002" && x.severity === "warn");
      const otherSt = tries.find(([m]) => m !== pm)?.[1]?.r?.status;
      if (x2 >= 0 && declared === pm && (otherSt === 404 || otherSt === 405)) {
        f[x2] = F("X002", "info", `Only ${pm} returns a 402 (${pm === "GET" ? "POST" : "GET"} -> ${otherSt}), and the bazaar extension declares method ${pm}, so this is consistent. Probes that ignore the declaration will still miss it.`, otherSt === 404 ? `Optional: answer the other method with 405 and an Allow: ${pm} header, so a probe learns the right method instead of 'not found'.` : void 0);
      }
      const getR = tries.find(([m]) => m === "GET")?.[1]?.r;
      if (x2 >= 0 && f[x2].severity === "warn" && pm === "POST" && getR?.status === 200 && /json/i.test(getR.headers["content-type"] ?? "")) {
        const ops = openapiOps(openapiDoc(oapi), u.pathname);
        const why = declared === "POST" ? "the bazaar extension declares method POST" : ops?.has("get") && ops?.has("post") ? "openapi.json documents GET and POST as separate operations on this path" : null;
        if (why) f[x2] = F("X002", "info", `Only POST returns a 402; GET -> 200 JSON, and ${why}, so GET looks like a different REST resource on the same path (e.g. an index), not a free copy of the paid result. GET-only directory probes will still not see a 402.`, "Make sure the GET 200 never returns the paid result.");
        else f[x2] = F("X002", "warn", `${f[x2].message} If GET 200 is a different resource on the same path (a REST index), declare method POST in the bazaar extension or document both operations in openapi.json and this drops to info.`, f[x2].fix);
      }
      const other = tries.find(([m, x]) => m !== pm && x?.r?.status === 402);
      if (other) {
        const o2 = parsePaymentRequired(other[1].r.headers, other[1].r.body).pr;
        const key = (x) => JSON.stringify((x?.accepts ?? []).map((a) => [a.network, String(a.payTo).toLowerCase(), a.amount ?? a.maxAmountRequired, String(a.asset).toLowerCase()]));
        if (o2 && !!parsed.pr?.extensions?.bazaar !== !!o2?.extensions?.bazaar) f.push(F("X133", "info", `Only the ${parsed.pr?.extensions?.bazaar ? pm : other[0]} 402 carries the bazaar extension; crawlers that probe with ${parsed.pr?.extensions?.bazaar ? other[0] : pm} see no input/output schema.`, "Serve the same extensions on both 402s."));
        if (o2 && key(o2) !== key(parsed.pr)) f.push(F("X132", "warn", `GET and POST return different payment terms (network/payTo/amount/asset). Clients will see different prices depending on method.`));
      }
      const acao = r.headers["access-control-allow-origin"];
      const expose = (r.headers["access-control-expose-headers"] ?? "").toLowerCase();
      if (acao && parsed.from === "header" && !expose.includes("payment-required") && expose !== "*") f.push(F("X009", "info", "CORS is on but PAYMENT-REQUIRED is not in access-control-expose-headers: browser-based agents cannot read the header challenge.", "Add access-control-expose-headers: PAYMENT-REQUIRED, PAYMENT-RESPONSE."));
      else if (!acao) f.push(F("X009", "info", "No CORS headers on the 402: in-browser agents cannot call this route (server-side agents are unaffected)."));
      if (pre.r && acao) {
        const ah = (pre.r.headers["access-control-allow-headers"] ?? "").toLowerCase();
        if (pre.r.status >= 400 || ah && ah !== "*" && !/payment-signature|x-payment/.test(ah)) f.push(F("X009", "info", `CORS preflight (OPTIONS) ${pre.r.status >= 400 ? `returned ${pre.r.status}` : "does not allow the PAYMENT-SIGNATURE / X-PAYMENT request header"}: browser agents cannot send payment.`, "Allow PAYMENT-SIGNATURE (v2) and X-PAYMENT (v1) in access-control-allow-headers."));
      }
      if (wk.r?.status === 200) {
        const txt = dec.decode(wk.r.body).toLowerCase();
        const missing = [...new Set((parsed.pr.accepts ?? []).map((a) => String(a.payTo ?? "").toLowerCase()).filter(Boolean))].filter((x) => !txt.includes(x));
        if (missing.length && !/0x[0-9a-f]{40}/.test(txt)) f.push(F("X010", "info", "/.well-known/x402 exists but lists no payTo address, so it cannot be cross-checked against the live challenge.", void 0, "/.well-known/x402"));
        else if (missing.length) f.push(F("X010", "warn", `/.well-known/x402 exists but does not mention payTo ${missing.map((m) => m.slice(0, 10) + "\u2026").join(", ")} from the live challenge.`, "Keep the well-known file and the live challenge in sync.", "/.well-known/x402"));
        const live = new Set((parsed.pr.accepts ?? []).map((a) => String(a.payTo ?? "").toLowerCase()));
        const wkAddrs = [...new Set(txt.match(/0x[0-9a-f]{40}(?![0-9a-f])/g) ?? [])];
        const assets = /* @__PURE__ */ new Set([...KNOWN_ASSETS.keys(), ...(parsed.pr.accepts ?? []).map((a) => String(a.asset ?? "").toLowerCase())]);
        const extra = wkAddrs.filter((x) => !live.has(x) && !assets.has(x));
        if (!missing.length && extra.length) f.push(F("X010", "info", `/.well-known/x402 also lists ${extra.length} address(es) this route's challenge does not use (${extra.map((m) => m.slice(0, 10) + "\u2026").join(", ")}). Fine if other routes pay to them; stale if they predate a payTo rotation.`, "Remove retired payTo addresses from the well-known file, or say which route each belongs to.", "/.well-known/x402"));
        probes.well_known_x402 = 200;
        probes.well_known_payto = missing.length ? wkAddrs.length ? "mismatch" : "no_address" : "match";
      } else f.push(F("X010", "info", "No /.well-known/x402 (optional): a second place for agents to cross-check your payTo.", void 0, "/.well-known/x402"));
    }
  }
  const has = (x) => !!x.r && x.r.status === 200 && x.r.body.length > 20;
  probes.llms_txt = has(llms) ? 200 : llms.r?.status ?? null;
  probes.openapi_json = has(oapi) ? 200 : oapi.r?.status ?? null;
  if (!has(llms)) f.push(F("X011", "info", "No /llms.txt: agents reading docs have nothing to learn price, inputs and limits from.", void 0, "/llms.txt"));
  const alt = altAuth(openapiDoc(oapi), wk.r?.status === 200 ? dec.decode(wk.r.body) : null);
  if (alt.length) {
    probes.alt_auth = alt;
    f.push(F("X014", "info", `Documented non-x402 access: ${alt.join(", ")}. A caller holding these credentials may get 2xx with no 402 first; that is a second rail, not a missing payment path. This lint only sees the unauthenticated path.`, "Say in /.well-known/x402 or llms.txt which routes accept the alternate auth, so probes can tell 'credits path' from 'free leak'."));
  }
  if (!has(oapi)) f.push(F("X012", "info", "No /openapi.json: tools that auto-generate clients cannot see your request schema.", void 0, "/openapi.json"));
  f.sort((a, b) => sevRank[a.severity] - sevRank[b.severity]);
  let directories;
  if (o.directories) {
    const parsed402 = r.status === 402 ? parsePaymentRequired(r.headers, r.body) : { pr: null, from: null };
    directories = directoryReadiness({
      url: u.href,
      getStatus: g?.r?.status ?? null,
      postStatus: p?.r?.status ?? null,
      pr: parsed402.pr,
      challengeFrom: parsed402.from,
      lintErrors: f.filter((x) => x.severity === "error").length,
      openapiText: has(oapi) && !oapi.r.truncated ? dec.decode(oapi.r.body) : null,
      wellKnownText: wk.r?.status === 200 ? dec.decode(wk.r.body) : null
    });
  }
  return { url: u.href, verdict: verdictOf(f), summary, probes, ...directories ? { directories } : {}, counts: { error: f.filter((x) => x.severity === "error").length, warn: f.filter((x) => x.severity === "warn").length, info: f.filter((x) => x.severity === "info").length }, findings: f, not_tested: NOT_TESTED, scope: SCOPE, verdict_meaning: VERDICT_MEANING, paid_path_checks: PAID_PATH_CHECKS };
}

// src/paid.ts
import { x402Client, x402HTTPClient } from "@x402/core/client";
import { decodePaymentResponseHeader } from "@x402/core/http";
import { ExactEvmScheme } from "@x402/evm";

// src/guard.ts
var GuardRefused = class extends Error {
};
function guardSigner(account, b) {
  const state = { count: 0, total: 0n, signed: [], purpose: "payment" };
  const lc = (x) => String(x ?? "").toLowerCase();
  const signer = {
    address: account.address,
    async signTypedData(args) {
      const refuse = (why) => {
        throw new GuardRefused(`paidpath guard refused to sign: ${why}`);
      };
      if (args?.primaryType !== "TransferWithAuthorization") refuse(`primaryType ${args?.primaryType} (only TransferWithAuthorization is allowed)`);
      const d = args.domain ?? {}, m = args.message ?? {};
      if (lc(d.verifyingContract) !== lc(b.asset)) refuse(`token ${d.verifyingContract} is not the expected asset ${b.asset}`);
      if (Number(d.chainId) !== b.chainId) refuse(`chainId ${d.chainId} is not ${b.chainId}`);
      if (lc(m.from) !== lc(account.address)) refuse("authorization 'from' is not this wallet");
      if (lc(m.to) !== lc(b.payTo)) refuse(`recipient ${m.to} is not your declared payTo ${b.payTo}`);
      let v;
      try {
        v = BigInt(m.value);
      } catch {
        return refuse("value is not an integer");
      }
      if (v <= 0n) refuse("value must be positive");
      if (v > b.maxPerPayment) refuse(`value ${v} exceeds the per-payment cap ${b.maxPerPayment}`);
      if (state.count + 1 > b.maxSignatures) refuse(`signature budget used up (${b.maxSignatures})`);
      if (state.total + v > b.maxTotal) refuse(`total cap ${b.maxTotal} would be exceeded (${state.total} + ${v})`);
      state.count++;
      state.total += v;
      state.signed.push({ n: state.count, to: String(m.to), value: v.toString(), nonce: String(m.nonce), validBefore: String(m.validBefore), purpose: state.purpose });
      return account.signTypedData(args);
    }
  };
  return { signer, state };
}

// src/onchain.ts
var TRANSFER_TOPIC = "0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef";
var DEFAULT_RPCS = {
  "eip155:8453": ["https://base-rpc.publicnode.com", "https://mainnet.base.org", "https://base.llamarpc.com"],
  "eip155:84532": ["https://base-sepolia-rpc.publicnode.com", "https://sepolia.base.org"]
};
var fromTopic = (t) => "0x" + t.slice(-40);
async function rpcCall(urls, method, params, fetchImpl = fetch) {
  let last = "no RPC configured";
  for (const url of urls) {
    try {
      const r = await fetchImpl(url, { method: "POST", headers: { "content-type": "application/json", "user-agent": "paidpath/0.1" }, body: JSON.stringify({ jsonrpc: "2.0", id: 1, method, params }), signal: AbortSignal.timeout(1e4) });
      if (!r.ok) {
        last = `${url}: HTTP ${r.status}`;
        continue;
      }
      const j = await r.json();
      if (j.error) {
        last = `${url}: ${j.error.message ?? JSON.stringify(j.error)}`;
        continue;
      }
      return { result: j.result, rpc: url };
    } catch (e) {
      last = `${url}: ${e.message}`;
    }
  }
  throw new Error(`all RPCs failed for ${method}: ${last}`);
}
async function verifyTransfer(o) {
  const checks = [];
  const urls = o.rpcUrls ?? DEFAULT_RPCS[o.network] ?? [];
  const sleep = o.sleep ?? ((ms) => new Promise((r) => setTimeout(r, ms)));
  if (!/^0x[0-9a-fA-F]{64}$/.test(o.tx)) return { ok: false, checks: [{ id: "P220", ok: false, text: `transaction '${o.tx}' is not a 32-byte hash` }] };
  if (!urls.length) return { ok: false, checks: [{ id: "P220", ok: null, text: `no RPC known for ${o.network}; pass --rpc` }] };
  let receipt = null, rpc = "";
  const deadline = Date.now() + (o.waitMs ?? 6e4);
  for (; ; ) {
    try {
      const r = await rpcCall(urls, "eth_getTransactionReceipt", [o.tx], o.fetchImpl);
      receipt = r.result;
      rpc = r.rpc;
    } catch (e) {
      checks.push({ id: "P220", ok: null, text: e.message });
    }
    if (receipt || Date.now() >= deadline) break;
    await sleep(o.pollMs ?? 3e3);
  }
  if (!receipt) {
    checks.push({ id: "P220", ok: false, text: `no receipt for ${o.tx} on ${o.network} after waiting; the seller reported a transaction that the chain does not have (yet)` });
    return { ok: false, checks };
  }
  checks.push({ id: "P220", ok: true, text: `receipt found in block ${parseInt(receipt.blockNumber, 16)}` });
  checks.push({ id: "P221", ok: receipt.status === "0x1", text: `transaction status ${receipt.status === "0x1" ? "success" : "REVERTED (" + receipt.status + ")"}` });
  const transfers = (receipt.logs ?? []).filter((l) => l.topics?.[0]?.toLowerCase() === TRANSFER_TOPIC && String(l.address).toLowerCase() === o.asset.toLowerCase()).map((l) => ({ from: fromTopic(l.topics[1]), to: fromTopic(l.topics[2]), value: BigInt(l.data).toString() }));
  const match = transfers.filter((t) => t.from === o.from.toLowerCase() && t.to === o.to.toLowerCase());
  checks.push({ id: "P222", ok: match.length > 0, text: match.length ? `token Transfer ${o.from.slice(0, 8)}\u2026 -> ${o.to.slice(0, 8)}\u2026 found on ${o.asset.slice(0, 8)}\u2026` : `no Transfer from the payer to payTo on token ${o.asset} in this transaction (${transfers.length} other token transfer(s))` });
  const sum = match.reduce((a, t) => a + BigInt(t.value), 0n);
  if (match.length) checks.push({ id: "P223", ok: sum === o.amount, text: sum === o.amount ? `amount on-chain ${sum} equals the advertised amount` : `amount on-chain ${sum} differs from the advertised amount ${o.amount}` });
  let confirmations;
  try {
    const head = await rpcCall(urls, "eth_blockNumber", [], o.fetchImpl);
    confirmations = parseInt(head.result, 16) - parseInt(receipt.blockNumber, 16) + 1;
  } catch {
  }
  return { ok: checks.every((c) => c.ok !== false), checks, block: parseInt(receipt.blockNumber, 16), confirmations, transfers, rpc };
}

// src/paid.ts
var is2xx = (s) => s !== null && s >= 200 && s < 300;
var redactPayment = (hdrVal) => {
  if (!hdrVal) return void 0;
  try {
    const j = JSON.parse(Buffer.from(hdrVal, "base64").toString("utf8"));
    const p = j?.payload ?? {};
    return {
      x402Version: j.x402Version,
      accepted: j.accepted ? { network: j.accepted.network, amount: j.accepted.amount, payTo: j.accepted.payTo, asset: j.accepted.asset } : void 0,
      authorization: p.authorization,
      signature: p.signature ? `${String(p.signature).slice(0, 10)}\u2026(redacted)` : void 0
    };
  } catch {
    return { undecodable: true };
  }
};
var PlanStop = class extends Error {
};
var planAccount = (address = "0x000000000000000000000000000000000000dEaD") => ({ address, signTypedData: async () => {
  throw new PlanStop("plan only");
} });
async function runPaidTest(o) {
  const t0 = Date.now();
  const f = o.fetchImpl ?? fetch;
  const method = (o.method ?? "POST").toUpperCase();
  const network = o.network ?? "eip155:8453";
  const checks = [];
  const exchanges = [];
  const settlements = [];
  const add = (id, ok, severity, text) => checks.push({ id, ok, severity, text });
  const result = (verdict, extra = {}) => ({
    verdict,
    url: o.url,
    method,
    checks,
    settlements,
    signed: guard?.state.signed ?? [],
    exchanges,
    started_at: new Date(t0).toISOString(),
    took_ms: Date.now() - t0,
    ...extra
  });
  let guard;
  const send = async (step, extraHeaders = {}, bodyOverride) => {
    const s = Date.now();
    const headers = { "user-agent": "paidpath/0.1 (+https://github.com/something-agent/paidpath)", accept: "application/json, */*;q=0.5", ...o.body && method !== "GET" ? { "content-type": "application/json" } : {}, ...o.headers ?? {}, ...extraHeaders };
    const ex = { step, method, url: o.url, status: null, ms: 0, sent_payment: redactPayment(extraHeaders["PAYMENT-SIGNATURE"] ?? extraHeaders["X-PAYMENT"]) };
    exchanges.push(ex);
    try {
      const r = await f(o.url, { method, headers, body: method === "GET" || method === "HEAD" ? void 0 : bodyOverride ?? o.body ?? "{}", redirect: "manual", signal: AbortSignal.timeout(6e4) });
      const text = await r.text();
      ex.status = r.status;
      ex.ms = Date.now() - s;
      ex.body_bytes = Buffer.byteLength(text);
      ex.body_preview = text.slice(0, 300);
      const prh = r.headers.get("payment-response") ?? r.headers.get("x-payment-response");
      if (prh) {
        try {
          ex.payment_response = decodePaymentResponseHeader(prh);
        } catch {
          ex.payment_response = { undecodable: prh.slice(0, 40) };
        }
      }
      return { r, text, prh, ex };
    } catch (e) {
      ex.ms = Date.now() - s;
      ex.error = e.message;
      return { r: null, text: "", prh: null, ex };
    }
  };
  const u = await send("unpaid");
  if (!u.r) {
    add("P200", false, "error", `unpaid request failed: ${u.ex.error}`);
    return result("fail");
  }
  add("P200", u.r.status === 402, "error", `unpaid ${method} returns ${u.r.status}${u.r.status === 402 ? "" : " (expected 402)"}`);
  if (u.r.status !== 402) return result("fail");
  const client0 = new x402HTTPClient(new x402Client());
  let pr;
  try {
    let body;
    try {
      body = JSON.parse(u.text);
    } catch {
    }
    pr = client0.getPaymentRequiredResponse((n) => u.r.headers.get(n), body);
  } catch (e) {
    add("P200", false, "error", `could not parse the 402 with the official x402 client: ${e.message}`);
    return result("fail");
  }
  const accepts = pr.accepts ?? [];
  const req = accepts.find((a) => a.scheme === "exact" && a.network === network && String(a.payTo).toLowerCase() === o.payTo.toLowerCase());
  if (!req) {
    add("P201", false, "error", `no 'exact' requirement on ${network} pays your declared payTo ${o.payTo} (challenge offers: ${accepts.map((a) => `${a.network}->${String(a.payTo).slice(0, 10)}\u2026`).join(", ") || "nothing"}). Refusing to pay.`);
    return result("refused");
  }
  const asset = String(req.asset);
  const known = KNOWN_ASSETS.get(asset.toLowerCase());
  if (o.asset ? asset.toLowerCase() !== o.asset.toLowerCase() : !(known && known.network === network)) {
    add("P201", false, "error", `asset ${asset} is not ${o.asset ? "the asset you passed" : "the known USDC on " + network}. Refusing to pay (pass --asset to override).`);
    return result("refused");
  }
  const amount = BigInt(req.amount ?? req.maxAmountRequired);
  if (amount > o.maxAmount) {
    add("P201", false, "error", `price ${amount} base units exceeds your cap ${o.maxAmount}. Refusing to pay.`);
    return result("refused");
  }
  add("P201", true, "info", `requirement selected: ${network}, ${amount} base units of ${asset.slice(0, 10)}\u2026 to ${req.payTo}`);
  const chainId = Number(network.split(":")[1]);
  const maxSignatures = o.maxSignatures ?? (o.underpay === false ? 1 : 2) + (o.race ? 1 : 0);
  guard = guardSigner(o.account, { payTo: o.payTo, asset, chainId, maxPerPayment: o.maxAmount, maxTotal: o.maxTotal ?? amount * (o.race ? 3n : 2n), maxSignatures });
  const client = new x402Client();
  client.register(network, new ExactEvmScheme(guard.signer));
  const http = new x402HTTPClient(client);
  const only = (r) => ({ ...pr, accepts: [r] });
  let payHeaders;
  try {
    guard.state.purpose = "payment";
    payHeaders = http.encodePaymentSignatureHeader(await client.createPaymentPayload(only(req)));
  } catch (e) {
    if (e instanceof PlanStop) {
      add("P202", null, "info", `plan only: the guard would allow 1 payment authorization of ${amount} to ${req.payTo}${o.underpay === false || amount <= 1n ? "" : ` and 1 underpayment probe of ${amount - 1n} (refused by a correct seller, so it should never settle)`}${o.race ? ` and 1 race probe of ${amount} (sent twice at once; settles once, to you)` : ""}. Nothing was signed. Re-run with --yes and PAIDPATH_PRIVATE_KEY to pay.`);
      guard.state.signed = [];
      return result("plan", { network, payTo: req.payTo, amount: amount.toString(), asset });
    }
    add("P202", false, "error", `could not create the payment: ${e.message}`);
    return result(e instanceof GuardRefused ? "refused" : "fail");
  }
  const p = await send("paid", payHeaders);
  const st = p.r?.status ?? null;
  add("P203", is2xx(st) && (o.expectStatus === void 0 || st === o.expectStatus), "error", `paid request returns ${st ?? p.ex.error}${o.expectStatus ? ` (expected ${o.expectStatus})` : ""}`);
  add("P204", p.text.trim().length > 0, "error", `paid response delivers a body (${Buffer.byteLength(p.text)} bytes)`);
  if (o.expectContains !== void 0) add("P205", p.text.includes(o.expectContains), "error", `paid body contains ${JSON.stringify(o.expectContains)}`);
  const ct = p.r?.headers.get("content-type") ?? "";
  if (ct.includes("json")) {
    let okj = true;
    try {
      JSON.parse(p.text);
    } catch {
      okj = false;
    }
    add("P206", okj, "warn", `paid body parses as JSON (content-type ${ct})`);
  }
  const settle = p.ex.payment_response;
  add("P210", !!p.prh, "error", p.prh ? "PAYMENT-RESPONSE header present" : "no PAYMENT-RESPONSE (or X-PAYMENT-RESPONSE) header on the paid response: the buyer gets no receipt");
  if (settle && !settle.undecodable) {
    add("P211", settle.success === true, "error", `settlement success=${settle.success}${settle.errorReason ? ` (${settle.errorReason})` : ""}`);
    add("P212", settle.network === network, "error", `settlement network ${settle.network} ${settle.network === network ? "matches" : "differs from"} the requirement (${network})`);
    add("P213", String(settle.payer ?? "").toLowerCase() === o.account.address.toLowerCase(), "warn", `settlement payer ${settle.payer ?? "missing"} ${String(settle.payer ?? "").toLowerCase() === o.account.address.toLowerCase() ? "is" : "is not"} the paying wallet`);
    add("P214", /^0x[0-9a-fA-F]{64}$/.test(String(settle.transaction ?? "")), "error", `settlement transaction ${settle.transaction || "missing"}`);
  } else if (p.prh) add("P211", false, "error", "PAYMENT-RESPONSE header is not decodable base64 JSON");
  const tx = String(settle?.transaction ?? "");
  if (/^0x[0-9a-fA-F]{64}$/.test(tx)) {
    const rpcUrls = o.rpcUrls ?? DEFAULT_RPCS[network];
    if (rpcUrls?.length) {
      try {
        const cid = await rpcCall(rpcUrls, "eth_chainId", [], f);
        add("P224", parseInt(cid.result, 16) === chainId, "error", `RPC chain id ${parseInt(cid.result, 16)} ${parseInt(cid.result, 16) === chainId ? "matches" : "differs from"} ${network}`);
      } catch (e) {
        add("P224", null, "warn", `could not read chain id: ${e.message}`);
      }
    }
    const oc = await verifyTransfer({ tx, network, asset, from: o.account.address, to: req.payTo, amount, rpcUrls, fetchImpl: f, waitMs: o.waitMs, pollMs: o.pollMs, sleep: o.sleep });
    for (const c of oc.checks) add(c.id, c.ok, c.ok === null ? "warn" : "error", c.text);
    settlements.push({ purpose: "payment", tx, network, amount: amount.toString(), asset, from: o.account.address, to: req.payTo, block: oc.block });
  }
  let replayIdempotent = false;
  if (o.replay !== false && is2xx(st)) {
    const r = await send("replay", payHeaders);
    const rs = r.r?.status ?? null;
    const newTx = r.ex.payment_response?.transaction;
    const sameBody = r.text === p.text;
    const noNewSettle = !newTx || newTx === tx;
    if (!is2xx(rs)) add("P230", true, "error", `replayed payment header refused with ${rs ?? r.ex.error}${rs === 402 ? "" : " (402 is the clearest answer)"}. Note: a buyer whose paid response was lost (timeout, 5xx after settle) cannot recover it with this header; consider re-serving the stored response for an identical retry keyed on the authorization nonce`);
    else if (sameBody && noNewSettle) {
      replayIdempotent = true;
      add("P230", true, "warn", `replay of the identical request got ${rs} with a byte-identical body and no new settlement: idempotent re-delivery (good for lost-response retries). This is only safe if the header is bound to the request; P231 checks that`);
    } else add("P230", false, "error", `REPLAY ACCEPTED: the same payment header got ${rs} again${newTx ? ` (PAYMENT-RESPONSE tx ${newTx})` : ""}${sameBody ? "" : " with a different body"}. One payment buys more than one response.`);
    if (is2xx(rs) && newTx && newTx !== tx) settlements.push({ purpose: "replay (unexpected)", tx: newTx, network, amount: amount.toString(), asset, from: o.account.address, to: req.payTo });
  }
  if (o.replay !== false && is2xx(st)) {
    if (o.replayBody !== void 0 && method !== "GET" && method !== "HEAD") {
      const r = await send("replay-different-request", payHeaders, o.replayBody);
      const rs = r.r?.status ?? null;
      add("P231", !is2xx(rs), "error", is2xx(rs) ? `PAYMENT NOT BOUND TO THE REQUEST: the used payment header bought a different request (${rs}). One payment buys any number of different answers.` : `used payment header with a different request body refused with ${rs ?? r.ex.error}`);
      const t2 = r.ex.payment_response?.transaction;
      if (is2xx(rs) && t2 && t2 !== tx) settlements.push({ purpose: "replay with different request (unexpected)", tx: t2, network, amount: amount.toString(), asset, from: o.account.address, to: req.payTo });
    } else if (replayIdempotent) add("P231", null, "warn", "not tested: the identical replay was re-delivered, so binding to the request matters. Pass --replay-body '<a different valid request>' to check that the used header cannot buy a different answer");
  }
  if (o.race && is2xx(st)) {
    let h = null;
    try {
      guard.state.purpose = "race probe";
      h = http.encodePaymentSignatureHeader(await client.createPaymentPayload(only(req)));
    } catch (e) {
      add("P232", null, "warn", `race probe not sent: ${e.message}`);
    }
    if (h) {
      const [a1, a2] = await Promise.all([send("race-1", h), send("race-2", h)]);
      const ok2 = [a1, a2].filter((x) => is2xx(x.r?.status ?? null));
      const txs = [...new Set(ok2.map((x) => x.ex.payment_response?.transaction).filter(Boolean))];
      if (ok2.length === 2 && ok2[0].text === ok2[1].text && txs.length <= 1) add("P232", true, "warn", `both concurrent copies got 2xx with byte-identical bodies and ${txs.length ? "one settlement" : "no settlement reported"}: treated as idempotent re-delivery, not double delivery`);
      else add("P232", ok2.length <= 1, "error", ok2.length <= 1 ? `concurrent double-submit: ${ok2.length} of 2 delivered (${a1.r?.status ?? a1.ex.error} / ${a2.r?.status ?? a2.ex.error})` : `DOUBLE DELIVERY: both concurrent copies of one authorization got 2xx with different bodies; the nonce lets it settle once, so one of them was free`);
      for (const t of txs) settlements.push({ purpose: "race probe", tx: t, network, amount: amount.toString(), asset, from: o.account.address, to: req.payTo });
    }
  }
  if (o.underpay !== false && is2xx(st)) {
    if (amount <= 1n) add("P240", null, "info", "price is 1 base unit; underpayment test skipped");
    else {
      const under = { ...req, amount: (amount - 1n).toString() };
      let h = null;
      try {
        guard.state.purpose = "underpayment probe";
        h = http.encodePaymentSignatureHeader(await client.createPaymentPayload(only(under)));
      } catch (e) {
        add("P240", null, "warn", `underpayment probe not sent: ${e.message}`);
      }
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

// src/cdp.ts
var CDP_VALIDATE = "https://api.cdp.coinbase.com/platform/v2/x402/validate";
async function cdpValidate(url, method, fetchImpl = fetch) {
  const r = await fetchImpl(CDP_VALIDATE, { method: "POST", headers: { "content-type": "application/json", "user-agent": "paidpath/0.1" }, body: JSON.stringify({ resource: url, method }), signal: AbortSignal.timeout(3e4) });
  const j = await r.json().catch(() => ({}));
  const failed = [...j.preflight ?? []].filter((c) => c && c.passed === false).map((c) => `${c.check}: ${c.detail ?? ""}`);
  return { http: r.status, valid: j.valid ?? null, simulation: j.simulation?.outcome ?? null, indexed: j.index ?? null, failed_checks: failed };
}

// src/util.ts
function parseUsdc(s, decimals = 6) {
  const m = /^(\d+)(?:\.(\d+))?$/.exec(String(s).trim());
  if (!m) throw new Error(`not a decimal amount: ${s}`);
  const frac = m[2] ?? "";
  if (frac.length > decimals) throw new Error(`too many decimals in ${s} (max ${decimals})`);
  return BigInt(m[1]) * 10n ** BigInt(decimals) + BigInt((frac + "0".repeat(decimals)).slice(0, decimals) || "0");
}
var fmtUsdc = (v, decimals = 6) => {
  const b = BigInt(v);
  const s = b.toString().padStart(decimals + 1, "0");
  return `${s.slice(0, -decimals)}.${s.slice(-decimals)}`;
};
function assertNoSecret(text, secret) {
  if (!secret) return;
  const hex = secret.toLowerCase().replace(/^0x/, "");
  if (hex.length < 32) return;
  const t = text.toLowerCase();
  if (t.includes(hex) || t.includes(hex.slice(-16))) throw new Error("leak guard: output would contain key material; refusing to print or write it");
}

// src/cli.ts
var VERSION = "0.1.2";
var KEY_ENV = "PAIDPATH_PRIVATE_KEY";
var HELP = `paidpath ${VERSION}: self-test kit for x402 sellers. Test YOUR OWN paid endpoint, unpaid and paid.

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
      --expect-status <n>   --expect-contains <text>   --no-replay   --no-underpay
      --max-signatures <n> (default 2, 3 with --race)   --max-total-usdc <cap> (default 2x price, 3x with --race)
      --out <transcript.json>   --json   --allow-private

  The key is read only from the ${KEY_ENV} env var, used in-process to sign, never sent or written.
  Every signature passes a guard: only an EIP-3009 transferWithAuthorization of the expected token,
  on the expected chain, to --pay-to, within the caps. Use a test wallet with a few cents in it.
  Exit codes: 0 pass, 1 fail, 2 refused / usage error, 3 plan only.`;
function parseArgs(argv) {
  const pos = [];
  const opt = {};
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a.startsWith("--")) {
      const [k, inline] = a.slice(2).split(/=(.*)/s, 2);
      const flag = ["json", "yes", "race", "no-replay", "no-underpay", "allow-private", "cdp-validate", "help"].includes(k);
      const v = flag ? "true" : inline ?? argv[++i];
      if (v === void 0) throw new Error(`--${k} needs a value`);
      (opt[k] ??= []).push(v);
    } else pos.push(a);
  }
  return { pos, opt, one: (k) => opt[k]?.[opt[k].length - 1], has: (k) => !!opt[k] };
}
var mark = (ok) => ok === true ? "PASS" : ok === false ? "FAIL" : "----";
async function main(argv, env = process.env, out = (s) => process.stdout.write(s + "\n")) {
  const secret = env[KEY_ENV];
  const emit = (s) => {
    assertNoSecret(s, secret);
    out(s);
  };
  let a;
  try {
    a = parseArgs(argv);
  } catch (e) {
    emit(e.message);
    return 2;
  }
  const [cmd, url] = a.pos;
  if (!cmd || a.has("help") || cmd === "help") {
    emit(HELP);
    return cmd ? 0 : 2;
  }
  if (cmd === "version" || cmd === "--version") {
    emit(VERSION);
    return 0;
  }
  if (!url) {
    emit("missing <url>\n\n" + HELP);
    return 2;
  }
  if (cmd === "lint" || cmd === "dry-run") {
    const m = (a.one("method") ?? "auto").toUpperCase();
    const r = await lintEndpoint(url, { method: m === "AUTO" ? "auto" : m, directories: true }, { allowPrivate: a.has("allow-private") });
    if (a.has("cdp-validate")) {
      try {
        r.cdp_validator = await cdpValidate(url, r.summary?.method ?? (m === "GET" ? "GET" : "POST"));
      } catch (e) {
        r.cdp_validator = { error: e.message };
      }
    }
    if (a.has("json")) emit(JSON.stringify(r, null, 2));
    else {
      emit(`paidpath lint ${r.url}
unpaid verdict: ${r.verdict.toUpperCase()}  (${r.counts?.error ?? 0} error, ${r.counts?.warn ?? 0} warn, ${r.counts?.info ?? 0} info)`);
      if (r.summary) emit(`challenge: ${r.summary.method} -> 402 in ${r.summary.challenge_in}, x402 v${r.summary.x402_version ?? "?"}`);
      for (const f of r.findings) emit(`  [${f.severity}] ${f.id} ${f.message}${f.fix ? `
          fix: ${f.fix}` : ""}`);
      emit("\ndirectory readiness (what each directory was known to check; not a listing guarantee):");
      for (const d of r.directories ?? []) {
        emit(`  ${d.directory}: ${d.status.toUpperCase().replace("_", " ")}`);
        for (const c of d.checks) emit(`    ${mark(c.ok)} ${c.text}`);
        emit(`    note: ${d.note}`);
      }
      if (r.cdp_validator) emit(`
CDP validator: ${JSON.stringify(r.cdp_validator)}`);
      emit(`
not tested here: ${r.not_tested.join("; ")}. Run 'paidpath pay' for the paid path.`);
    }
    return r.verdict === "fail" ? 1 : 0;
  }
  if (cmd === "pay") {
    const payTo = a.one("pay-to");
    const cap = a.one("max-usdc");
    if (!payTo || !/^0x[0-9a-fA-F]{40}$/.test(payTo)) {
      emit("--pay-to <0x\u2026 your own receiving address> is required: paidpath only pays the address you say is yours.");
      return 2;
    }
    if (!cap) {
      emit("--max-usdc <cap per payment, e.g. 0.01> is required.");
      return 2;
    }
    let body = a.one("body");
    const bf = a.one("body-file");
    if (bf) body = readFileSync(bf, "utf8");
    const headers = {};
    for (const h of a.opt["header"] ?? []) {
      const i = h.indexOf(":");
      if (i > 0) headers[h.slice(0, i).trim()] = h.slice(i + 1).trim();
    }
    const live = a.has("yes");
    let account;
    if (live) {
      if (!secret) {
        emit(`--yes needs the ${KEY_ENV} env var (a 0x-prefixed private key of a TEST wallet).`);
        return 2;
      }
      try {
        account = privateKeyToAccount(secret.startsWith("0x") ? secret : "0x" + secret);
      } catch {
        emit(`${KEY_ENV} is not a valid private key.`);
        return 2;
      }
      if (account.address.toLowerCase() === payTo.toLowerCase()) emit("note: paying from the payTo wallet itself (the money comes straight back; the facilitator pays gas).");
    } else account = planAccount();
    let r;
    try {
      r = await runPaidTest({
        url,
        method: a.one("method") ?? "POST",
        body,
        headers,
        payTo,
        network: a.one("network"),
        asset: a.one("asset"),
        maxAmount: parseUsdc(cap),
        maxTotal: a.one("max-total-usdc") ? parseUsdc(a.one("max-total-usdc")) : void 0,
        maxSignatures: a.one("max-signatures") ? Number(a.one("max-signatures")) : void 0,
        account,
        replay: !a.has("no-replay"),
        underpay: !a.has("no-underpay"),
        replayBody: a.one("replay-body"),
        race: a.has("race"),
        expectStatus: a.one("expect-status") ? Number(a.one("expect-status")) : void 0,
        expectContains: a.one("expect-contains"),
        rpcUrls: a.opt["rpc"]
      });
    } catch (e) {
      emit(`error: ${e.message}`);
      return 1;
    }
    const transcript = JSON.stringify({ tool: `paidpath ${VERSION}`, ...r, payer: live ? account.address : void 0 }, null, 2);
    const o = a.one("out");
    if (o) {
      assertNoSecret(transcript, secret);
      writeFileSync(o, transcript + "\n");
    }
    if (a.has("json")) emit(transcript);
    else {
      emit(`paidpath pay ${r.url} (${r.method})${live ? "" : "  [PLAN ONLY: nothing signed]"}`);
      if (r.amount) emit(`price ${fmtUsdc(r.amount)} on ${r.network}, payTo ${r.payTo}`);
      for (const c of r.checks) emit(`  ${mark(c.ok)} ${c.id} ${c.text}`);
      for (const s of r.settlements) emit(`  settled (${s.purpose}): ${s.tx} ${fmtUsdc(s.amount)} ${s.from.slice(0, 8)}\u2026 -> ${s.to.slice(0, 8)}\u2026${s.block ? ` block ${s.block}` : ""}`);
      if (live) emit(`  authorizations signed: ${r.signed.length} (${r.signed.map((x) => `${x.purpose} ${fmtUsdc(x.value)}`).join(", ") || "none"})`);
      emit(`verdict: ${r.verdict.toUpperCase()}${o ? `  transcript: ${o}` : ""}`);
    }
    return r.verdict === "pass" ? 0 : r.verdict === "fail" ? 1 : r.verdict === "plan" ? 3 : 2;
  }
  emit(`unknown command '${cmd}'

` + HELP);
  return 2;
}
var isMain = process.argv[1] && /paidpath|cli\.(m?js|ts)$/.test(process.argv[1]);
if (isMain && !process.env.VITEST) main(process.argv.slice(2)).then((c) => process.exit(c), (e) => {
  console.error(`error: ${e?.message ?? e}`);
  process.exit(1);
});
export {
  VERSION,
  main
};
