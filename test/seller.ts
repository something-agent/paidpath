// An in-process x402 v2 seller + Base RPC stub, with switchable bugs, for testing paidpath without money.
import { verifyTypedData, keccak256, toHex } from "viem";
export const USDC = "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913";
export const PAYTO = "0x209693Bc6afc0C5328bA36FaF03C514EF312287C";
export const URL_ = "https://seller.example/paid";
export const RPC = "https://rpc.test";
const b64 = (o: unknown) => Buffer.from(JSON.stringify(o)).toString("base64");
const pad = (a: string) => "0x" + a.toLowerCase().replace(/^0x/, "").padStart(64, "0");

export interface Bugs {
  acceptReplay?: boolean; acceptUnderpay?: boolean; noPaymentResponse?: boolean; emptyBody?: boolean;
  wrongNetworkInResponse?: boolean; settleTo?: string; settleAmount?: bigint; reverted?: boolean; noReceipt?: boolean;
  price?: string; payTo?: string; skipSigCheck?: boolean;
}

export function seller(bugs: Bugs = {}) {
  const price = bugs.price ?? "10000";
  const payTo = bugs.payTo ?? PAYTO;
  const req = { scheme: "exact", network: "eip155:8453", amount: price, asset: USDC, payTo, maxTimeoutSeconds: 300, extra: { name: "USD Coin", version: "2" } };
  const pr = { x402Version: 2, error: "Payment required", resource: { url: URL_, description: "test resource", mimeType: "application/json" }, accepts: [req] };
  const used = new Set<string>();
  const receipts = new Map<string, any>();
  const settled: { tx: string; value: string }[] = [];
  let calls = 0;
  const challenge = () => new Response(JSON.stringify({ error: "payment required" }), { status: 402, headers: { "content-type": "application/json", "payment-required": b64(pr) } });

  const f = (async (input: any, init?: RequestInit) => {
    const url = typeof input === "string" ? input : input.url;
    if (url === RPC) {
      const { method, params } = JSON.parse(String(init?.body));
      const out = (result: unknown) => new Response(JSON.stringify({ jsonrpc: "2.0", id: 1, result }), { headers: { "content-type": "application/json" } });
      if (method === "eth_chainId") return out("0x2105");
      if (method === "eth_blockNumber") return out("0x64");
      if (method === "eth_getTransactionReceipt") return out(bugs.noReceipt ? null : receipts.get(params[0]) ?? null);
      return out(null);
    }
    if (url !== URL_) return new Response("nf", { status: 404 });
    calls++;
    const h = new Headers(init?.headers as any);
    const sig = h.get("payment-signature");
    if (!sig) return challenge();
    const p = JSON.parse(Buffer.from(sig, "base64").toString());
    const a = p.payload.authorization;
    const strict = JSON.stringify(p.accepted) === JSON.stringify(req);
    if (!strict && !bugs.acceptUnderpay) return challenge();
    if (BigInt(a.value) < BigInt(price) && !bugs.acceptUnderpay) return challenge();
    if (a.to.toLowerCase() !== payTo.toLowerCase()) return challenge();
    if (!bugs.skipSigCheck) {
      const ok = await verifyTypedData({ address: a.from, domain: { name: "USD Coin", version: "2", chainId: 8453, verifyingContract: USDC },
        types: { TransferWithAuthorization: [{ name: "from", type: "address" }, { name: "to", type: "address" }, { name: "value", type: "uint256" }, { name: "validAfter", type: "uint256" }, { name: "validBefore", type: "uint256" }, { name: "nonce", type: "bytes32" }] },
        primaryType: "TransferWithAuthorization", message: { ...a, value: BigInt(a.value), validAfter: BigInt(a.validAfter), validBefore: BigInt(a.validBefore) }, signature: p.payload.signature });
      if (!ok) return challenge();
    }
    let tx = keccak256(a.nonce);
    if (used.has(a.nonce)) { if (!bugs.acceptReplay) return challenge(); }
    else {
      used.add(a.nonce);
      const to = bugs.settleTo ?? a.to; const value = bugs.settleAmount ?? BigInt(a.value);
      receipts.set(tx, { status: bugs.reverted ? "0x0" : "0x1", blockNumber: "0x60", logs: [{ address: USDC.toLowerCase(), topics: ["0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef", pad(a.from), pad(to)], data: toHex(value, { size: 32 }) }] });
      settled.push({ tx, value: value.toString() });
    }
    const headers: Record<string, string> = { "content-type": "application/json" };
    if (!bugs.noPaymentResponse) headers["payment-response"] = b64({ success: true, transaction: tx, network: bugs.wrongNetworkInResponse ? "eip155:1" : "eip155:8453", payer: a.from });
    return new Response(bugs.emptyBody ? "" : JSON.stringify({ result: "the paid thing" }), { status: 200, headers });
  }) as typeof fetch;
  return { f, settled, used, calls: () => calls };
}
