// Confirms a settlement on-chain: the receipt succeeded and it contains an ERC-20 Transfer of exactly the
// expected amount, from the payer to payTo, emitted by the expected token contract on the expected chain.
export const TRANSFER_TOPIC = "0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef";
export const DEFAULT_RPCS: Record<string, string[]> = {
  "eip155:8453": ["https://base-rpc.publicnode.com", "https://mainnet.base.org", "https://base.llamarpc.com"],
  "eip155:84532": ["https://base-sepolia-rpc.publicnode.com", "https://sepolia.base.org"],
};
export interface OnchainCheck { id: string; ok: boolean | null; text: string }
export interface OnchainResult { ok: boolean; checks: OnchainCheck[]; block?: number; confirmations?: number; transfers?: { from: string; to: string; value: string }[]; rpc?: string }

const topicAddr = (a: string) => "0x" + a.toLowerCase().replace(/^0x/, "").padStart(64, "0");
const fromTopic = (t: string) => "0x" + t.slice(-40);

export async function rpcCall(urls: string[], method: string, params: unknown[], fetchImpl: typeof fetch = fetch): Promise<{ result: any; rpc: string }> {
  let last = "no RPC configured";
  for (const url of urls) {
    try {
      const r = await fetchImpl(url, { method: "POST", headers: { "content-type": "application/json", "user-agent": "paidpath/0.1" }, body: JSON.stringify({ jsonrpc: "2.0", id: 1, method, params }), signal: AbortSignal.timeout(10_000) });
      if (!r.ok) { last = `${url}: HTTP ${r.status}`; continue; }
      const j: any = await r.json();
      if (j.error) { last = `${url}: ${j.error.message ?? JSON.stringify(j.error)}`; continue; }
      return { result: j.result, rpc: url };
    } catch (e) { last = `${url}: ${(e as Error).message}`; }
  }
  throw new Error(`all RPCs failed for ${method}: ${last}`);
}

export async function verifyTransfer(o: { tx: string; network: string; asset: string; from: string; to: string; amount: bigint; rpcUrls?: string[]; fetchImpl?: typeof fetch; waitMs?: number; pollMs?: number; sleep?: (ms: number) => Promise<void> }): Promise<OnchainResult> {
  const checks: OnchainCheck[] = [];
  const urls = o.rpcUrls ?? DEFAULT_RPCS[o.network] ?? [];
  const sleep = o.sleep ?? ((ms: number) => new Promise((r) => setTimeout(r, ms)));
  if (!/^0x[0-9a-fA-F]{64}$/.test(o.tx)) return { ok: false, checks: [{ id: "P220", ok: false, text: `transaction '${o.tx}' is not a 32-byte hash` }] };
  if (!urls.length) return { ok: false, checks: [{ id: "P220", ok: null, text: `no RPC known for ${o.network}; pass --rpc` }] };
  let receipt: any = null, rpc = "";
  const deadline = Date.now() + (o.waitMs ?? 60_000);
  for (;;) {
    try { const r = await rpcCall(urls, "eth_getTransactionReceipt", [o.tx], o.fetchImpl); receipt = r.result; rpc = r.rpc; } catch (e) { checks.push({ id: "P220", ok: null, text: (e as Error).message }); }
    if (receipt || Date.now() >= deadline) break;
    await sleep(o.pollMs ?? 3000);
  }
  if (!receipt) { checks.push({ id: "P220", ok: false, text: `no receipt for ${o.tx} on ${o.network} after waiting; the seller reported a transaction that the chain does not have (yet)` }); return { ok: false, checks }; }
  checks.push({ id: "P220", ok: true, text: `receipt found in block ${parseInt(receipt.blockNumber, 16)}` });
  checks.push({ id: "P221", ok: receipt.status === "0x1", text: `transaction status ${receipt.status === "0x1" ? "success" : "REVERTED (" + receipt.status + ")"}` });
  const transfers = (receipt.logs ?? []).filter((l: any) => l.topics?.[0]?.toLowerCase() === TRANSFER_TOPIC && String(l.address).toLowerCase() === o.asset.toLowerCase())
    .map((l: any) => ({ from: fromTopic(l.topics[1]), to: fromTopic(l.topics[2]), value: BigInt(l.data).toString() }));
  const match = transfers.filter((t: any) => t.from === o.from.toLowerCase() && t.to === o.to.toLowerCase());
  checks.push({ id: "P222", ok: match.length > 0, text: match.length ? `token Transfer ${o.from.slice(0, 8)}… -> ${o.to.slice(0, 8)}… found on ${o.asset.slice(0, 8)}…` : `no Transfer from the payer to payTo on token ${o.asset} in this transaction (${transfers.length} other token transfer(s))` });
  const sum = match.reduce((a: bigint, t: any) => a + BigInt(t.value), 0n);
  if (match.length) checks.push({ id: "P223", ok: sum === o.amount, text: sum === o.amount ? `amount on-chain ${sum} equals the advertised amount` : `amount on-chain ${sum} differs from the advertised amount ${o.amount}` });
  let confirmations: number | undefined;
  try { const head = await rpcCall(urls, "eth_blockNumber", [], o.fetchImpl); confirmations = parseInt(head.result, 16) - parseInt(receipt.blockNumber, 16) + 1; } catch { /* informational */ }
  return { ok: checks.every((c) => c.ok !== false), checks, block: parseInt(receipt.blockNumber, 16), confirmations, transfers, rpc };
}
