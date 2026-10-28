// A signer wrapper that refuses every signature except an x402 "exact" EIP-3009 transferWithAuthorization
// to the seller's own payTo, on the expected token and chain, within a per-payment cap, a total cap and a
// signature count. It sits between the official x402 client and the key, so even a bug in the flow (or a
// hostile 402 challenge) cannot make paidpath sign anything else.
export interface Budget {
  payTo: string; asset: string; chainId: number;
  maxPerPayment: bigint; maxTotal: bigint; maxSignatures: number;
}
export interface SignedAuth { n: number; to: string; value: string; nonce: string; validBefore: string; purpose: string }
export interface GuardState { count: number; total: bigint; signed: SignedAuth[]; purpose: string }

export class GuardRefused extends Error {}

export interface MinimalAccount { address: `0x${string}`; signTypedData: (args: any) => Promise<`0x${string}`> }

export function guardSigner(account: MinimalAccount, b: Budget): { signer: MinimalAccount; state: GuardState } {
  const state: GuardState = { count: 0, total: 0n, signed: [], purpose: "payment" };
  const lc = (x: unknown) => String(x ?? "").toLowerCase();
  const signer: MinimalAccount = {
    address: account.address,
    async signTypedData(args: any) {
      const refuse = (why: string) => { throw new GuardRefused(`paidpath guard refused to sign: ${why}`); };
      if (args?.primaryType !== "TransferWithAuthorization") refuse(`primaryType ${args?.primaryType} (only TransferWithAuthorization is allowed)`);
      const d = args.domain ?? {}, m = args.message ?? {};
      if (lc(d.verifyingContract) !== lc(b.asset)) refuse(`token ${d.verifyingContract} is not the expected asset ${b.asset}`);
      if (Number(d.chainId) !== b.chainId) refuse(`chainId ${d.chainId} is not ${b.chainId}`);
      if (lc(m.from) !== lc(account.address)) refuse("authorization 'from' is not this wallet");
      if (lc(m.to) !== lc(b.payTo)) refuse(`recipient ${m.to} is not your declared payTo ${b.payTo}`);
      let v: bigint;
      try { v = BigInt(m.value); } catch { return refuse("value is not an integer"); }
      if (v <= 0n) refuse("value must be positive");
      if (v > b.maxPerPayment) refuse(`value ${v} exceeds the per-payment cap ${b.maxPerPayment}`);
      if (state.count + 1 > b.maxSignatures) refuse(`signature budget used up (${b.maxSignatures})`);
      if (state.total + v > b.maxTotal) refuse(`total cap ${b.maxTotal} would be exceeded (${state.total} + ${v})`);
      state.count++; state.total += v;
      state.signed.push({ n: state.count, to: String(m.to), value: v.toString(), nonce: String(m.nonce), validBefore: String(m.validBefore), purpose: state.purpose });
      return account.signTypedData(args);
    },
  };
  return { signer, state };
}
