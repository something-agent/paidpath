import { describe, expect, it } from "vitest";
import { guardSigner, GuardRefused } from "../src/guard";
const USDC = "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913", ME = "0x00000000000000000000000000000000000000aA", PT = "0x209693Bc6afc0C5328bA36FaF03C514EF312287C";
const acct = { address: ME as `0x${string}`, signTypedData: async () => "0xsig" as `0x${string}` };
const budget = { payTo: PT, asset: USDC, chainId: 8453, maxPerPayment: 10000n, maxTotal: 15000n, maxSignatures: 2 };
const args = (over: any = {}, msg: any = {}) => ({ primaryType: "TransferWithAuthorization", domain: { name: "USD Coin", version: "2", chainId: 8453, verifyingContract: USDC }, message: { from: ME, to: PT, value: 10000n, validAfter: 0n, validBefore: 1n, nonce: "0x01", ...msg }, ...over });

describe("guardSigner", () => {
  it("allows the expected authorization and records it", async () => {
    const g = guardSigner(acct, budget);
    await expect(g.signer.signTypedData(args())).resolves.toBe("0xsig");
    expect(g.state.signed[0]).toMatchObject({ to: PT, value: "10000" });
  });
  const bad: [string, any][] = [
    ["other primaryType", args({ primaryType: "Permit" })],
    ["other token", args({ domain: { chainId: 8453, verifyingContract: "0x0000000000000000000000000000000000000001" } })],
    ["other chain", args({ domain: { chainId: 1, verifyingContract: USDC } })],
    ["other recipient", args({}, { to: "0x1111111111111111111111111111111111111111" })],
    ["other sender", args({}, { from: PT })],
    ["above per-payment cap", args({}, { value: 10001n })],
    ["zero value", args({}, { value: 0n })],
  ];
  for (const [name, a] of bad) it(`refuses ${name}`, async () => { const g = guardSigner(acct, budget); await expect(g.signer.signTypedData(a)).rejects.toBeInstanceOf(GuardRefused); expect(g.state.count).toBe(0); });
  it("enforces the total cap and the signature count", async () => {
    const g = guardSigner(acct, budget);
    await g.signer.signTypedData(args());
    await expect(g.signer.signTypedData(args({}, { value: 6000n }))).rejects.toThrow(/total cap/);
    await g.signer.signTypedData(args({}, { value: 5000n }));
    await expect(g.signer.signTypedData(args({}, { value: 1n }))).rejects.toThrow(/budget used up/);
  });
});
