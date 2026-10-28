import { describe, expect, it } from "vitest";
import { generatePrivateKey, privateKeyToAccount } from "viem/accounts";
import { runPaidTest, planAccount } from "../src/paid";
import { seller, Bugs, PAYTO, URL_, RPC } from "./seller";

const account = privateKeyToAccount(generatePrivateKey());
const run = (bugs: Bugs = {}, over: Record<string, any> = {}) => {
  const s = seller(bugs);
  return runPaidTest({ url: URL_, body: '{"q":1}', payTo: PAYTO, maxAmount: 10000n, account, fetchImpl: s.f, rpcUrls: [RPC], waitMs: 0, pollMs: 1, sleep: async () => {}, ...over }).then((r) => ({ r, s }));
};
const check = (r: any, id: string) => r.checks.find((c: any) => c.id === id);

describe("paid path against a correct seller", () => {
  it("passes every check, settles once, signs exactly two authorizations", async () => {
    const { r, s } = await run();
    expect(r.verdict).toBe("pass");
    for (const id of ["P200", "P201", "P203", "P204", "P210", "P211", "P212", "P213", "P214", "P220", "P221", "P222", "P223", "P224", "P230", "P240"]) expect(check(r, id)?.ok, id).toBe(true);
    expect(s.settled).toHaveLength(1);
    expect(r.settlements).toEqual([expect.objectContaining({ purpose: "payment", amount: "10000", to: PAYTO })]);
    expect(r.signed.map((x: any) => [x.purpose, x.value])).toEqual([["payment", "10000"], ["underpayment probe", "9999"]]);
  });
  it("redacts signatures in the transcript", async () => {
    const { r } = await run();
    const paid = r.exchanges.find((e: any) => e.step === "paid");
    expect(paid.sent_payment.signature).toMatch(/redacted/);
    expect(JSON.stringify(r)).not.toMatch(/0x[0-9a-f]{130}/i);
  });
  it("--expect-contains checks the delivered body", async () => {
    expect(check((await run({}, { expectContains: "paid thing" })).r, "P205").ok).toBe(true);
    const { r } = await run({}, { expectContains: "nope" });
    expect(check(r, "P205").ok).toBe(false); expect(r.verdict).toBe("fail");
  });
  it("can skip the replay and underpayment probes (one signature)", async () => {
    const { r } = await run({}, { replay: false, underpay: false });
    expect(check(r, "P230")).toBeUndefined(); expect(check(r, "P240")).toBeUndefined(); expect(r.signed).toHaveLength(1);
  });
});

describe("paid path catches seller bugs", () => {
  it("replay accepted", async () => { const { r } = await run({ acceptReplay: true }); expect(check(r, "P230").ok).toBe(false); expect(r.verdict).toBe("fail"); });
  it("underpayment accepted (and records the extra settlement)", async () => {
    const { r } = await run({ acceptUnderpay: true });
    expect(check(r, "P240").ok).toBe(false);
    expect(r.settlements.map((x: any) => x.amount)).toEqual(["10000", "9999"]);
  });
  it("no PAYMENT-RESPONSE header", async () => { const { r } = await run({ noPaymentResponse: true }); expect(check(r, "P210").ok).toBe(false); });
  it("empty paid body", async () => { const { r } = await run({ emptyBody: true }); expect(check(r, "P204").ok).toBe(false); });
  it("PAYMENT-RESPONSE network differs", async () => { const { r } = await run({ wrongNetworkInResponse: true }); expect(check(r, "P212").ok).toBe(false); });
  it("on-chain transfer goes elsewhere", async () => { const { r } = await run({ settleTo: "0x1111111111111111111111111111111111111111" }); expect(check(r, "P222").ok).toBe(false); });
  it("on-chain amount differs", async () => { const { r } = await run({ settleAmount: 5000n }); expect(check(r, "P223").ok).toBe(false); });
  it("reverted settlement", async () => { const { r } = await run({ reverted: true }); expect(check(r, "P221").ok).toBe(false); });
  it("reported tx not on chain", async () => { const { r } = await run({ noReceipt: true }); expect(check(r, "P220").ok).toBe(false); });
});

describe("refuses before signing", () => {
  it("payTo is not the seller's declared address", async () => {
    const { r, s } = await run({ payTo: "0x1111111111111111111111111111111111111111" });
    expect(r.verdict).toBe("refused"); expect(r.signed).toHaveLength(0); expect(s.used.size).toBe(0);
  });
  it("price above the cap", async () => { const { r } = await run({ price: "10001" }); expect(r.verdict).toBe("refused"); expect(r.signed).toHaveLength(0); });
  it("non-402 unpaid response", async () => {
    const r = await runPaidTest({ url: "https://seller.example/free", payTo: PAYTO, maxAmount: 1n, account, fetchImpl: (async () => new Response("ok")) as any });
    expect(r.verdict).toBe("fail"); expect(check(r, "P200").ok).toBe(false);
  });
  it("plan mode signs nothing and pays nothing", async () => {
    const s = seller();
    const r = await runPaidTest({ url: URL_, payTo: PAYTO, maxAmount: 10000n, account: planAccount(), fetchImpl: s.f, rpcUrls: [RPC] });
    expect(r.verdict).toBe("plan"); expect(r.signed).toHaveLength(0); expect(s.used.size).toBe(0); expect(s.calls()).toBe(1);
  });
  it("signature budget of 1 stops the underpayment probe", async () => {
    const { r, s } = await run({}, { maxSignatures: 1 });
    expect(check(r, "P240").ok).toBe(null); expect(r.signed).toHaveLength(1); expect(s.settled).toHaveLength(1);
  });
});
