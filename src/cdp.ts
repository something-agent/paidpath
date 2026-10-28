// Optional: Coinbase's free x402 validator (no key). Sends only the URL and method to api.cdp.coinbase.com.
export const CDP_VALIDATE = "https://api.cdp.coinbase.com/platform/v2/x402/validate";
export async function cdpValidate(url: string, method: string, fetchImpl: typeof fetch = fetch) {
  const r = await fetchImpl(CDP_VALIDATE, { method: "POST", headers: { "content-type": "application/json", "user-agent": "paidpath/0.1" }, body: JSON.stringify({ resource: url, method }), signal: AbortSignal.timeout(30_000) });
  const j: any = await r.json().catch(() => ({}));
  const failed = [...(j.preflight ?? [])].filter((c: any) => c && c.passed === false).map((c: any) => `${c.check}: ${c.detail ?? ""}`);
  return { http: r.status, valid: j.valid ?? null, simulation: j.simulation?.outcome ?? null, indexed: j.index ?? null, failed_checks: failed };
}
