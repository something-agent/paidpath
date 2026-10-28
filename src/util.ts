/** "0.01" -> 10000n for a 6-decimal token. Rejects more than `decimals` fractional digits. */
export function parseUsdc(s: string, decimals = 6): bigint {
  const m = /^(\d+)(?:\.(\d+))?$/.exec(String(s).trim());
  if (!m) throw new Error(`not a decimal amount: ${s}`);
  const frac = m[2] ?? "";
  if (frac.length > decimals) throw new Error(`too many decimals in ${s} (max ${decimals})`);
  return BigInt(m[1]) * 10n ** BigInt(decimals) + BigInt((frac + "0".repeat(decimals)).slice(0, decimals) || "0");
}
export const fmtUsdc = (v: bigint | string, decimals = 6) => { const b = BigInt(v); const s = b.toString().padStart(decimals + 1, "0"); return `${s.slice(0, -decimals)}.${s.slice(-decimals)}`; };

/** Throws if any recognisable form of the secret appears in the text (full hex, or its last 16 hex chars). */
export function assertNoSecret(text: string, secret: string | undefined) {
  if (!secret) return;
  const hex = secret.toLowerCase().replace(/^0x/, "");
  if (hex.length < 32) return;
  const t = text.toLowerCase();
  if (t.includes(hex) || t.includes(hex.slice(-16))) throw new Error("leak guard: output would contain key material; refusing to print or write it");
}
