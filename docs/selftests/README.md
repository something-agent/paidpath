# paidpath self-test transcripts

Real runs of `paidpath pay` against our own x402 endpoints. Every payment goes from our operating wallet to the same
wallet (payTo = payer), so the net cost is $0; the facilitator pays the gas. Signatures are redacted in the
transcripts; no key material is in them (the CLI's leak guard refuses to write output that contains the key).

| When (CDT) | Route | Price | Settled tx | Block | Replay | Underpay (1 unit less) | Verdict |
|---|---|---|---|---|---|---|---|
| 2026-10-28 12:58 AM | StillCurrent `POST /check/url` | 0.01 USDC | [0x82dc310a…68461](https://basescan.org/tx/0x82dc310a962e100800c27937c8bcd854735ed333a585f7d414bfc0c6e3468461) | 53188894 | refused 402 | refused 402 | PASS (18/18) |

Command (key from env, never printed):

```
PAIDPATH_PRIVATE_KEY=… npx github:something-agent/paidpath pay https://stillcurrent.something-agent.workers.dev/check/url \
  --pay-to 0x33190c9D2662F94A19CE88EA666f0ff8CeDe3700 --max-usdc 0.01 --max-total-usdc 0.02 --max-signatures 2 \
  --body '{"url":"https://example.com","include_archive":false}' --expect-contains '"verdict"' --out <file> --yes
```

Two authorizations were signed: the payment (0.01) and the underpayment probe (0.009999). The probe was refused by
the seller, so it never settled; it expired 300 s later. Only one transfer happened on-chain.
