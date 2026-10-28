# paidpath

**A self-test kit for x402 sellers.** Run it against your *own* paid endpoint before buyers and directories do.

Most x402 checkers stop at the 402. paidpath also walks the paid path end to end, the part where real bugs cost
real money: it pays your endpoint once (to your own wallet), then checks that the payment settled, that the
receipt and the on-chain transfer match what you advertised, that the paid response is actually delivered, and
that a replayed or underpaid payment is refused.

Free, MIT, no account, no telemetry. Built by [something-agent](https://github.com/something-agent).

```
npx github:something-agent/paidpath lint https://your.api/paid-route            # no key, no payment
npx github:something-agent/paidpath pay  https://your.api/paid-route \
    --pay-to 0xYourPayTo --max-usdc 0.01 --body '{"q":"test"}'                  # plan only: shows what it would sign
PAIDPATH_PRIVATE_KEY=0x… npx github:something-agent/paidpath pay … --yes --out run.json   # the real thing
```

Node 20+. The bundled CLI is in `dist/`; no build step needed.

## `paidpath lint <url>`: the unpaid path (no key)

* **The 402 challenge**, using the same rules as the hosted [x402lint](https://github.com/something-agent/x402lint)
  (X001–X133): parseable v2 challenge, payTo/asset/amount sanity, EIP-712 domain for USDC, cacheability, CORS,
  method consistency, `/.well-known/x402` cross-check, llms.txt / OpenAPI presence.
* **Directory readiness**: what each directory was known to check before listing (sources and dates in the output):

  | Directory | What it checks |
  |---|---|
  | x402dash | its register probe is an unpaid **GET** and must get a 402 (a POST-only route is rejected) |
  | x402scan | a runtime v2 402, discovery from the origin (`/openapi.json` with `x-payment-info`, or `/.well-known/x402`), an input schema |
  | the402 | its validator must say "payable": a v2 header challenge with no errors |
  | CDP / PayAI Bazaar | `extensions.bazaar` with input/output and schema, description ≤ 500 chars, a non-tunnel https host, GET/HEAD probes answered; then **one settled payment** through their facilitator |

* `--cdp-validate` also asks Coinbase's free x402 validator (sends only the URL and method to api.cdp.coinbase.com).

"Ready" means it passes what that directory was known to check, not that it will be listed.

## `paidpath pay <url>`: the paid path

| Check | What |
|---|---|
| P200–P201 | unpaid request returns a 402; a requirement exists that pays **your** `--pay-to`, in known USDC, at or below `--max-usdc`. Otherwise it refuses before signing anything. |
| P203–P206 | the paid request returns 2xx, delivers a non-empty body (`--expect-contains`, `--expect-status`), valid JSON if it says JSON |
| P210–P214 | a `PAYMENT-RESPONSE` header: success, same network, payer is your wallet, a transaction hash |
| P220–P224 | on-chain: the receipt exists and succeeded, the token Transfer goes payer → payTo on the advertised token, for exactly the advertised amount, on the right chain |
| P230 | **replay**: the exact same payment header sent again must be refused (no new signature). A byte-identical re-delivery of the identical request with no new settlement passes as a warning (idempotent retry, good for buyers whose response was lost) and then needs P231 |
| P231 | `--replay-body`: the used payment header with a *different* request must be refused (payment bound to the request) |
| P232 | `--race` (opt-in, one extra payment to yourself): one fresh authorization sent twice at the same moment; at most one copy may deliver (catches check-then-mark windows) |
| P240 | **underpayment**: a fresh authorization for 1 base unit less must be refused |

### Safety

* The key comes only from `PAIDPATH_PRIVATE_KEY`. It is used in-process to sign and never sent anywhere. A leak guard
  refuses to print or write output containing it. Signatures are redacted in transcripts.
* Every signature goes through a **guard**: only an EIP-3009 `TransferWithAuthorization` of the expected token, on the
  expected chain, to your `--pay-to`, from your wallet, within `--max-usdc` per payment, `--max-total-usdc` in total and
  `--max-signatures` (default 2: the payment and the underpayment probe). It never signs permits, approvals or anything else.
* Without `--yes` it only plans: reads the 402 and says what it would sign.
* Use a test wallet with a few cents in it. Paying from your payTo wallet itself makes the test net $0.
* A correct seller refuses the underpayment probe, so it never settles and expires after `maxTimeoutSeconds`. If your
  seller *accepts* it, that settlement is reported (and is the bug).

## Real run

Against our own StillCurrent `POST /check/url` (0.01 USDC, wallet → same wallet) on 2026-10-28: 18/18 checks pass,
settled in [0x82dc310a…](https://basescan.org/tx/0x82dc310a962e100800c27937c8bcd854735ed333a585f7d414bfc0c6e3468461),
replay and underpayment both refused with 402. Transcript: [docs/selftests](docs/selftests/).

## Not covered (yet)

Solana and non-`exact` schemes; v1-only sellers; load, latency and uptime; whether the paid response is *correct*
(only that it is delivered and matches `--expect-contains`); facilitators other than via the seller.

## Library use

```js
import { runPaidTest, lintEndpoint, directoryReadiness, guardSigner } from "paidpath";
```

## Develop

`npm install && npm test` (79 tests; the paid path is tested against an in-process seller with switchable bugs and a
stub RPC: no money moves). `npm run build` rebuilds `dist/`.

License: MIT.
