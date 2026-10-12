# Quickstart — @fairseal/mcp-server

## Verifiable audit trails for Claude agents

Give any Claude (or other MCP) agent the ability to produce a cryptographic receipt
for its own decisions: hash the input and the decision locally, notarize the hashes,
and get back a receipt that is Merkle-batched and anchored on Base mainnet. Anyone
can later verify — offline — that this exact decision record existed at that time.
Receipts prove provenance (a given hash existed at a given time); they do not prove
the decision was correct.

### Configure (Claude Desktop)

Add to `claude_desktop_config.json`:

```json
{
  "mcpServers": {
    "fairseal": {
      "command": "npx",
      "args": ["-y", "@fairseal/mcp-server"],
      "env": {
        "FAIRSEAL_API_KEY": "your-key-here"
      }
    }
  }
}
```

No key yet? Email hello@fairseal.io. Zero-account alternative: the same endpoints
accept x402 USDC micropayments on Base with no signup — an unauthenticated request
returns HTTP 402 with machine-readable payment terms
(`https://x402.fairseal.io/.well-known/x402`).

### Three-step flow

1. **Hash the input** — `fairseal_hash_content` with the raw input the agent acted
   on. Hashing is local; the content never leaves the machine. Keep the returned
   `sha256` as `input_hash`.
2. **Hash the decision** — `fairseal_hash_content` again with the decision text.
   Keep the returned `sha256` as `decision_hash`.
3. **Notarize** — `fairseal_notarize_decision` with `agent_id`, `input_hash`,
   `decision_hash` (plus optional `session_id`, `model`, `description`,
   `operator`). Returns a receipt (`receipt_id`, `leaf_hash`, `verify_url`) that
   is batched and anchored on Base, typically within ~2 minutes.

Optional hardening: pass the receipt's `leaf_hash` to `fairseal_anchor_submit`
for an independent anchor via Anchor API v2, and poll `fairseal_anchor_status`
until `anchored` (Merkle proof + Base tx hash).

### Verify offline

Fetch the receipt with `fairseal_notarize_status` (free, no key) or
`GET https://api.fairseal.io/v1/notarize/{receipt_id}`. The response includes the
leaf formula, Merkle path, root, and the Base mainnet anchor transaction. Verify
independently with [`@fairseal/verify`](https://www.npmjs.com/package/@fairseal/verify)
or any SHA-256 + Merkle implementation — no trust in FairSeal servers required:

- `leaf_hash = SHA256(receipt_id + '||' + payload_hash)` (hex-as-text)
- Fold the Merkle path (sorted-pair SHA-256) to the root
- Check the root against the on-chain `MerkleAnchor` batch on Base

#### Verify with `@fairseal/verify` (copy-ready snippet)

```js
import { verifyAnchor } from '@fairseal/verify';

// 1. Fetch the full receipt JSON — use fairseal_notarize_status or fetch directly.
//    Poll until status === 'anchored' (typically ~2 min after notarize).
const receiptId = 'nr_...'; // receipt_id returned by fairseal_notarize_decision
const receipt = await fetch(
  `https://api.fairseal.io/v1/notarize/${receiptId}`
).then(r => r.json());

// 2. Pass the FULL receipt JSON directly — verifyAnchor handles schema detection.
const result = await verifyAnchor(receipt);
//   result.valid         → true if on-chain verified
//   result.anchored      → true when Base tx confirmed
//   result.checks        → per-check breakdown (record / merkleProof / transaction / contractState)
//   result.onChain       → { transactionStatus, blockNumber, merkleRoot, ... }

if (result.valid) {
  console.log('✅ On-chain verified', result.onChain);
} else {
  console.error('❌ Verification failed', result.errors);
}
```

> ⚠️ **Common mistake — do not spread individual fields:**
>
> ```js
> // ❌ WRONG — produces misleading "chain is missing" errors
> verifyAnchor({ receipt_id, leaf_hash, merkle_root, anchor_tx, anchor_chain });
>
> // ✅ CORRECT — pass the complete response object
> const receipt = await fetch(`https://api.fairseal.io/v1/notarize/${receiptId}`).then(r => r.json());
> verifyAnchor(receipt);
> ```
>
> `verifyAnchor` expects either:
> - A **full notarize receipt** (`schema: "agent_decision"` with a nested `proof` object) —
>   returned by `GET /v1/notarize/{id}` or `fairseal_notarize_status`.
> - A **fairseal-anchor-receipt-v1** object (`schema: "fairseal-anchor-receipt-v1"`) —
>   returned by `GET /v2/anchor/{id}/receipt`.
> - A **VEO-2 object** with an `anchor` sub-object.
>
> As of `@fairseal/verify` v0.4.1, passing flat fields returns a clear diagnostic:
> `"Input appears to be flattened fields; verifyAnchor expects the full receipt JSON..."`

## Install & run

```bash
npx @fairseal/mcp-server        # stdio transport
```

## Environment variables

| Variable | Default | Notes |
|---|---|---|
| `FAIRSEAL_API_KEY` | *(none)* | Bearer key for gated tools (entropy, stats, rng, notarize, anchor) |
| `FAIRSEAL_NOTARY_API_KEY` | falls back to `FAIRSEAL_API_KEY` | Key override for `fairseal_notarize_decision` |
| `FAIRSEAL_ANCHOR_API_KEY` | falls back to `FAIRSEAL_API_KEY` | Key override for `fairseal_anchor_submit` |
| `FAIRSEAL_API_URL` | `https://api.fairseal.io` | Upstream API base URL |
| `FAIRSEAL_X402_URL` | `https://x402.fairseal.io` | Anchor API v2 / x402 host |
| `FAIRSEAL_TIMEOUT_MS` | `15000` | Per-request timeout |

## Provably-fair games & entropy

The server also exposes FairSeal's verifiable entropy and provably-fair game tools
(sicbo, dice, gacha, slots) — see [README.md](README.md) for the full tool list.
