# @fairseal/mcp-server

MCP (Model Context Protocol) server for [FairSeal](https://fairseal.io) — verifiable
entropy, provably-fair games, and cryptographic receipt verification for AI agents.

Wraps the live FairSeal Verifiable Entropy API (`https://api.fairseal.io`) as MCP
tools over **stdio**. Every game outcome is provably fair (commitment-before-entropy
+ VDF) and independently verifiable — offline, or at
[verify.fairseal.io](https://verify.fairseal.io).

**New in v0.2.0 — oversight tools:** any MCP agent can produce a verifiable audit
trail for its own decisions (hash locally → notarize → anchored on Base mainnet).
See [QUICKSTART.md](QUICKSTART.md).

## Install & Run

```bash
npx @fairseal/mcp-server
```

Or add to your MCP client config (Claude Desktop, etc.):

```json
{
  "mcpServers": {
    "fairseal": {
      "command": "npx",
      "args": ["-y", "@fairseal/mcp-server"]
    }
  }
}
```

## Tools

**Oversight — verifiable audit trails for agent decisions:**

| Tool | Description |
|---|---|
| `fairseal_hash_content` | SHA-256 a string **locally** (zero network calls — content never leaves the machine) |
| `fairseal_notarize_decision` | Notarize an agent decision (`POST /v1/notarize`, schema `agent_decision`) → receipt, Merkle-batched and anchored on Base mainnet — **requires `FAIRSEAL_API_KEY`** (or `FAIRSEAL_NOTARY_API_KEY`) |
| `fairseal_notarize_status` | Fetch a receipt by `receipt_id` with Merkle proof + anchor tx (free, public) |

> **Receipt delivery ≠ cryptographic verification.**
> `fairseal_notarize_decision` returns HTTP 201 with `status: "pending_anchor"` — this means
> the server accepted and queued your request. The receipt is independently verifiable **only
> after** status changes to `"anchored"` (typically ~2 min). Verify with `@fairseal/verify`
> (`verifyMerklePath` for inclusion, `verifyAnchor` for on-chain confirmation) or manually via SHA-256 + Merkle path. See [QUICKSTART.md](QUICKSTART.md).
>
> `fairseal_notarize_status` is free and key-less — use it to poll.
>
> ⚠️ **PII endpoint note:** `/v1/pii/detect` responses are NOT Merkle receipts and cannot be
> verified with `@fairseal/verify`. Only notarize and anchor endpoints produce verifiable
> Merkle receipts.

Receipts prove provenance (a hash existed at a time), not correctness of the decision.

**Read-only:**

| Tool | Description |
|---|---|
| `fairseal_entropy` | Raw verifiable entropy from the latest resolved VDF epoch — **requires `FAIRSEAL_API_KEY`** |
| `fairseal_games_catalog` | Game catalog (sicbo, dice, gacha, slots) with bet types |
| `fairseal_stats` | Entropy engine statistics — **requires `FAIRSEAL_API_KEY`** |
| `fairseal_recent_games` | Recently resolved games (find game_ids to verify) |
| `fairseal_game_result` | Poll a game result by game_id |
| `fairseal_verify_game` | Verify fairness of a completed game (VDF proof + replay steps) |

**Write (live API, play money):**

| Tool | Description |
|---|---|
| `fairseal_rng_generate` | Request raw verifiable RNG (resolves next VDF epoch, ~5s) — **requires `FAIRSEAL_API_KEY`** |
| `fairseal_sicbo_bet` | Three-dice Sic Bo bet |
| `fairseal_dice_bet` | Two-dice bet (exact/over7/under7/odd/even) |
| `fairseal_gacha_pull` | Weighted loot-box pull (standard/premium pool) |
| `fairseal_slots_spin` | 5-reel 3-row slots with wild substitution |

**Anchor API v2 (live — x402.fairseal.io):**

| Tool | Description |
|---|---|
| `fairseal_anchor_submit` | Queue a SHA-256 hash for Merkle-batch anchoring to Base mainnet — Bearer key (`FAIRSEAL_API_KEY` / `FAIRSEAL_ANCHOR_API_KEY`) or keyless x402 micropayment |
| `fairseal_anchor_status` | Anchor lifecycle by `anchor_id`: queued → batched → anchored (Merkle proof + Base tx hash). Free, public |

## Zero-key / x402 path

No API key is required to notarize. Both `/v1/notarize` and `/v2/anchor` accept
**x402 USDC micropayments** on Base mainnet instead of a Bearer key.

| Endpoint | Price | Network |
|---|---|---|
| `POST https://x402.fairseal.io/v1/notarize` | $0.02 USDC | Base (eip155:8453) |
| `POST https://x402.fairseal.io/v2/anchor` | per tier | Base (eip155:8453) |

Unauthenticated requests return HTTP 402 with a machine-readable `PAYMENT-REQUIRED`
header (x402Version 2). Use [`@x402/fetch`](https://www.npmjs.com/package/@x402/fetch)
to auto-pay on 402:

```js
import { x402Client, wrapFetchWithPayment } from "@x402/fetch";
import { ExactEvmScheme } from "@x402/evm/exact/client";
import { toClientEvmSigner } from "@x402/evm";
// (wallet setup — see full guide at https://fairseal.io/docs/notarize)

const client = new x402Client().register("eip155:8453", new ExactEvmScheme(signer));
const fetchWithPayment = wrapFetchWithPayment(fetch, client);

const res = await fetchWithPayment("https://x402.fairseal.io/v1/notarize", {
  method: "POST",
  headers: { "Content-Type": "application/json" },
  body: JSON.stringify({
    schema: "agent_decision",
    payload_hash: "<64-char sha256>",
    metadata: { agent_id: "...", decided_at: "...", input_hash: "...", decision_hash: "..." }
  })
});
// res.status === 201 → receipt
```

Inspect the 402 challenge:
```
GET https://x402.fairseal.io/.well-known/x402
```

## Configuration (env vars)

| Variable | Default | Notes |
|---|---|---|
| `FAIRSEAL_API_URL` | `https://api.fairseal.io` | Upstream API base URL |
| `FAIRSEAL_API_KEY` | *(none)* | Sent as `Authorization: Bearer` header. Required for `fairseal_entropy`, `fairseal_stats`, `fairseal_rng_generate`, `fairseal_notarize_decision`, and keyless-free use of `fairseal_anchor_submit`. No key yet? Email hello@fairseal.io or see https://fairseal.io/llms.txt. |
| `FAIRSEAL_NOTARY_API_KEY` | falls back to `FAIRSEAL_API_KEY` | Key override for the notary service |
| `FAIRSEAL_ANCHOR_API_KEY` | falls back to `FAIRSEAL_API_KEY` | Key override for Anchor API v2 |
| `FAIRSEAL_X402_URL` | `https://x402.fairseal.io` | Anchor API v2 / x402 host |
| `FAIRSEAL_TIMEOUT_MS` | `15000` | Per-request timeout |

## What FairSeal Proves

- A commitment existed **before** an externally verifiable anchor point (Base block)
- Selection outcomes are mathematically independent of operator will
- Receipts have not been modified since creation
- Randomness is authentic (VDF verified)

FairSeal issues graduated verification evidence (full taxonomy forthcoming) and is
explicit about limits: it does not prove that a claimed execution occurred or that
input data was authentic — those require attested execution / independent input
validation (future work).

## Pricing

**Pricing:** `fairseal_notarize_decision` costs $0.02 USDC per call (via x402 path) or is
covered by your API key plan. `fairseal_notarize_status`, `fairseal_anchor_status`, and all
game-read tools are free and require no key.

## AWS Bedrock AgentCore

[Amazon Bedrock AgentCore Payments](https://docs.aws.amazon.com/bedrock/latest/userguide/)
(preview, May 2026) supports x402 natively. An AgentCore agent configured with a Coinbase CDP
or Stripe Privy embedded wallet will automatically handle the 402→sign→retry loop when it
calls FairSeal's notarize endpoint — no custom middleware needed. Cost: $0.02 USDC per
notarization (Base mainnet). For setup steps and a worked example, see the integration guide
at https://fairseal.io/docs/notarize.

## Troubleshooting

**400 "path contains template placeholder":** The MCP client sent a literal `{receipt_id}`
URL instead of the actual `nr_...` value. Capture `receipt.receipt_id` from the notarize
response and pass it to `fairseal_notarize_status`.

**401/403 on notarize:** Check that `FAIRSEAL_API_KEY` or `FAIRSEAL_NOTARY_API_KEY` is set
in the MCP server `env` block (not in your shell — MCP servers run in a subprocess). Key
prefix: `fsn_`. Keys for notarize (`fsn_`) and anchor (`anck_`) are separate.

**x402 host vs API host:** Use `x402.fairseal.io` for x402 payment flows; use
`api.fairseal.io` for key-authenticated calls and free GET lookups. The MCP server
routes this automatically based on your env config.

## Links

- Website: https://fairseal.io
- Integration guide: https://fairseal.io/docs/notarize
- API: https://api.fairseal.io (OpenAPI: https://api.fairseal.io/api/v1/openapi.json)
- Receipt verifier: https://verify.fairseal.io
- npm org: https://www.npmjs.com/org/fairseal
- GitHub: https://github.com/ned-del/fairseal

## License

MIT © FairSeal
