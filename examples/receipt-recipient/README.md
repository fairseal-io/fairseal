# FairSeal Receipt Recipient — Independent Verification

**Audience:** Downstream agents, auditors, and reviewers who *received* a
FairSeal notarize receipt from an AI agent and want to verify it independently.

**Zero wallet. Zero payment. Zero trust in the FairSeal server's own `verification` block.**

---

## The Scenario

You're a downstream agent or human reviewer. An upstream AI agent (`compliance-agent-v2`,
a trading bot, a content-moderation system, …) claims it notarized a decision on FairSeal
and hands you a receipt like:

```json
{
  "receipt_id": "nr_04d7de00519cbf2b86ffa2e911ac01d8",
  "schema": "agent_decision",
  "payload_hash": "25bec1d1…af85cf14",
  "proof": { "leaf_hash": "52fc…9859", "merkle_root": "52fc…9859", ... }
}
```

**How do you know it wasn't forged?** You verify it yourself — without calling the
FairSeal notarize API, without a wallet, and without trusting the receipt's own
`verification` block (which was produced by the same server that issued the receipt).

---

## Three Independent Checks

| # | Check | Tool | What it proves |
|---|-------|------|----------------|
| 1 | **Leaf recompute** | `node:crypto` SHA256 | `payload_hash` wasn't swapped after anchoring |
| 2 | **Merkle path** | `@fairseal/verify` `verifyMerklePath` | leaf is in the committed Merkle tree |
| 3 | **On-chain anchor** | `@fairseal/verify` `verifyAnchor` | Merkle root exists on Base mainnet contract |

---

## 3-Step Quickstart

### Step 1 — Install

```bash
npm install
```

### Step 2 — Get a receipt

Use the bundled fixture (already anchored, no payment needed):

```bash
# Positive fixture — should PASS all checks
cat fixtures/receipt-real.json

# Or fetch a live receipt by ID (free endpoint, no payment)
# node verify-receipt.mjs nr_04d7de00519cbf2b86ffa2e911ac01d8
```

### Step 3 — Verify

```bash
node verify-receipt.mjs fixtures/receipt-real.json
```

Expected output (all three checks pass):

```
═══════════════════════════════════════════════════════════
 FairSeal Receipt Verification
═══════════════════════════════════════════════════════════
 Receipt ID : nr_04d7de00519cbf2b86ffa2e911ac01d8
 Status     : anchored
 Agent ID   : compliance-agent-v2
 Decided At : 2026-09-11T04:03:20.351Z
═══════════════════════════════════════════════════════════

[1] Leaf recompute ...  ✅ PASS — payload_hash is committed
[2] Merkle path ...     ✅ PASS — leaf is in committed tree
[3] On-chain anchor ... ✅ PASS — merkle_root confirmed on Base mainnet

═══════════════════════════════════════════════════════════
 ✅  VERIFIED
═══════════════════════════════════════════════════════════
```

#### Negative test — tampered receipt must fail-closed

```bash
node verify-receipt.mjs fixtures/receipt-tampered.json
# exit 1 — payload_hash mismatch detected at Check 1 & 2
```

---

## How to get receipts from a live API

You don't need to pay anything to retrieve an existing receipt:

```bash
# Free — no payment, no wallet
curl https://api.fairseal.io/v1/notarize/nr_04d7de00519cbf2b86ffa2e911ac01d8

# Or via the script directly
node verify-receipt.mjs nr_04d7de00519cbf2b86ffa2e911ac01d8
```

The receipt is only issued after the notarizing agent pays $0.02 USDC.
As a *recipient*, you verify for free.

---

## What the checks do (and don't) prove

| The receipt proves… | …does NOT prove |
|---------------------|-----------------|
| `payload_hash` existed at `created_at` | The decision was correct or ethical |
| The hash was committed to a Merkle tree | The agent's inputs were honest |
| The tree root is on Base mainnet | FairSeal validated the decision content |

FairSeal is a **timestamping witness**, not a decision auditor.
It answers "did this hash exist at this time?" — not "was this a good decision?"

---

## Leaf formula (reproduced from the receipt)

```
leaf = SHA256(receipt_id + "||" + payload_hash)
```

Both values are ASCII strings; SHA256 operates on their UTF-8 encoding and
produces a 64-char lowercase hex digest.

Merkle pairs are pair-sorted lexicographically:
```
node = SHA256(min(node, sibling) + max(node, sibling))
```

---

## Dependencies

- `@fairseal/verify` v0.4.1 — `verifyMerklePath`, `verifyAnchor` (agent_decision schema support added in v0.4.0)
- `node:crypto` — leaf recompute (built-in, no install needed)
- Node.js ≥ 18

No private key. No USDC. No wallet.

---

## Files

| File | Purpose |
|------|---------|
| `verify-receipt.mjs` | Main verification script |
| `fixtures/receipt-real.json` | Real anchored receipt (nr_04d7de00519cbf2b86ffa2e911ac01d8) |
| `fixtures/receipt-tampered.json` | Negative test — `payload_hash` changed; must FAIL |
| `run-log.txt` | Run transcript — three-check acceptance evidence |

---

## Links

- **Live verifier UI:** https://verify.fairseal.io
- **API receipt lookup:** `GET https://api.fairseal.io/v1/notarize/<receipt_id>`
- **npm package:** [@fairseal/verify](https://www.npmjs.com/package/@fairseal/verify)
- **Support:** hello@fairseal.io
