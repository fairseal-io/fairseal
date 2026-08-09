# Fairseal 🦭

**Provably fair selections for games, loot boxes, and any randomized allocation.**

Fairseal creates verifiable receipts (CSRs) proving that a selection was committed before the outcome was knowable. Every loot drop, gacha pull, and randomized selection — independently verifiable, trustlessly.

[![@fairseal/commit](https://img.shields.io/npm/v/@fairseal/commit?label=%40fairseal%2Fcommit&color=3ecf8e)](https://www.npmjs.com/package/@fairseal/commit)
[![@fairseal/core](https://img.shields.io/npm/v/@fairseal/core?label=%40fairseal%2Fcore&color=3b82f6)](https://www.npmjs.com/package/@fairseal/core)
[![Tests](https://img.shields.io/badge/tests-32%20passing-3ecf8e)](#)

---

## Try It Now

```bash
npx @fairseal/commit
```

One command. A verifiable gacha pull in your terminal. No setup.

## Quick Start

```bash
npm install @fairseal/commit
```

```typescript
import { createCommitment, resolveCommitment, createReceipt, verifyReceipt } from '@fairseal/commit';

// 1. Lock your loot table BEFORE the outcome is knowable
const commitment = createCommitment({
  rule: JSON.stringify(LOOT_TABLE),
  inputs: [playerId, pullNumber.toString()],
  revealAfter: 10,
});

// 2. Resolve with verifiable entropy from drand
const resolution = await resolveCommitment(commitment);

// 3. Your algorithm + verifiable entropy = provably fair drop
const drop = yourWeightedPull(LOOT_TABLE, resolution.beaconRandomness);

// 4. Package as a receipt anyone can verify
const receipt = createReceipt(commitment, resolution);
const proof = await verifyReceipt(receipt); // ✅ PARTIAL
```

## How It Works

1. **Commit** — Lock your drop table + player ID into a hash before the randomness exists
2. **Entropy** — Wait for a public drand beacon round (Cloudflare + Protocol Labs)
3. **Resolve** — Derive the selection from beacon entropy + your committed rule
4. **Verify** — Anyone can re-run every step. BLS12-381 cryptographic verification. No trust required.

## Performance

| Operation | Time |
|---|---|
| Commitment creation | **0.006ms** (170,000+/sec) |
| Beacon fetch | **~200ms** |
| BLS verification | **~150ms** |
| Receipt size | **0.9 KB** |

Client-side. No server. No account. No fees for PARTIAL verification.

## Packages

| Package | Description |
|---|---|
| [`@fairseal/game`](packages/game) | **Game API for RGS studios.** Slots, gacha, loot boxes. (v0.1 ALPHA) |
| [`@fairseal/commit`](packages/commit) | Committed selection receipts. Core library. |
| [`@fairseal/core`](packages/core) | Cryptographic primitives, signing, Merkle trees. |
| [`@fairseal/verify`](packages/verify) | Independent receipt verification. |

## Use Cases

| Scenario | How |
|---|---|
| Gacha / loot box | Every pull has a receipt. Players verify drops match published rates. |
| Boss loot drops | Drop table committed per encounter. No ninja-nerfing. |
| Matchmaking | Pairing algorithm committed. Players verify no favoritism. |
| Tournament brackets | Seeding provably random, not rigged. |
| NFT mint order | Queue provably fair — no insider front-running. |
| Slot machines | Seed Commitment Model — verifiable spins, no nonce chain. |

## Links

- 🌐 [fairseal.io](https://fairseal.io) — Landing page
- 📦 [npm @fairseal](https://www.npmjs.com/org/fairseal) — All packages
- 🔍 [verify.fairseal.io](https://verify.fairseal.io) — Receipt verifier
- 📖 [@fairseal/commit README](packages/commit/README.md) — Full documentation

## License

MIT — [Fairseal](https://fairseal.io)
