# @fairseal/commit

> Provably fair selections for games, loot boxes, and any randomized allocation.  
> Commit to a rule before the outcome is knowable. Verify every result trustlessly.

**No server. No account. No trust required.**

## What It Does

When your game drops loot, runs a gacha pull, or makes any randomized selection — players have no way to know it was fair. They can only trust you.

`@fairseal/commit` eliminates that trust requirement. It creates a **Committed Selection Receipt (CSR)** — cryptographic proof that:

1. Your selection rule was locked **before** the randomness existed
2. The randomness came from a **public, verifiable source** (drand beacon)
3. Anyone can **independently verify** every step

## Quick Start

```bash
npm install @fairseal/commit
```

Copy-paste runnable (Node.js ≥ 18, ESM or ts-node):

```typescript
import { createCommitment, resolveCommitment, createReceipt, verifyReceipt } from '@fairseal/commit';

// 1. Commit to your rule BEFORE the outcome is knowable
const commitment = createCommitment({
  rule: JSON.stringify({ type: 'uniform', pick: 1 }),
  inputs: ['SSR_Dragon', 'SR_Phoenix', 'R_Shield', 'N_Sword'],
  revealAfter: 10, // seconds until the beacon round
});
// commitment.commitHash is now locked — can't be changed

// 2–3. Resolve: { wait: true } polls until the beacon round is available
//    (max ~15s by default — no manual sleep needed)
const resolution = await resolveCommitment(commitment, { wait: true });
// resolution.beaconRandomness = verifiable entropy from drand
// resolution.selection        = built-in rule result (e.g. one of your inputs)

// 4. Package as a portable receipt
const receipt = createReceipt(commitment, resolution);

// 5. Anyone can verify — no trust in you required
const proof = await verifyReceipt(receipt);
console.log(proof.status, resolution.selection);
// → "PARTIAL" + your selected item
```

> **Expected:** a self-issued receipt that is **not anchored on-chain** verifies as
> `status: 'PARTIAL'` (precedence `unattested`) — the math and entropy check out, but
> timing isn't third-party provable. That is the expected result here, **not** a
> failure. Only `INVALID` means verification failed.

Prefer an explicit helper? `waitAndResolve(commitment)` ≡ `resolveCommitment(commitment, { wait: true })`.

## How Operators Integrate

**You keep your own drop-rate algorithm.** Fairseal doesn't implement your game logic — it proves your commitment was made before the outcome.

```typescript
import { createCommitment, resolveCommitment, createReceipt } from '@fairseal/commit';

// Your published loot table (legally required in many jurisdictions)
const LOOT_TABLE = {
  version: 'celestial-banner-v3.2',
  rates: { SSR: 0.006, SR: 0.051, R: 0.200, N: 0.743 },
  items: {
    SSR: ['Dragon_Blade'],
    SR: ['Phoenix_Staff', 'Thunder_Bow'],
    R: ['Iron_Shield', 'Wind_Cloak'],
    N: ['Wooden_Sword', 'Leather_Armor'],
  },
};

// Step 1: Commit to the loot table + player ID before the pull
const commitment = createCommitment({
  rule: JSON.stringify(LOOT_TABLE),        // your entire table, hashed
  inputs: [playerId, sessionId, pullNumber.toString()],
  revealAfter: 10,
});

// Step 2: Resolve (waits for the beacon round automatically)
const resolution = await resolveCommitment(commitment, { wait: true });

// Step 3: Use YOUR weighted algorithm with the verifiable entropy
const drop = yourWeightedPull(LOOT_TABLE, resolution.beaconRandomness);

// Step 4: Package receipt — player can verify everything
const receipt = createReceipt(commitment, resolution);

// Give the player: { drop, receipt }
// They can verify: the table was locked before the entropy,
// the entropy is real, and re-run your algorithm to check the drop.
```

### What the player sees

```
🎰 You pulled: ✨ SR Phoenix Staff

📜 Verification:
   Loot table committed: ✅ (locked before randomness existed)
   Randomness source:    ✅ (drand round #31034840, independently verifiable)
   Timing verified:      ⚠️  (PARTIAL — no on-chain anchor)
   
   Receipt ID: de31f0f939d2efcc...
   Verify: https://verify.fairseal.io/de31f0f939d2efcc
```

## Architecture

```
┌─────────────┐     ┌──────────────┐     ┌─────────────┐
│  Your Game   │     │    drand     │     │  Base Chain  │
│  Server      │     │  (public     │     │  (optional   │
│              │     │   beacon)    │     │   anchor)    │
│  1. Commit   │     │              │     │              │
│  2. Wait     │────▶│  3. Entropy  │     │              │
│  4. Resolve  │◀────│              │     │              │
│  5. Receipt  │     │              │     │  6. Anchor   │
└─────────────┘     └──────────────┘     └─────────────┘
       │                                        │
       │              ┌──────────┐              │
       └─────────────▶│  Player  │◀─────────────┘
                      │ (verify) │
                      └──────────┘
```

**Your game server** commits to the loot table and resolves the selection.  
**drand** provides public, verifiable randomness (League of Entropy — Cloudflare, Protocol Labs, etc.).  
**Base chain** (optional) anchors the commitment timestamp for third-party proof.  
**The player** can independently verify every step. No trust required.

## Verification Levels

| Level | What it proves | How |
|---|---|---|
| **PARTIAL** | Math is correct, entropy is real | Free — `@fairseal/commit` only |
| **VALID** | Math + entropy + timing independently proven | On-chain anchor (self-anchor or Fairseal service) |

**PARTIAL** = your players can verify the math. Good for trust-building.  
**VALID** = a third party (regulator, auditor, dispute resolver) can prove timing. Required for compliance.

**Need VALID?** On-chain anchoring (`anchorCommitment`) is coming in v0.2. In the meantime, you can self-anchor the `commitment.commitHash` to any EVM chain. The [Fairseal service](https://fairseal.io) will offer batched anchoring at ~100x lower cost.

## Use Cases

| Scenario | How CSR helps |
|---|---|
| **Gacha / loot box** | Every pull has a receipt. Players verify drops match published rates. |
| **Boss loot drops** | Drop table committed per encounter. No "ninja nerfing." |
| **Matchmaking** | Pairing algorithm committed. Players verify no favoritism. |
| **Daily rewards** | Reward distribution provably follows announced rules. |
| **Tournament brackets** | Bracket seeding provably random, not rigged. |
| **NFT minting order** | Mint queue provably fair — no insider front-running. |

## Regulatory Compliance

Drop-rate disclosure is **legally mandated** in key markets:

- 🇨🇳 China — required since 2017
- 🇹🇼 Taiwan — disclosure requirements added 2023
- 🇯🇵 Japan — kompu gacha banned outright
- 📱 Apple / Google — odds disclosure required for paid random items

**CSR closes the gap:** disclosure says what the rates *should be*; CSR proves every pull *followed* the disclosed rates.

## API Reference

### `createCommitment(opts)`

Creates a commitment bound to a future drand beacon round.

```typescript
createCommitment({
  rule: string,          // your game logic (canonical JSON) — will be hashed
  inputs: string[],      // context: player ID, session, pull number, etc.
  revealAfter: number,   // seconds until the beacon round
  beacon?: string,       // default: 'drand:quicknet'
  salt?: Uint8Array,     // random if omitted
})
```

Returns: `Commitment` with `commitHash`, `targetRound`, `ruleHash`, etc.

### `resolveCommitment(commitment, opts?)`

Fetches the beacon randomness and verifies the BLS signature.

```typescript
resolveCommitment(commitment, {
  wait?: boolean,      // poll until the target round is available (default: false — throws if early)
  maxWaitMs?: number,  // wait budget when wait=true (default: 15000)
})
```

Returns: `Resolution` with `beaconRandomness`, `verified`, `output`, etc.

### `waitAndResolve(commitment, opts?)`

Convenience wrapper for `resolveCommitment(commitment, { wait: true })`.

### `createReceipt(commitment, resolution, anchor?)`

Packages everything into a portable CSR receipt.

Returns: `CSReceipt` — JSON-serializable, independently verifiable.

### `verifyReceipt(receipt)`

Independent verification — recomputes every hash, re-fetches the beacon, checks everything.

Returns: `VerificationResult` with `status` ('VALID' | 'PARTIAL' | 'INVALID') and individual `checks`.

## Performance

Benchmarked on Apple M-series, Node.js v26. Your game won't notice.

| Operation | Time | Notes |
|---|---|---|
| Commitment creation | **0.006ms** | Local SHA-256. 170,000+/sec. |
| Beacon fetch (drand) | **~200ms** | Cloudflare CDN, global. |
| Resolve (fetch + derive) | **< 1 sec** | One HTTP call + local HMAC. |
| BLS verification | **~150ms** | Real BLS12-381 pairing check. |
| Receipt size | **0.9 KB** | Smaller than a PNG thumbnail. |

**Scale:** Client-side, no server. 10M pulls/day is just ~116 requests/sec to public drand relays. Your game server is the only bottleneck — and Fairseal won't be it.

## FAQ

**Do I need to change my game logic?**  
No. You keep your existing drop-rate algorithm. Fairseal wraps it with a commitment and verification layer.

**What if the drand beacon is down?**  
Graceful degradation — the selection is delayed, never corrupted. The library tries multiple relays (Cloudflare, Protocol Labs) with automatic failover.

**Is this free?**  
The library is free and open source. PARTIAL verification is free. For VALID (on-chain anchored) verification, you can self-anchor (~$0.01/tx) or use the Fairseal service for batched anchoring at lower cost.

**Can I use this without blockchain?**  
Yes. The library works entirely without blockchain. On-chain anchoring is optional — it's only needed for VALID (third-party provable) receipts.

## License

MIT — [Fairseal](https://fairseal.io)
