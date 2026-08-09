# RFC-001: `@fairseal/game` — Provably Fair Game API for RGS Studios

**Status:** Draft  
**Author:** OMI (FairSeal)  
**Date:** 2026-08-09  
**Target Package:** `@fairseal/game`  
**Builds On:** `@fairseal/commit`, `@fairseal/core`, `@fairseal/verify`

---

## 1. Problem Statement

Remote Game Server (RGS) studios that want to offer **Provably Fair (PF)** games to Casino Operators face six integration challenges that the legacy seed-chain model (server_seed + sequential nonce + client_seed) cannot cleanly solve:

| # | Challenge | Root Cause in Legacy Model |
|---|-----------|---------------------------|
| 1 | Nonce desync on debit failure | Sequential nonce chain creates holes when transactions fail |
| 2 | Sub-nonce explosion (free spins, cascades) | 1 nonce per event exhausts quota; Operator ledger misaligns |
| 3 | Client seed control in iFrame | Operator vs. player ownership of client seed |
| 4 | Offline player seed reveal lifecycle | Long-lived server seed needs explicit reveal scheduling |
| 5 | API payload bloat | Every spin must return full verification data |
| 6 | GLI-19 regulatory conflict | Client seed in derivation path may violate RNG certification |

**Key insight** (from external review): Problems 1, 3, and 4 are all artifacts of the long-lived server-seed + sequential-nonce lifecycle. An epoch-based commitment model dissolves them architecturally.

### 1.1 Why Not the Legacy Model?

The legacy PF model (used by most crypto casinos today) works like this:

```
server_seed = random()
server_seed_hash = SHA256(server_seed)  → shown to player before play
result = HMAC_SHA256(server_seed, client_seed || nonce)
// After N spins or player request: reveal server_seed
```

This creates a **seed lifecycle management burden** that compounds across dozens of Operators:

- **Nonce gaps are accusation vectors.** A voided spin (debit failed) either leaves a hole in the nonce chain (player screams "吃單") or requires a published void receipt — but publishing void receipts means the RGS computed the result before deciding the bet exists, enabling selective voiding of unfavorable outcomes.
- **Seed reveal timing is fragile.** 90% of players leave after 30-50 spins. The seed remains unrevealed. Historical verification breaks.
- **Client seed ownership is ambiguous.** Operator wants to set it via URL parameter. Player wants to set it in-game. Neither trusts the other's choice.

FairSeal's Seed Commitment Model eliminates these problems by design.

---

## 2. Architecture: Seed Commitment Model (SCM)

### 2.1 Core Concept

Instead of managing a long-lived server seed with sequential nonces, FairSeal commits a **session seed** to a future drand beacon round. Once the beacon arrives (0-3 seconds), the seed is cryptographically locked. All game outcomes derive from this locked seed deterministically.

```
Session Start:
  1. RGS calls createSession({ serverSeed, clientSeed? })
  2. FairSeal commits: hash(serverSeed) → targets drand round R
  3. drand round R arrives (0-3s) → beacon randomness B is public
  4. session_seed = HMAC_SHA256(serverSeed, B || clientSeed?)
  5. session_seed is now LOCKED — neither party can change it

Each Spin:
  result = HMAC_SHA256(session_seed, spinIndex)
  → pure computation, zero latency, zero network calls

Verification:
  Player receives: session_seed, drand_round, paytable_hash
  Player recomputes: every spin result locally
  Receipt anchored: Merkle batch → on-chain (permanent)
```

### 2.2 Why This Dissolves the Six Challenges

| # | Legacy Pain | SCM Resolution |
|---|-------------|----------------|
| 1 | Nonce hole on void | No sequential chain. Voided spin = unused derivation path. `HMAC(seed, spin_42)` was never evaluated — not a gap in a chain. |
| 2 | Sub-nonce explosion | Tree derivation: `HMAC(seed, "spin:105:freespin:3")`. One master index per paid spin, unlimited sub-paths. Operator sees 1 transaction. |
| 3 | Client seed conflict | Client seed is optional input to session_seed derivation. Player can override → old session auto-closes, new session opens. No ambiguity. |
| 4 | Seed reveal lifecycle | No reveal needed. drand beacon is public the moment it's emitted. Session seed is verifiable immediately — not after 10,000 spins. |
| 5 | Payload bloat | Spin response: `{ spinIndex, resultHash }`. Full verification via `verify.fairseal.io` (stateless). Receipt = compact Merkle leaf. |
| 6 | GLI-19 conflict | Two modes (see Section 4). Mode B removes client_seed from derivation, satisfying strictest ITL interpretation. |

### 2.3 Void Handling (Critical Design Point)

In the legacy model, a voided spin creates either a nonce gap or a selective-voiding attack vector. In SCM:

- A voided spin is simply a `spinIndex` that was computed but whose transaction was not committed.
- The derivation path `HMAC(session_seed, spinIndex)` exists mathematically whether or not the bet was placed.
- The session receipt includes a `spinLog[]` array listing all committed spins with their indices. Gaps between indices are **structurally meaningless** — they're just unused derivation paths, like addresses in an HD wallet that were never funded.
- No void receipt is needed. No nonce chain is broken. The verification question is: "for each committed spin, does the result match `HMAC(session_seed, spinIndex)`?" — and the answer is deterministic.

---

## 3. API Design

### 3.1 Package Structure

```
@fairseal/game
├── session.ts      — Session lifecycle (create, spin, close)
├── derive.ts       — Deterministic result derivation
├── receipt.ts      — Receipt generation and Merkle anchoring
├── verify.ts       — Client-side verification
├── types.ts        — Type definitions
└── index.ts        — Public exports
```

### 3.2 Core Types

```typescript
interface GameSessionConfig {
  /** Mode A: full PF. Mode B: GLI-safe audit-only. */
  mode: 'provably-fair' | 'audit-only';

  /** Server-generated cryptographic seed. */
  serverSeed: string;

  /** Optional player-provided seed (Mode A only; ignored in Mode B). */
  clientSeed?: string;

  /** Beacon source. Default: 'drand:quicknet'. Use 'offline' for demos. */
  beaconId?: string;

  /** Game identifier for receipt anchoring. */
  gameId: string;

  /** Paytable hash — committed at session start for verification. */
  paytableHash: string;

  /** Session timeout in ms. Default: 30 minutes. */
  timeoutMs?: number;
}

interface GameSession {
  /** Unique session identifier. */
  sessionId: string;

  /** Locked session seed (available after beacon resolves). */
  sessionSeed: string;

  /** Commitment hash (shown to player before play). */
  commitmentHash: string;

  /** drand round used for seed locking. */
  beaconRound: number;

  /** Beacon randomness value. */
  beaconOutput: string;

  /** Active mode. */
  mode: 'provably-fair' | 'audit-only';

  /** Committed paytable hash. */
  paytableHash: string;

  /** Session state. */
  state: 'pending' | 'active' | 'closed' | 'expired';
}

interface SpinResult {
  /** Sequential spin index (0-based). */
  spinIndex: number;

  /** Raw entropy: HMAC(session_seed, derivation_path). */
  entropy: string;

  /** Derivation path used (e.g., "spin:0" or "spin:5:freespin:2"). */
  path: string;

  /** Result hash for compact API response. */
  resultHash: string;
}

interface SubResult extends SpinResult {
  /** Parent spin index. */
  parentSpinIndex: number;

  /** Sub-event type. */
  subType: 'freespin' | 'cascade' | 'respin' | 'bonus' | string;

  /** Sub-event index within parent. */
  subIndex: number;
}

interface SessionReceipt {
  /** Session metadata. */
  sessionId: string;
  gameId: string;
  mode: 'provably-fair' | 'audit-only';
  commitmentHash: string;
  beaconRound: number;
  beaconOutput: string;
  paytableHash: string;

  /** Server seed (revealed at session close). */
  serverSeed: string;

  /** Client seed (Mode A only). */
  clientSeed?: string;

  /** Ordered log of all committed spins. */
  spinLog: SpinLogEntry[];

  /** Merkle root of all spin results. */
  merkleRoot: string;

  /** On-chain anchor reference (if anchored). */
  anchor?: {
    chain: string;
    txHash: string;
    blockNumber: number;
  };
}

interface SpinLogEntry {
  spinIndex: number;
  path: string;
  resultHash: string;
  subResults?: SubResult[];
  /** Operator transaction reference (opaque to FairSeal). */
  txRef?: string;
}
```

### 3.3 Core Functions

```typescript
// ── Session Lifecycle ─────────────────────────────────────

/**
 * Create a new game session.
 * Commits serverSeed to a future drand round.
 * Returns immediately with commitmentHash (show to player).
 * Session becomes 'active' when beacon resolves (0-3s).
 */
async function createSession(config: GameSessionConfig): Promise<GameSession>;

/**
 * Wait for session to become active (beacon resolved).
 * Resolves when session_seed is locked.
 * Rejects on timeout.
 */
async function awaitSession(session: GameSession): Promise<GameSession>;

/**
 * Close a session. Reveals serverSeed.
 * Generates and returns the full session receipt.
 * Automatically called on timeout if configured.
 */
async function closeSession(session: GameSession): Promise<SessionReceipt>;

/**
 * Update client seed mid-session (Mode A only).
 * Closes current session, returns receipt, opens new session.
 * Atomic: new session inherits gameId and paytableHash.
 */
async function rotateClientSeed(
  session: GameSession,
  newClientSeed: string
): Promise<{ closedReceipt: SessionReceipt; newSession: GameSession }>;


// ── Spin Derivation ───────────────────────────────────────

/**
 * Derive a spin result from the locked session seed.
 * Pure computation — no network, no latency.
 */
function deriveSpin(session: GameSession, spinIndex: number): SpinResult;

/**
 * Derive a sub-result (free spin, cascade, bonus).
 * Path: "spin:{parentIndex}:{subType}:{subIndex}"
 */
function deriveSubResult(
  session: GameSession,
  parentSpinIndex: number,
  subType: string,
  subIndex: number
): SubResult;

/**
 * Map raw entropy to a game result (e.g., slot reel positions).
 * Generic mapper — game-specific logic lives in the RGS.
 *
 * @param entropy - 256-bit hex string from deriveSpin/deriveSubResult
 * @param range - Number of possible outcomes (e.g., symbolCount * reels)
 * @returns Deterministic integer in [0, range)
 */
function mapEntropy(entropy: string, range: number): number;


// ── Verification ──────────────────────────────────────────

/**
 * Verify a complete session receipt.
 * Re-derives all spin results and checks against receipt.
 * Runs entirely client-side — no server calls.
 */
function verifySession(receipt: SessionReceipt): VerificationResult;

interface VerificationResult {
  valid: boolean;
  sessionId: string;
  /** Per-spin verification. */
  spins: { spinIndex: number; valid: boolean; expected: string; actual: string }[];
  /** Beacon verification (drand signature check). */
  beaconValid: boolean;
  /** Merkle root verification. */
  merkleValid: boolean;
  /** Anchor verification (if anchored). */
  anchorValid?: boolean;
  /** Human-readable summary. */
  summary: string;
}
```

---

## 4. Two Modes: PF vs. GLI-Safe

### 4.1 Mode A — Provably Fair (Full Verifiability)

For crypto/Web3 Operators and unregulated markets.

```
session_seed = HMAC_SHA256(serverSeed, beaconOutput || clientSeed)
```

- `clientSeed` participates in derivation
- Player can verify: server didn't grind (seed was committed before beacon)
- Player can verify: their input influenced the seed (anti-dealer-grinding)
- Full transparency: receipt includes serverSeed, clientSeed, beaconRound

**GLI-19 compliance analysis (Mode A):**

| Section | Requirement | Mode A Status |
|---------|-------------|---------------|
| 3.2.3 | Distribution — equally likely outcomes | ✅ HMAC-SHA256 produces uniform distribution regardless of clientSeed |
| 3.2.4 | Independence — no inter-draw information | ✅ Each spin uses unique derivation path |
| 3.3.1 | Cryptographic strength | ✅ HMAC-SHA256 is NIST-approved |
| 3.3.2(a) | Direct cryptanalytic attack resistance | ✅ Infeasible to predict future outputs |
| 3.3.2(b) | Known input attack resistance | ⚠️ Player knows clientSeed (partial state knowledge). Counter: player cannot determine serverSeed or beaconOutput, so cannot estimate full RNG state. clientSeed prevents dealer grinding — net security improvement. |
| 3.4.4 | Player shall not influence physical RNG | N/A — applies to mechanical devices only |

**ITL risk:** Section 3.3.2(b) could be strictly interpreted. Pre-validate with certifying lab before pilot.

### 4.2 Mode B — GLI-Safe (Audit-Only Verifiability)

For GLI/MGA/UKGC-regulated markets.

```
session_seed = HMAC_SHA256(serverSeed, beaconOutput)
// clientSeed is NOT in the derivation path
```

- `clientSeed` is recorded as a **commitment witness** only
- Player can verify: serverSeed was committed before play (anti-tampering)
- Player can verify: beaconOutput matches the drand round (public record)
- Player **cannot** verify that their input influenced the seed (because it didn't)
- Auditor (ITL/regulator) can verify the full chain: commitment → beacon → derivation → results

**GLI-19 compliance analysis (Mode B):**

| Section | Requirement | Mode B Status |
|---------|-------------|---------------|
| 3.2.3 | Distribution | ✅ Uniform |
| 3.2.4 | Independence | ✅ Unique paths |
| 3.3.1 | Cryptographic strength | ✅ HMAC-SHA256 |
| 3.3.2(a) | Direct cryptanalytic attack | ✅ |
| 3.3.2(b) | Known input attack | ✅ Player knows nothing about serverSeed or internal state |
| 3.4.4 | Player influence | ✅ N/A (software RNG) and clientSeed doesn't enter derivation |

**Mode B satisfies the strictest possible reading of GLI-19.** No player input touches the RNG output. The verifiability story shifts from "player-verifiable" to "auditor-verifiable" — the regulator or ITL can confirm the seed commitment chain, but the player trusts the auditor's stamp rather than running verification themselves.

### 4.3 Mode Selection at Runtime

```typescript
// Crypto operator — full PF
const session = await createSession({
  mode: 'provably-fair',
  serverSeed: crypto.randomBytes(32).toString('hex'),
  clientSeed: playerProvidedSeed,
  gameId: 'sweet-bonanza-v2',
  paytableHash: 'abc123...',
});

// Regulated operator — GLI-safe
const session = await createSession({
  mode: 'audit-only',
  serverSeed: crypto.randomBytes(32).toString('hex'),
  // clientSeed omitted or ignored
  gameId: 'sweet-bonanza-v2',
  paytableHash: 'abc123...',
});
```

The API surface is identical. The only difference is whether `clientSeed` enters the `session_seed` derivation. RGS code doesn't branch — the mode is a config flag per Operator.

---

## 5. Data Flow

### 5.1 Session Lifecycle

```
┌─────────┐     ┌─────────┐     ┌──────────┐     ┌──────────┐
│  Player  │     │   RGS   │     │ FairSeal │     │  drand   │
│ (browser)│     │ (server)│     │   SDK    │     │ (beacon) │
└────┬─────┘     └────┬────┘     └────┬─────┘     └────┬─────┘
     │                │               │                 │
     │  open game     │               │                 │
     ├───────────────►│               │                 │
     │                │ createSession │                 │
     │                ├──────────────►│                 │
     │                │               │  commit(hash)   │
     │                │               │  → target round │
     │                │  commitHash   │                 │
     │                │◄──────────────┤                 │
     │  show hash     │               │                 │
     │◄───────────────┤               │                 │
     │                │               │   beacon R      │
     │                │               │◄────────────────┤
     │                │  session OK   │                 │
     │                │◄──────────────┤                 │
     │                │               │                 │
     │  spin (bet)    │               │                 │
     ├───────────────►│               │                 │
     │                │ deriveSpin(0) │                 │
     │                │──────────────►│                 │
     │                │  SpinResult   │  (pure math,    │
     │                │◄──────────────┤   no network)   │
     │                │               │                 │
     │                ├──► Operator Wallet API (debit)  │
     │                │◄── 200 OK                       │
     │                │               │                 │
     │  result + hash │               │                 │
     │◄───────────────┤               │                 │
     │                │               │                 │
     │  ... N spins ...               │                 │
     │                │               │                 │
     │  close / leave │               │                 │
     ├───────────────►│               │                 │
     │                │ closeSession  │                 │
     │                ├──────────────►│                 │
     │                │  receipt      │                 │
     │                │◄──────────────┤                 │
     │  receipt link  │               │                 │
     │◄───────────────┤               │  (Merkle batch  │
     │                │               │   → on-chain)   │
     │                │               │                 │
     │  verify.fairseal.io            │                 │
     ├────────────────────────────────┼──── (client-    │
     │   (re-derive all spins         │     side only)  │
     │    from receipt data)          │                 │
```

### 5.2 Spin API Response (Compact)

What the RGS returns to the player per spin:

```json
{
  "spinIndex": 7,
  "resultHash": "a3f2...",
  "symbols": [[2,0,1,3,4],[1,2,0,4,3],[0,3,2,1,4]],
  "winAmount": 250,
  "subResults": [
    { "type": "freespin", "index": 0, "resultHash": "b7e1..." },
    { "type": "freespin", "index": 1, "resultHash": "c4d9..." }
  ]
}
```

No `server_seed_hash`, no `nonce`, no `combined_hash`, no mapping history. Just the result hash. Full verification happens post-session via the receipt.

### 5.3 Free Spin / Cascade Derivation Tree

```
Paid Spin (spinIndex: 5)
├── entropy: HMAC(session_seed, "spin:5")
├── triggers 3 free spins:
│   ├── HMAC(session_seed, "spin:5:freespin:0")
│   ├── HMAC(session_seed, "spin:5:freespin:1")
│   └── HMAC(session_seed, "spin:5:freespin:2")
│       └── triggers cascade:
│           ├── HMAC(session_seed, "spin:5:freespin:2:cascade:0")
│           └── HMAC(session_seed, "spin:5:freespin:2:cascade:1")
```

All derivations are deterministic from `session_seed`. The receipt includes the full tree. Verification re-derives every leaf.

---

## 6. Client Seed Lifecycle (Mode A Only)

### 6.1 Setting the Client Seed

Three options, in order of trust:

1. **Player-provided (highest trust):** Player types a seed in the PF control panel within the game iFrame. FairSeal SDK generates a default if player doesn't provide one.

2. **Operator-provided (default):** Operator passes a seed via URL parameter or API. Player can override at any time.

3. **Auto-generated (fallback):** If neither player nor Operator provides a seed, the SDK generates a random client seed and displays it to the player.

### 6.2 Changing the Client Seed Mid-Session

```typescript
// Player clicks "Change Seed" in PF panel
const { closedReceipt, newSession } = await rotateClientSeed(
  currentSession,
  newPlayerSeed
);

// closedReceipt: reveals server_seed for spins 0-47
// newSession: new commitment, new server_seed, new beacon round
//             player's new seed is in the derivation
```

This is atomic:
- Old session closes → receipt generated → server_seed revealed
- New session opens → new commitment → new beacon round (0-3s wait)
- No gap in play continuity from the Operator's perspective

### 6.3 No Reveal Scheduling Problem

In the legacy model, the server seed is revealed after N spins or on player request, creating a lifecycle management burden.

In SCM, the `serverSeed` is revealed at session close — which happens on:
- Player leaves (navigates away, closes tab)
- Player changes client seed (see 6.2)
- Session timeout (default: 30 minutes of inactivity)
- Player explicitly requests verification

There is no "wait for 10,000 spins" scenario. Sessions are naturally short (30-50 spins typical).

---

## 7. Session Lifecycle Management

### 7.1 Session States

```
pending  → Commitment sent, waiting for drand beacon
active   → Beacon resolved, session_seed locked, spins allowed
closed   → Session ended, receipt generated, serverSeed revealed
expired  → Timeout reached, auto-closed
```

### 7.2 Disconnect / Reconnect

If a player disconnects and reconnects:

1. **Within timeout window:** RGS looks up the active session. Session is still `active`. Player resumes spinning from the next `spinIndex`. No new commitment needed.

2. **After timeout:** Session auto-closed to `expired`. Receipt generated. Player starts a new session on reconnect. Previous session's receipt is available via history API.

### 7.3 History API

```typescript
/**
 * Get historical session receipts for a player.
 * Operator integrates this into their "Bet History" UI.
 */
async function getSessionHistory(
  playerId: string,
  options?: { limit?: number; before?: Date }
): Promise<SessionReceipt[]>;
```

This replaces the legacy `GET /v1/pf/history` pattern. Receipts are durable (Merkle-anchored), not cached.

---

## 8. Verification Architecture

### 8.1 Client-Side Verification

All verification runs in the player's browser. No server calls needed.

```typescript
import { verifySession } from '@fairseal/game';

const receipt = /* loaded from verify.fairseal.io or Operator's bet history */;
const result = verifySession(receipt);

console.log(result.valid);        // true
console.log(result.beaconValid);  // true (drand signature verified)
console.log(result.merkleValid);  // true (Merkle root matches)
console.log(result.summary);
// "Session abc123: 47 spins verified. All results match.
//  Beacon: drand round 1284723 (verified BLS signature).
//  Merkle root: anchored on Base block 18273645."
```

### 8.2 Verification Page

`verify.fairseal.io/session/{sessionId}` — hosted, open-source verification page.

- Loads receipt data from Merkle anchor (on-chain) or IPFS fallback
- Re-derives every spin result client-side
- Verifies drand beacon signature (BLS12-381)
- Shows full derivation tree with expand/collapse for sub-results
- No server trust required — all math happens in the browser

### 8.3 Anchoring

Receipts are batched and anchored via `@fairseal/commit`'s existing Merkle infrastructure:

```
Receipt₁ ─┐
Receipt₂ ─┼─► Merkle Tree ─► Root Hash ─► Base L2 (or configured chain)
Receipt₃ ─┘
```

Batching interval: configurable (default: every 100 receipts or 5 minutes, whichever comes first).

---

## 9. Integration Example: 5-Reel Slot

```typescript
import { createSession, awaitSession, deriveSpin, deriveSubResult, mapEntropy, closeSession } from '@fairseal/game';
import crypto from 'crypto';

// ── Setup ──────────────────────────────────────────
const SYMBOLS = ['cherry', 'lemon', 'bar', 'seven', 'wild'];
const REELS = 5;
const ROWS = 3;

// Paytable hash — committed so player can verify the game rules didn't change
const paytableHash = crypto.createHash('sha256')
  .update(JSON.stringify(PAYTABLE))
  .digest('hex');

// ── Session Start ──────────────────────────────────
const session = await createSession({
  mode: 'provably-fair',
  serverSeed: crypto.randomBytes(32).toString('hex'),
  clientSeed: 'player-chosen-seed-123',
  gameId: 'fruit-frenzy-v1',
  paytableHash,
});

// Show commitment hash to player BEFORE play begins
showToPlayer(session.commitmentHash);

// Wait for drand beacon (0-3 seconds, one-time)
const activeSession = await awaitSession(session);

// ── Spin Loop ──────────────────────────────────────
for (let i = 0; i < 10; i++) {
  const spin = deriveSpin(activeSession, i);

  // Map 256-bit entropy to reel positions
  const grid: number[][] = [];
  for (let reel = 0; reel < REELS; reel++) {
    const reelEntropy = crypto.createHash('sha256')
      .update(spin.entropy + ':reel:' + reel)
      .digest('hex');
    const row: number[] = [];
    for (let r = 0; r < ROWS; r++) {
      const pos = mapEntropy(reelEntropy + ':' + r, SYMBOLS.length);
      row.push(pos);
    }
    grid.push(row);
  }

  // Check for wins, handle free spins
  const wins = evaluatePaytable(grid, PAYTABLE);
  if (wins.triggersFreeSpins) {
    for (let fs = 0; fs < wins.freeSpinCount; fs++) {
      const freeSpinResult = deriveSubResult(activeSession, i, 'freespin', fs);
      // ... same grid mapping logic ...
    }
  }

  // Debit via Operator API (FairSeal doesn't touch this)
  await operatorWallet.debit(playerId, betAmount);

  // Return compact result to player
  sendToPlayer({ spinIndex: i, resultHash: spin.resultHash, grid, wins });
}

// ── Session Close ──────────────────────────────────
const receipt = await closeSession(activeSession);

// Receipt is Merkle-anchored and permanently verifiable
sendToPlayer({ verifyUrl: `https://verify.fairseal.io/session/${receipt.sessionId}` });
```

---

## 10. Comparison: Legacy PF vs. FairSeal SCM

| Aspect | Legacy Seed-Chain | FairSeal SCM |
|--------|-------------------|--------------|
| Seed lifecycle | Long-lived, requires reveal scheduling | Per-session, auto-revealed on close |
| Nonce management | Sequential chain, gaps = trust violation | Index-based derivation, gaps = unused paths |
| Void handling | Requires published void receipts (attack vector) | No void concept — unused derivation path |
| Free spin support | Sub-nonce explosion | Tree derivation, unlimited depth |
| Client seed change | Requires full seed rotation ceremony | Atomic: close old session, open new |
| Latency per spin | 0 (same) | 0 (same — pure HMAC computation) |
| Latency per session | 0 | 0-3s (one-time drand wait) |
| Verification timing | After seed reveal (may be 10K+ spins later) | Immediately on session close |
| Payload per spin | ~500 bytes (hashes + mapping) | ~100 bytes (resultHash only) |
| GLI-19 compatibility | Requires disabling PF entirely | Mode B: audit-only, client_seed as witness |
| External dependency | None (self-contained) | drand beacon (with offline fallback) |
| Anchor durability | None (or Redis cache) | Merkle batch → on-chain (permanent) |

---

## 11. Open Questions

1. **drand latency budget:** 0-3s wait on session start is acceptable for slots (player expects a loading screen). Is it acceptable for live table games? Consider pre-committing sessions during matchmaking.

2. **Session duration caps:** Should we enforce a maximum session duration (e.g., 4 hours) for responsible gambling alignment, even beyond the inactivity timeout?

3. **Paytable versioning:** If the Operator updates the paytable mid-session, the `paytableHash` commitment is violated. Should the SDK enforce paytable immutability per session, or allow versioned paytables with explicit migration?

4. **Multi-game sessions:** Should one session span multiple game types (e.g., player switches from Slot A to Slot B without closing the session)? Current design assumes one `gameId` per session.

5. **Batch anchoring cost:** Who pays for on-chain anchoring? Options: (a) RGS studio absorbs as cost of PF, (b) per-session fee via FairSeal API, (c) x402 micropayment per anchor batch.

---

## 12. Dependencies

| Package | Role | Status |
|---------|------|--------|
| `@fairseal/commit` | drand commitment, resolve, beacon management | Published v1.x |
| `@fairseal/core` | VEO-2 types, hashing primitives | Published v1.3.2 |
| `@fairseal/verify` | Receipt verification, Merkle proofs | Published v0.1.0 |
| `drand-client` | drand beacon fetching (transitive via commit) | External dependency |

New dependency: none. `@fairseal/game` is a composition layer over existing packages.

---

## 13. Rollout Plan

| Phase | Deliverable | Timeline |
|-------|-------------|----------|
| 1 | This RFC — review and finalize | Now |
| 2 | Slot demo (TypeScript, 5-reel, 10 spins, full verify) | After RFC approval |
| 3 | `@fairseal/game` v0.1.0 — core API, Mode A only | 1-2 weeks after demo |
| 4 | Mode B (GLI-safe) + GLI-19 compliance brief | 2-3 weeks |
| 5 | GLI/iTech Labs pre-consultation | When Mode B is spec-complete |
| 6 | `@fairseal/game` v1.0.0 — production release | After lab feedback |

---

## Appendix A: GLI-19 v3.0 Section References

**Section 3.2.1 (Source Code Review):**
> "The independent test laboratory shall review the source code pertaining to any and all core randomness algorithms, scaling algorithms, shuffling algorithms, and other algorithms or functions that play a critical role in the final random outcome selected for use by a game."

**Section 3.2.3 (Distribution):**
> "Each possible RNG selection shall be equally likely to be chosen."

**Section 3.2.4 (Independence):**
> "Knowledge of the numbers chosen in one draw shall not provide information on the numbers that may be chosen in a future draw."

**Section 3.3.1 (RNG Strength):**
> "The RNG used in the determination of game outcomes in a Gaming Platform shall be cryptographically strong."

**Section 3.3.2(b) (Known Input Attack):**
> "It shall be infeasible to computationally determine or reasonably estimate the state of the RNG after initial seeding. In particular, the RNG shall not be seeded from a time value alone."

**Section 3.4.4 (Mechanical RNG — Tampering):**
> "The players and/or gaming attendants... shall not have the ability to manipulate or influence the physical randomness devices in a physical manner with respect to the production of game outcome data, except as intended by game design."

**Section 4.6 (Game Fairness):**
> "The game shall not modify or discard outcomes selected by the RNG due to adaptive behavior."

**Key finding:** The "player shall not influence RNG" language (3.4.4) applies exclusively to mechanical/physical randomness devices. Software RNG requirements (3.2) focus on distribution, independence, and cryptographic strength — all of which HMAC with client_seed satisfies. Section 3.3.2(b) is the only gray area, addressed by Mode B.

---

## Appendix B: Cryptographic Rationale for Mode A

**Claim:** Including `clientSeed` in `HMAC_SHA256(serverSeed, beaconOutput || clientSeed)` does not compromise RNG quality.

**Proof sketch:**

1. **Distribution preservation:** HMAC-SHA256 is a pseudorandom function (PRF). For any fixed key (`serverSeed`), the output is computationally indistinguishable from random, regardless of the message input. Changing `clientSeed` changes the output unpredictably (from the player's perspective, since they don't know `serverSeed`).

2. **No bias introduction:** The player's choice of `clientSeed` cannot increase or decrease the probability of any particular output. This follows from the PRF property — if the player could bias the output, they could distinguish HMAC from a random function, breaking the PRF assumption.

3. **Anti-grinding property:** The server cannot try different `serverSeed` values to find a favorable outcome, because `serverSeed` is committed (via hash) before `clientSeed` is known. Conversely, the player cannot try different `clientSeed` values to find a favorable outcome, because `serverSeed` and `beaconOutput` are unknown to the player when choosing `clientSeed`.

4. **Net security improvement:** The combined commitment (server commits seed hash → player provides client seed → drand provides beacon → seed derived) creates a **three-party commitment** where no single party can influence the outcome. This is strictly more secure than server-only RNG (where the player trusts the server blindly).

**This argument should be presented to the ITL during pre-consultation for Mode A certification.**
