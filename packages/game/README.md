# @fairseal/game

> ⚠️ **v0.1 ALPHA — Offline beacon only. NOT production-ready.**
> This version uses a simulated beacon (`crypto.randomBytes`), not real drand.
> Verification proves internal hash consistency only — it does NOT prove
> the operator couldn't have chosen a favorable seed.
> Real drand integration comes in v0.2. Do not use v0.1 for production
> provably fair claims.

Game API scaffold for RGS studios — Seed Commitment Model.

## Install

```bash
npm install @fairseal/game
```

## Quick Start

```typescript
import { createSession, deriveSpin, deriveSubResult, closeSession, verifySession, mapEntropy } from '@fairseal/game';

// Create a provably fair session
const session = await createSession({
  mode: 'provably-fair',
  serverSeed: 'your-secret-seed',
  clientSeed: 'player-seed',
  gameId: 'my-slot-game',
  paytableHash: 'abc123',
});

// Derive spin results (pure computation — zero latency)
const spin = deriveSpin(session, 0);
console.log(spin.entropy); // Use to derive game result

// Free spins, cascades, bonuses — unlimited sub-paths
const freeSpin = deriveSubResult(session, 0, 'freespin', 0);

// Close session and get verifiable receipt
const receipt = await closeSession(session);
const result = verifySession(receipt);
console.log(result.valid); // true
```

## Modes

- **`provably-fair`** (Mode A): Full player verifiability. Client seed participates in derivation.
- **`audit-only`** (Mode B): GLI-19 safe. Client seed recorded as witness only.

## API

| Function | Description |
|----------|-------------|
| `createSession(config)` | Create a new game session with committed seed |
| `awaitSession(session)` | Wait for beacon resolution (0-3s) |
| `deriveSpin(session, index)` | Derive spin result — pure HMAC, zero latency |
| `deriveSubResult(session, parent, type, index)` | Derive sub-event (free spin, cascade, etc.) |
| `mapEntropy(entropy, range)` | Map 256-bit entropy to `[0, range)` |
| `closeSession(session)` | Close session, reveal seed, generate receipt |
| `rotateClientSeed(session, newSeed)` | Atomic seed rotation (Mode A only) |
| `verifySession(receipt)` | Client-side receipt verification |
| `computeMerkleRoot(leaves)` | Merkle tree construction |

See [RFC-001](../../rfcs/001-fairseal-game-api.md) for full specification.

## License

MIT
