# FairSeal Slot Demo

Interactive terminal demo showing FairSeal's Seed Commitment Model (SCM) applied to a 5-reel, 3-row slot machine.

Demonstrates the full provably-fair lifecycle:
1. **Commit** — server seed committed before play begins
2. **Beacon** — drand beacon locks the randomness (offline mode for instant demo)
3. **Derive** — deterministic spin outcomes via HMAC chains
4. **Verify** — client re-derives every result from the receipt

## Run

```bash
npm install && npm run demo
```

No network required — uses offline beacon source.
