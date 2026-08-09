# Cloudflare Monetization Gateway — Integration Plan

## Current State
FairSeal already has x402 running independently at `x402.fairseal.io`:
- Accepts USDC on Base
- $0.001 per API call
- Treasury: 0x6323610984fE...10dC

## What Cloudflare Monetization Gateway Adds
1. **Discovery** — FairSeal API appears in Cloudflare's x402 ecosystem → agents on Cloudflare find us automatically
2. **Cloudflare Wallets** — agents with `*.cloudflare.pay` wallets can pay FairSeal seamlessly
3. **Edge caching** — API responses cached at Cloudflare edge (faster for global clients)
4. **DDoS protection** — Cloudflare's infrastructure protects the API

## Integration Options

### Option A: Cloudflare Worker Proxy (Recommended)
Deploy a Cloudflare Worker that proxies to `api.fairseal.io` with x402-hono middleware.

```javascript
// worker.ts
import { Hono } from 'hono';
import { x402 } from 'x402-hono';

const app = new Hono();

// Gate endpoints with x402
app.use('/api/v1/games/*', x402({
  price: '0.001',
  asset: 'USDC',
  network: 'base',
  recipient: '0x6323610984fE...10dC', // Treasury
  facilitator: 'https://x402.org/facilitator',
}));

// Proxy to origin
app.all('/api/v1/*', async (c) => {
  const res = await fetch(`https://api.fairseal.io${c.req.path}`, {
    method: c.req.method,
    headers: c.req.header(),
    body: c.req.method !== 'GET' ? await c.req.text() : undefined,
  });
  return new Response(res.body, res);
});

export default app;
```

**Pros:** Minimal change to existing infrastructure. Cloudflare handles x402 payment verification.
**Cons:** Adds a proxy hop (latency ~5ms). Need Cloudflare Workers account.

### Option B: Direct x402 on api.fairseal.io (Current)
Keep current setup. FairSeal handles x402 directly.

**Pros:** No dependency on Cloudflare. Full control.
**Cons:** Not discoverable in Cloudflare ecosystem. No edge caching. No Cloudflare Wallet integration.

### Option C: Hybrid (Best)
- Cloudflare Worker at `api.fairseal.cloudflare.pay` for Cloudflare ecosystem agents
- Direct API at `api.fairseal.io` for non-Cloudflare clients
- Both point to same backend

## Steps to Implement (Option C)

1. **Create Cloudflare Workers project:**
   ```bash
   npm create cloudflare@latest fairseal-worker
   cd fairseal-worker
   npm install hono x402-hono
   ```

2. **Deploy Worker:**
   ```bash
   wrangler deploy
   ```

3. **Configure custom domain:**
   Add Worker route for `api.fairseal.cloudflare.pay` (once Cloudflare Wallets supports custom domains)

4. **Register on x402.org Bazaar:**
   List FairSeal as an x402-compatible service
   - Already submitted once (rejected for http:// URL, resubmitted with https://)
   - Check status and resubmit if needed

5. **Link to Cloudflare Wallet:**
   Once `fairseal.cloudflare.pay` wallet is active, configure it as the payment recipient

## Prerequisites
- Cloudflare account with Workers enabled (Ned's account: jumboned@gmail.com)
- Need to wait for Cloudflare Wallets to launch (currently in reservation phase)
- x402-hono and @x402/fetch npm packages

## Timeline
- **Now:** Can deploy Worker proxy (Option A/C) immediately
- **When Wallets launch:** Link fairseal.cloudflare.pay as recipient
- **When Bazaar accepts:** Listed in x402 ecosystem for discovery

## Estimated Effort
- Worker deployment: 1-2 hours
- Bazaar re-listing: 30 minutes
- Wallet linking: when available (post-launch)
