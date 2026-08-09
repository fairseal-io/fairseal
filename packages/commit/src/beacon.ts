/**
 * @fairseal/commit — Beacon sources
 * 
 * drand quicknet implementation with multi-relay failover.
 * Abstract interface supports future beacon sources (RANDAO, Pyth, etc.)
 */

import type { BeaconConfig, BeaconRound, BeaconSource } from './types.js';
import { sha256 } from './crypto.js';

// ─── drand quicknet configuration ──────────────────────────

export const DRAND_QUICKNET: BeaconConfig = {
  id: 'drand:quicknet',
  chainHash: '52db9ba70e0cc0f6eaf7803dd07447a1f5477735fd3f661792ba94600c84e971',
  period: 3,           // 3-second rounds
  genesisTime: 1692803367,
  publicKey:
    '83cf0f2896adee7eb8b5f01fcad3912212c437e0073e911fb90022d3e760183c' +
    '8c4b450b6a0a6c3ac6a5776a2d1064510d1fec758c921cc22b0e17e63aaf4bcb' +
    '5ed66304de9cf809bd274ca73bab4af5a6e9c76a4bc09e76eae8991ef5ece45a',
  relays: [
    'https://api.drand.sh',
    'https://drand.cloudflare.com',
  ],
};

// ─── drand beacon source ───────────────────────────────────

export class DrandBeaconSource implements BeaconSource {
  readonly config: BeaconConfig;

  constructor(config?: Partial<BeaconConfig>) {
    this.config = { ...DRAND_QUICKNET, ...config };
  }

  /**
   * Compute the drand round number for a given Unix timestamp.
   * round = floor((t - genesis) / period) + 1
   */
  getRound(unixSeconds: number): number {
    if (unixSeconds < this.config.genesisTime) {
      throw new Error(`Timestamp ${unixSeconds} is before genesis ${this.config.genesisTime}`);
    }
    return Math.floor((unixSeconds - this.config.genesisTime) / this.config.period) + 1;
  }

  /**
   * Compute the wall-clock time (Unix seconds) when a round becomes available.
   * time = genesis + (round - 1) * period
   */
  getRoundTime(round: number): number {
    if (round < 1) throw new Error(`Invalid round: ${round}`);
    return this.config.genesisTime + (round - 1) * this.config.period;
  }

  /**
   * Fetch a beacon round from relays with failover.
   * Tries each relay in order; throws if all fail.
   */
  async fetchBeacon(round: number): Promise<BeaconRound> {
    const errors: Error[] = [];

    for (const relay of this.config.relays) {
      try {
        const url = `${relay}/${this.config.chainHash}/public/${round}`;
        const resp = await fetch(url, {
          signal: AbortSignal.timeout(10_000),
        });

        if (!resp.ok) {
          throw new Error(`HTTP ${resp.status} from ${relay}`);
        }

        const data = await resp.json() as { round: number; randomness: string; signature: string };

        if (data.round !== round) {
          throw new Error(`Round mismatch: requested ${round}, got ${data.round}`);
        }

        return {
          round: data.round,
          randomness: data.randomness,
          signature: data.signature,
        };
      } catch (err) {
        errors.push(err instanceof Error ? err : new Error(String(err)));
      }
    }

    throw new AggregateError(
      errors,
      `Failed to fetch beacon round ${round} from all ${this.config.relays.length} relays`
    );
  }

  /**
   * Verify a beacon round's BLS12-381 signature cryptographically.
   * 
   * This is REAL cryptographic verification using @noble/curves:
   * 1. Constructs the signed message: SHA-256(round as 8-byte big-endian)
   * 2. Hashes to G1 curve point using the quicknet DST
   * 3. Verifies BLS pairing: e(sig, G2_gen) == e(H(msg), pubkey)
   * 4. Confirms randomness = SHA-256(signature)
   * 
   * No trust in any relay or server required.
   */
  async verifyBeacon(beacon: BeaconRound): Promise<boolean> {
    try {
      const { verifyDrandBeacon } = await import('./bls-verify.js');
      return await verifyDrandBeacon(
        beacon.round,
        beacon.signature,
        beacon.randomness,
        this.config.publicKey,
      );
    } catch {
      return false;
    }
  }
}

// ─── Offline beacon source ─────────────────────────────────

/**
 * Offline beacon source for demos and firewall environments.
 * 
 * Generates deterministic (but NOT cryptographically random) beacons
 * from the round number using SHA-256. NOT suitable for production —
 * the output is predictable from the round number alone.
 * 
 * Use `{ beaconId: 'offline' }` in CommitmentOptions to activate.
 */
export class OfflineBeaconSource implements BeaconSource {
  readonly config: BeaconConfig;

  constructor() {
    this.config = {
      ...DRAND_QUICKNET,
      id: 'offline',
      relays: [], // no network needed
    };
  }

  getRound(unixSeconds: number): number {
    if (unixSeconds < this.config.genesisTime) {
      throw new Error(`Timestamp ${unixSeconds} is before genesis ${this.config.genesisTime}`);
    }
    return Math.floor((unixSeconds - this.config.genesisTime) / this.config.period) + 1;
  }

  getRoundTime(round: number): number {
    if (round < 1) throw new Error(`Invalid round: ${round}`);
    return this.config.genesisTime + (round - 1) * this.config.period;
  }

  /**
   * Generate a deterministic beacon from the round number.
   * randomness = SHA-256("offline-beacon:" + round)
   * signature  = SHA-256("offline-sig:" + round)
   * 
   * ⚠️ NOT cryptographically secure — suitable for demos only.
   */
  async fetchBeacon(round: number): Promise<BeaconRound> {
    console.warn('⚠️  Using offline beacon — not suitable for production');
    const randomness = sha256(`offline-beacon:${round}`);
    const signature = sha256(`offline-sig:${round}`);
    return { round, randomness, signature };
  }

  /**
   * Offline beacons are self-generated, so "verification" just checks
   * the deterministic derivation is consistent.
   */
  async verifyBeacon(beacon: BeaconRound): Promise<boolean> {
    const expectedRandomness = sha256(`offline-beacon:${beacon.round}`);
    const expectedSignature = sha256(`offline-sig:${beacon.round}`);
    return beacon.randomness === expectedRandomness && beacon.signature === expectedSignature;
  }
}

// ─── Cached beacon wrapper ─────────────────────────────────

/**
 * Caching wrapper around any BeaconSource.
 * 
 * Caches fetched beacons in-memory. On fetch failure, returns the
 * cached value if available. Helps with intermittent connectivity
 * and avoids redundant relay requests.
 */
export class CachedBeaconSource implements BeaconSource {
  readonly config: BeaconConfig;
  private readonly inner: BeaconSource;
  private readonly cache = new Map<number, BeaconRound>();

  constructor(inner: BeaconSource) {
    this.inner = inner;
    this.config = inner.config;
  }

  getRound(unixSeconds: number): number {
    return this.inner.getRound(unixSeconds);
  }

  getRoundTime(round: number): number {
    return this.inner.getRoundTime(round);
  }

  async fetchBeacon(round: number): Promise<BeaconRound> {
    // Return cached value if available
    const cached = this.cache.get(round);

    try {
      const beacon = await this.inner.fetchBeacon(round);
      this.cache.set(round, beacon);
      return beacon;
    } catch (err) {
      // On failure, return cached value if we have one
      if (cached) {
        return cached;
      }
      throw err;
    }
  }

  async verifyBeacon(beacon: BeaconRound): Promise<boolean> {
    return this.inner.verifyBeacon(beacon);
  }

  /** Check if a round is in the cache. */
  has(round: number): boolean {
    return this.cache.has(round);
  }

  /** Pre-populate the cache (e.g. from stored receipts). */
  seed(beacon: BeaconRound): void {
    this.cache.set(beacon.round, beacon);
  }

  /** Clear all cached entries. */
  clear(): void {
    this.cache.clear();
  }
}

/**
 * Default beacon source — drand quicknet with standard relays.
 */
export function createDefaultBeacon(): BeaconSource {
  return new DrandBeaconSource();
}

/**
 * Registry of known beacon sources.
 * Extensible — add new beacons here for multi-beacon support.
 */
const BEACON_REGISTRY = new Map<string, () => BeaconSource>([
  ['drand:quicknet', () => new DrandBeaconSource()],
  ['offline', () => new OfflineBeaconSource()],
]);

export function getBeaconSource(id: string): BeaconSource {
  const factory = BEACON_REGISTRY.get(id);
  if (!factory) {
    throw new Error(`Unknown beacon: ${id}. Available: ${[...BEACON_REGISTRY.keys()].join(', ')}`);
  }
  return factory();
}

export function registerBeacon(id: string, factory: () => BeaconSource): void {
  BEACON_REGISTRY.set(id, factory);
}
