/**
 * @fairseal/commit — Commitment resolution
 * 
 * After the target beacon round elapses: fetch the beacon output,
 * verify its BLS signature, and derive the selection via HMAC.
 */

import type { Commitment, CSReceipt, Resolution } from './types.js';
import { getBeaconSource } from './beacon.js';
import { deriveOutput } from './crypto.js';

/**
 * Options for {@link resolveCommitment}.
 */
export interface ResolveOptions {
  /**
   * If true, wait (poll) until the target beacon round becomes available
   * instead of throwing. Bounded by `maxWaitMs`.
   */
  wait?: boolean;
  /** Maximum total milliseconds to wait when `wait` is true. Default: 15000. */
  maxWaitMs?: number;
}

const sleep = (ms: number) => new Promise<void>((r) => setTimeout(r, ms));

/**
 * Resolve a commitment after its target beacon round has elapsed.
 * 
 * Fetches the beacon output, verifies the BLS signature, derives
 * the HMAC output, and applies the committed rule to produce the selection.
 * 
 * @throws If the target round hasn't elapsed yet
 * @throws If the beacon cannot be fetched
 * 
 * @example
 * ```typescript
 * const resolution = await resolveCommitment(commitment);
 * console.log(resolution.selection); // "alice"
 * console.log(resolution.verified);  // true
 * ```
 */
export async function resolveCommitment(
  commitment: Commitment,
  opts: ResolveOptions = {},
): Promise<Resolution> {
  const beacon = getBeaconSource(commitment.beacon);
  const maxWaitMs = opts.maxWaitMs ?? 15_000;
  const deadline = Date.now() + maxWaitMs;

  // Check if the target round has elapsed
  const roundTime = beacon.getRoundTime(commitment.targetRound);
  const now = Math.floor(Date.now() / 1000);

  if (now < roundTime) {
    const waitSeconds = roundTime - now;
    if (!opts.wait) {
      throw new Error(
        `Target round ${commitment.targetRound} hasn't elapsed yet. ` +
        `Available at ${new Date(roundTime * 1000).toISOString()} (${waitSeconds}s from now). ` +
        `Tip: pass { wait: true } (or use waitAndResolve) to wait automatically.`
      );
    }
    const waitMs = (roundTime - now) * 1000 + 500; // +0.5s margin for relay propagation
    if (Date.now() + waitMs > deadline) {
      throw new Error(
        `Target round ${commitment.targetRound} is ${waitSeconds}s away, which exceeds ` +
        `maxWaitMs=${maxWaitMs}. Increase maxWaitMs or resolve later.`
      );
    }
    await sleep(waitMs);
  }

  // Fetch the beacon round (with bounded polling when wait=true —
  // relays can lag a moment behind the theoretical round time)
  let beaconRound;
  for (;;) {
    try {
      beaconRound = await beacon.fetchBeacon(commitment.targetRound);
      break;
    } catch (err) {
      if (opts.wait && Date.now() + 1000 < deadline) {
        await sleep(1000);
        continue;
      }
      const msg = err instanceof AggregateError
        ? err.message
        : err instanceof Error ? err.message : String(err);
      throw new Error(
        `Beacon fetch failed: ${msg}. ` +
        `For offline demos, use beaconId: 'offline' in CommitmentOptions.`
      );
    }
  }

  // Verify the beacon signature
  const verified = await beacon.verifyBeacon(beaconRound);

  // Derive the output: HMAC-SHA256(beacon.randomness, ruleHash ‖ inputsHash)
  const output = deriveOutput(
    beaconRound.randomness,
    commitment.ruleHash,
    commitment.inputsHash,
  );

  // Try to apply built-in rule types; if unknown, leave selection as null
  // Operators with custom algorithms use beaconRandomness directly
  let selection: unknown = null;
  try {
    const parsed = JSON.parse(commitment.rule) as { type?: string };
    if (parsed.type && ['uniform', 'shuffle', 'index'].includes(parsed.type)) {
      const { applyRule } = await import('./rules.js');
      selection = applyRule(commitment.rule, commitment.inputs, output);
    }
  } catch {
    // Custom rule — operator handles selection
  }

  return {
    beaconRound: beaconRound.round,
    beaconSignature: beaconRound.signature,
    beaconRandomness: beaconRound.randomness,
    verified,
    output,
    selection,
  };
}

/**
 * Convenience wrapper: resolve a commitment, waiting for the target beacon
 * round to become available (polls, bounded by `maxWaitMs`, default 15s).
 *
 * Equivalent to `resolveCommitment(commitment, { wait: true, ...opts })`.
 *
 * @example
 * ```typescript
 * const resolution = await waitAndResolve(commitment); // no manual sleep needed
 * ```
 */
export async function waitAndResolve(
  commitment: Commitment,
  opts: Omit<ResolveOptions, 'wait'> = {},
): Promise<Resolution> {
  return resolveCommitment(commitment, { ...opts, wait: true });
}

/**
 * Create a complete receipt from a commitment, optional anchor, and resolution.
 */
export function createReceipt(
  commitment: Commitment,
  resolution: Resolution,
  anchor?: { txHash: string; blockNumber: number; blockTimestamp: number; chainId: number },
): CSReceipt {
  return {
    version: '1.0.0',
    commitment,
    anchor: anchor
      ? { ...anchor, precedence: 'onchain' as const }
      : undefined,
    resolution,
    precedence: anchor ? 'onchain' : 'unattested',
    attestation: anchor ? 'self-anchored' : 'unattested',
  };
}
