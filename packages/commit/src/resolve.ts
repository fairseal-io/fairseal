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
export async function resolveCommitment(commitment: Commitment): Promise<Resolution> {
  const beacon = getBeaconSource(commitment.beacon);

  // Check if the target round has elapsed
  const roundTime = beacon.getRoundTime(commitment.targetRound);
  const now = Math.floor(Date.now() / 1000);
  
  if (now < roundTime) {
    const waitSeconds = roundTime - now;
    throw new Error(
      `Target round ${commitment.targetRound} hasn't elapsed yet. ` +
      `Available at ${new Date(roundTime * 1000).toISOString()} (${waitSeconds}s from now)`
    );
  }

  // Fetch the beacon round
  let beaconRound;
  try {
    beaconRound = await beacon.fetchBeacon(commitment.targetRound);
  } catch (err) {
    const msg = err instanceof AggregateError
      ? err.message
      : err instanceof Error ? err.message : String(err);
    throw new Error(
      `Beacon fetch failed: ${msg}. ` +
      `For offline demos, use beaconId: 'offline' in CommitmentOptions.`
    );
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
