/**
 * @fairseal/game — Spin derivation
 * Deterministic result derivation from locked session seed.
 */

import { createHmac, createHash } from 'node:crypto';
import type { GameSession, SpinResult, SubResult } from './types.js';

/**
 * Derive a spin result from the locked session seed.
 * Pure computation — no network, no latency.
 *
 * @param session - Active game session
 * @param spinIndex - Sequential spin index (0-based)
 * @returns SpinResult with entropy and result hash
 */
export function deriveSpin(session: GameSession, spinIndex: number): SpinResult {
  if (session.state !== 'active') {
    throw new Error(`Cannot derive spin: session is '${session.state}', expected 'active'`);
  }

  const path = `spin:${spinIndex}`;
  const entropy = createHmac('sha256', session.sessionSeed)
    .update(path)
    .digest('hex');
  const resultHash = createHash('sha256').update(entropy).digest('hex');

  // Add to spin log
  session._spinLog.push({ spinIndex, path, resultHash });

  return { spinIndex, entropy, path, resultHash };
}

/**
 * Derive a sub-result (free spin, cascade, respin, bonus).
 * Path: "spin:{parentIndex}:{subType}:{subIndex}"
 *
 * @param session - Active game session
 * @param parentSpinIndex - Parent spin index
 * @param subType - Sub-event type (e.g., 'freespin', 'cascade')
 * @param subIndex - Sub-event index within parent
 * @returns SubResult with entropy and result hash
 */
export function deriveSubResult(
  session: GameSession,
  parentSpinIndex: number,
  subType: string,
  subIndex: number,
): SubResult {
  if (session.state !== 'active') {
    throw new Error(`Cannot derive sub-result: session is '${session.state}', expected 'active'`);
  }

  const path = `spin:${parentSpinIndex}:${subType}:${subIndex}`;
  const entropy = createHmac('sha256', session.sessionSeed)
    .update(path)
    .digest('hex');
  const resultHash = createHash('sha256').update(entropy).digest('hex');

  // Find parent in spin log and attach sub-result
  const parentEntry = session._spinLog.find((e) => e.spinIndex === parentSpinIndex);
  if (parentEntry) {
    if (!parentEntry.subResults) {
      parentEntry.subResults = [];
    }
    parentEntry.subResults.push({
      spinIndex: parentSpinIndex,
      entropy,
      path,
      resultHash,
      parentSpinIndex,
      subType,
      subIndex,
    });
  }

  return {
    spinIndex: parentSpinIndex,
    entropy,
    path,
    resultHash,
    parentSpinIndex,
    subType,
    subIndex,
  };
}

/**
 * Map raw entropy to a deterministic integer in [0, range).
 * Uses the first 8 hex characters (32 bits) for mapping.
 *
 * @param entropy - 256-bit hex string from deriveSpin/deriveSubResult
 * @param range - Number of possible outcomes
 * @returns Deterministic integer in [0, range)
 */
export function mapEntropy(entropy: string, range: number): number {
  if (range <= 0) {
    throw new Error('Range must be a positive integer');
  }
  const value = parseInt(entropy.slice(0, 8), 16);
  return value % range;
}
