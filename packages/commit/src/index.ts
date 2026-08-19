/**
 * @fairseal/commit — Trustless committed selections
 * 
 * Create cryptographic commitments to selection rules bound to future
 * drand beacon rounds. No server, no trust — verify everything.
 * 
 * The posture: you don't have to trust Fairseal. This library does
 * everything client-side. The paid Fairseal service (@fairseal/core)
 * is the convenience tier — batched anchoring, hosted receipts, SLAs.
 * 
 * @example
 * ```typescript
 * import { createCommitment, resolveCommitment, verifyReceipt, createReceipt } from '@fairseal/commit';
 * 
 * // 1. Commit to a selection rule before the outcome is knowable
 * const commitment = createCommitment({
 *   rule: JSON.stringify({ type: 'uniform', pick: 1 }),
 *   inputs: ['alice', 'bob', 'charlie'],
 *   revealAfter: 30, // seconds
 * });
 * 
 * // 2. (Optional) Anchor on-chain for third-party verifiability
 * // const anchor = await anchorCommitment(commitment, walletClient);
 * 
 * // 3. Resolve the selection ({ wait: true } polls until the round is available)
 * const resolution = await resolveCommitment(commitment, { wait: true });
 * console.log(resolution.selection); // "alice"
 * 
 * // 4. Create a portable receipt
 * const receipt = createReceipt(commitment, resolution);
 * 
 * // 5. Anyone can verify — no trust required
 * const result = await verifyReceipt(receipt);
 * console.log(result.status); // "VALID" or "PARTIAL" (if unanchored)
 * ```
 * 
 * @packageDocumentation
 */

// Core functions
export { createCommitment } from './commitment.js';
export { resolveCommitment, waitAndResolve, createReceipt } from './resolve.js';
export type { ResolveOptions } from './resolve.js';
export { verifyReceipt } from './verify.js';

// Beacon sources
export {
  DrandBeaconSource,
  OfflineBeaconSource,
  CachedBeaconSource,
  createDefaultBeacon,
  getBeaconSource,
  registerBeacon,
  DRAND_QUICKNET,
} from './beacon.js';

// Rules
export { applyRule, validateRule } from './rules.js';

// Crypto utilities
export {
  sha256,
  hashRule,
  hashInputs,
  computeCommitHash,
  deriveOutput,
  toHex,
  fromHex,
} from './crypto.js';

// Types
export type {
  BeaconConfig,
  BeaconRound,
  BeaconSource,
  Commitment,
  CommitmentOptions,
  AnchorProof,
  PrecedenceType,
  Resolution,
  CSReceipt,
  VerificationResult,
  VerificationStatus,
} from './types.js';
