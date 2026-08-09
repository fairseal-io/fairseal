/**
 * @fairseal/game — Provably Fair Game API
 * Seed Commitment Model for RGS studios.
 *
 * @packageDocumentation
 */

// Session lifecycle
export { createSession, awaitSession, closeSession, rotateClientSeed } from './session.js';

// Spin derivation
export { deriveSpin, deriveSubResult, mapEntropy } from './derive.js';

// Verification
export { verifySession } from './verify.js';

// Receipt utilities
export { computeMerkleRoot } from './receipt.js';

// Types
export type {
  GameSessionConfig,
  GameSession,
  SpinResult,
  SubResult,
  SpinLogEntry,
  SessionReceipt,
  VerificationResult,
} from './types.js';
