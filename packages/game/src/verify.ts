/**
 * @fairseal/game — Session verification
 * Client-side verification of session receipts. No server calls needed.
 */

import { createHmac, createHash } from 'node:crypto';
import type { SessionReceipt, VerificationResult } from './types.js';
import { computeMerkleRoot } from './receipt.js';

/**
 * Verify a complete session receipt.
 * Re-derives all spin results and checks against the receipt.
 * Runs entirely client-side — no server calls.
 *
 * @param receipt - Full session receipt from closeSession()
 * @returns VerificationResult with per-spin details and summary
 */
export function verifySession(receipt: SessionReceipt): VerificationResult {
  const spins: Array<{
    spinIndex: number;
    valid: boolean;
    expected: string;
    actual: string;
  }> = [];

  // 1. Verify commitment: hash(serverSeed) === commitmentHash
  const recomputedHash = createHash('sha256')
    .update(receipt.serverSeed)
    .digest('hex');
  const commitmentValid = recomputedHash === receipt.commitmentHash;

  // 2. Recompute session seed using the same derivation as createSession
  const sessionSeedInput =
    receipt.mode === 'provably-fair' && receipt.clientSeed
      ? receipt.beaconOutput + receipt.clientSeed
      : receipt.beaconOutput;

  const sessionSeed = createHmac('sha256', receipt.serverSeed)
    .update(sessionSeedInput)
    .digest('hex');

  // 3. Verify each spin in the log
  let allSpinsValid = true;
  for (const entry of receipt.spinLog) {
    // Verify the main spin
    const entropy = createHmac('sha256', sessionSeed)
      .update(entry.path)
      .digest('hex');
    const expected = createHash('sha256').update(entropy).digest('hex');
    const valid = expected === entry.resultHash;
    if (!valid) allSpinsValid = false;
    spins.push({
      spinIndex: entry.spinIndex,
      valid,
      expected,
      actual: entry.resultHash,
    });

    // Verify sub-results if present
    if (entry.subResults) {
      for (const sub of entry.subResults) {
        const subEntropy = createHmac('sha256', sessionSeed)
          .update(sub.path)
          .digest('hex');
        const subExpected = createHash('sha256').update(subEntropy).digest('hex');
        const subValid = subExpected === sub.resultHash;
        if (!subValid) allSpinsValid = false;
        // Sub-results reported under their parent spin index
        spins.push({
          spinIndex: sub.spinIndex,
          valid: subValid,
          expected: subExpected,
          actual: sub.resultHash,
        });
      }
    }
  }

  // 4. Verify Merkle root
  const leaves = receipt.spinLog.map((s) => s.resultHash);
  const recomputedMerkleRoot = computeMerkleRoot(leaves);
  const merkleValid = recomputedMerkleRoot === receipt.merkleRoot;

  // 5. Beacon verification (v0.1.0: offline beacon always valid)
  // v0.1: offline beacon — cannot verify. Returns null to signal unverified.
  const beaconValid: boolean | null = null;

  const valid = commitmentValid && allSpinsValid && merkleValid;

  const issues: string[] = [];
  if (!commitmentValid) issues.push('commitment hash mismatch');
  if (!allSpinsValid) {
    const mismatches = spins.filter((s) => !s.valid).length;
    issues.push(`${mismatches} spin result mismatch(es)`);
  }
  if (!merkleValid) issues.push('Merkle root mismatch');

  const summary = valid
    ? `Session ${receipt.sessionId}: ${receipt.spinLog.length} spins verified. All results match.`
    : `Session ${receipt.sessionId}: Verification FAILED. ${issues.join('; ')}.`;

  return {
    valid,
    sessionId: receipt.sessionId,
    spins,
    beaconValid,
    merkleValid,
    anchorValid: undefined,
    summary,
  };
}
