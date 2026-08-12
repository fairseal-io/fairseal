/**
 * @fairseal/commit — Receipt verification
 * 
 * Verify a complete CSReceipt from scratch — no trust in the issuer.
 * Every check is independently reproducible.
 */

import type { AnchorProof, CSReceipt, VerificationResult, VerificationStatus } from './types.js';
import { getBeaconSource } from './beacon.js';
import { computeCommitHash, deriveOutput, hashInputs, hashRule } from './crypto.js';

/**
 * Structural validation of an AnchorProof.
 * Returns null if valid, or a human-readable error string.
 */
function validateAnchorStructure(anchor: AnchorProof): string | null {
  if (!anchor.txHash || typeof anchor.txHash !== 'string' || !/^0x[0-9a-fA-F]{64}$/.test(anchor.txHash)) {
    return 'Invalid txHash format (expected 0x-prefixed 32-byte hex)';
  }
  if (typeof anchor.blockNumber !== 'number' || !Number.isInteger(anchor.blockNumber) || anchor.blockNumber <= 0) {
    return 'Invalid blockNumber (expected positive integer)';
  }
  if (typeof anchor.blockTimestamp !== 'number' || anchor.blockTimestamp <= 0) {
    return 'Invalid blockTimestamp (expected positive Unix timestamp)';
  }
  if (typeof anchor.chainId !== 'number' || !Number.isInteger(anchor.chainId) || anchor.chainId <= 0) {
    return 'Invalid chainId (expected positive integer)';
  }
  return null;
}

/**
 * Verify a complete Committed Selection Receipt.
 * 
 * Performs five independent checks:
 * 1. Commitment integrity — recompute commitHash from components
 * 2. Precedence — anchor timestamp precedes target round time
 * 3. Beacon — BLS signature is valid
 * 4. Output — HMAC derivation matches
 * 5. Selection — rule application matches
 * 
 * Returns VALID if all checks pass, PARTIAL if some pass (e.g. unattested
 * precedence), INVALID if any critical check fails.
 * 
 * **Security note:** Receipts claiming `precedence: 'onchain'` are INVALID
 * by default unless a `verifyAnchor` callback is provided and succeeds.
 * Self-reported anchor data is never trusted without on-chain verification.
 * Set `strictAnchor: false` to explicitly opt into accepting unverified
 * on-chain claims (NOT recommended for audit/compliance use cases).
 * 
 * @example
 * ```typescript
 * const result = await verifyReceipt(receipt);
 * if (result.status === 'VALID') {
 *   console.log('Receipt is cryptographically valid');
 * }
 * ```
 */
export async function verifyReceipt(
  receipt: CSReceipt,
  options?: {
    /** Optional callback for on-chain anchor verification */
    verifyAnchor?: (anchor: AnchorProof, commitHash: string) => Promise<boolean>;
    /**
     * When true (default), receipts claiming on-chain precedence are INVALID
     * unless verifyAnchor callback is provided and succeeds. Self-reported
     * anchor data is never trusted without independent verification.
     * 
     * Set to false ONLY when anchor verification is handled externally
     * and you accept the security implications.
     */
    strictAnchor?: boolean;
  }
): Promise<VerificationResult> {
  const checks = {
    commitmentIntegrity: false,
    precedenceVerified: false,
    beaconVerified: false,
    outputVerified: false,
    selectionVerified: false,
  };
  const reasons: string[] = [];
  /** Tracks whether an on-chain claim was made but could not be verified */
  let anchorClaimUnverified = false;

  const { commitment, anchor, resolution } = receipt;

  // ─── Check 1: Commitment Integrity ────────────────────────
  try {
    const recomputedRuleHash = hashRule(commitment.rule);
    const recomputedInputsHash = hashInputs(commitment.inputs);

    if (recomputedRuleHash !== commitment.ruleHash) {
      reasons.push(`Rule hash mismatch: expected ${recomputedRuleHash}, got ${commitment.ruleHash}`);
    } else if (recomputedInputsHash !== commitment.inputsHash) {
      reasons.push(`Inputs hash mismatch: expected ${recomputedInputsHash}, got ${commitment.inputsHash}`);
    } else {
      const recomputedCommitHash = computeCommitHash(
        commitment.beacon,
        commitment.targetRound,
        commitment.ruleHash,
        commitment.inputsHash,
        commitment.salt,
      );

      if (recomputedCommitHash === commitment.commitHash) {
        checks.commitmentIntegrity = true;
      } else {
        reasons.push(`Commit hash mismatch: expected ${recomputedCommitHash}, got ${commitment.commitHash}`);
      }
    }
  } catch (err) {
    reasons.push(`Commitment integrity check failed: ${err}`);
  }

  // ─── Check 2: Precedence ──────────────────────────────────
  const strictAnchor = options?.strictAnchor !== false; // default: true

  if (anchor && receipt.precedence === 'onchain') {
    // Step 2a: Structural validation — reject malformed anchor proofs immediately
    const structError = validateAnchorStructure(anchor);
    if (structError) {
      anchorClaimUnverified = true;
      reasons.push(`Anchor proof structurally invalid: ${structError}`);
    } else if (options?.verifyAnchor) {
      // Step 2b: On-chain verification via caller-provided callback
      try {
        const anchorValid = await options.verifyAnchor(anchor, commitment.commitHash);
        if (anchorValid) {
          const beacon = getBeaconSource(commitment.beacon);
          const roundTime = beacon.getRoundTime(commitment.targetRound);
          if (anchor.blockTimestamp < roundTime) {
            checks.precedenceVerified = true;
          } else {
            reasons.push('Anchor timestamp does not precede target round time');
          }
        } else {
          anchorClaimUnverified = true;
          reasons.push('Anchor proof rejected by verifyAnchor callback');
        }
      } catch (err) {
        anchorClaimUnverified = true;
        reasons.push(`Anchor verification failed: ${err}`);
      }
    } else {
      // No verifyAnchor callback — receipt claims on-chain but we cannot verify.
      // This is a security-critical distinction: self-reported anchor data
      // MUST NOT be trusted without independent verification.
      anchorClaimUnverified = true;
      if (strictAnchor) {
        reasons.push(
          'Receipt claims on-chain precedence but no verifyAnchor callback provided. ' +
          'Self-reported anchor data cannot be trusted without independent on-chain verification. ' +
          'Pass a verifyAnchor callback, or set strictAnchor: false to accept unverified claims (not recommended).'
        );
      } else {
        reasons.push(
          'Anchor proof present but not independently verified (strictAnchor: false). ' +
          'Self-reported anchor data accepted without on-chain verification — NOT suitable for audit/compliance.'
        );
        // In non-strict mode, we don't block on this, but precedenceVerified stays false
        anchorClaimUnverified = false; // caller explicitly opted out
      }
    }
  } else if (receipt.precedence === 'unattested') {
    reasons.push('Precedence is unattested — commitment timing cannot be independently verified');
  }

  // ─── Check 3: Beacon Verification ────────────────────────
  if (resolution) {
    try {
      const beacon = getBeaconSource(commitment.beacon);
      const beaconRound = await beacon.fetchBeacon(commitment.targetRound);

      if (beaconRound.randomness === resolution.beaconRandomness &&
          beaconRound.signature === resolution.beaconSignature) {
        checks.beaconVerified = true;
      } else {
        reasons.push('Beacon randomness/signature does not match fetched round');
      }
    } catch (err) {
      reasons.push(`Beacon verification failed: ${err}`);
    }
  }

  // ─── Check 4: Output Verification ────────────────────────
  if (resolution) {
    try {
      const recomputedOutput = deriveOutput(
        resolution.beaconRandomness,
        commitment.ruleHash,
        commitment.inputsHash,
      );

      if (recomputedOutput === resolution.output) {
        checks.outputVerified = true;
      } else {
        reasons.push(`Output mismatch: expected ${recomputedOutput}, got ${resolution.output}`);
      }
    } catch (err) {
      reasons.push(`Output verification failed: ${err}`);
    }
  }

  // ─── Check 5: Selection Verification ──────────────────────
  if (resolution && checks.outputVerified) {
    try {
      // Try to verify selection with built-in rules
      // For custom operator rules, selection verification is skipped (operator's algorithm)
      const parsed = JSON.parse(commitment.rule) as { type?: string };
      if (parsed.type && ['uniform', 'shuffle', 'index'].includes(parsed.type)) {
        const { applyRule } = await import('./rules.js');
        const recomputedSelection = applyRule(commitment.rule, commitment.inputs, resolution.output);
        if (JSON.stringify(recomputedSelection) === JSON.stringify(resolution.selection)) {
          checks.selectionVerified = true;
        } else {
          reasons.push('Selection does not match rule application to output');
        }
      } else {
        // Custom rule — selection verification requires operator algorithm
        // DO NOT auto-pass — this is a security-critical check
        checks.selectionVerified = false;
        reasons.push('Custom rule — selection verification requires operator-provided verification function');
      }
    } catch (err) {
      reasons.push(`Selection verification failed: ${err}`);
    }
  }

  // ─── Determine overall status ─────────────────────────────
  let status: VerificationStatus;

  const coreChecks = checks.commitmentIntegrity && checks.beaconVerified && checks.outputVerified;
  
  if (anchorClaimUnverified) {
    // Receipt claimed on-chain precedence but anchor could not be verified.
    // This is INVALID regardless of other checks — an unverifiable on-chain
    // claim in an audit context is worse than no claim at all.
    // A verifier that returns PARTIAL for fabricated anchors is a liability.
    status = 'INVALID';
  } else if (coreChecks && checks.selectionVerified) {
    // All checks pass
    status = checks.precedenceVerified ? 'VALID' : 'PARTIAL';
  } else if (coreChecks && !checks.selectionVerified) {
    // Core checks pass but selection unverified (custom operator rule)
    // This is still PARTIAL — the commitment and entropy are proven
    status = 'PARTIAL';
  } else {
    status = 'INVALID';
  }

  return {
    status,
    checks,
    reason: reasons.length > 0 ? reasons.join('; ') : undefined,
  };
}
