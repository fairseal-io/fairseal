/**
 * @fairseal/commit — Receipt verification
 *
 * Verify a complete CSReceipt (drand-based) from scratch — no trust in the issuer.
 * Every check is independently reproducible.
 *
 * VDF receipt dispatch:
 * This file also handles FairSeal API VDF receipts (from /v1/rng/commit and
 * /v1/rng/reveal) at runtime.  When verifyReceipt() receives an object that
 * passes the isVDFReceipt() type guard it dispatches to verifyVDFReceipt()
 * and maps the result back to VerificationResult for API consistency.
 *
 * TypeScript users who hold a typed VDFRevealReceipt or VDFCommitReceipt are
 * encouraged to call verifyVDFReceipt() directly for the richer result type.
 */

import type { AnchorProof, CSReceipt, VerificationResult, VerificationStatus } from './types.js';
import { getBeaconSource } from './beacon.js';
import { computeCommitHash, deriveOutput, hashInputs, hashRule } from './crypto.js';
import { isVDFReceipt, verifyVDFReceipt, type VDFVerificationResult } from './vdf-verify.js';

// ─── VDF Dispatch Helpers ─────────────────────────────────────────────────────

/**
 * Map a VDFVerificationResult to the standard VerificationResult shape.
 *
 * Mapping rationale:
 *   commitmentIntegrity  ← commitmentHashVerified  (both are integrity anchors)
 *   precedenceVerified   ← temporalValid            (timing guarantee)
 *   beaconVerified       ← wesolowskiMathVerified   (entropy source soundness)
 *   outputVerified       ← valueDerivationVerified  (derived random output)
 *   selectionVerified    ← false (N/A: VDF receipts don't carry a selection rule)
 *
 * Status UNVERIFIABLE is mapped to INVALID (fail-closed: if we cannot verify,
 * we must not return a positive signal).
 */
function mapVDFResult(vdf: VDFVerificationResult): VerificationResult {
  const status: VerificationStatus =
    vdf.status === 'UNVERIFIABLE' ? 'INVALID' : vdf.status;
  return {
    status,
    checks: {
      commitmentIntegrity: vdf.checks.commitmentHashVerified,
      precedenceVerified: vdf.checks.temporalValid,
      beaconVerified: vdf.checks.wesolowskiMathVerified,
      outputVerified: vdf.checks.valueDerivationVerified,
      selectionVerified: false,
    },
    reason: vdf.reason,
  };
}

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
  // ─── VDF format detection (runtime dispatch) ────────────────────────────────────
  // If the caller passes a FairSeal VDF receipt instead of a CSReceipt,
  // dispatch to verifyVDFReceipt() and map the result to VerificationResult.
  // TypeScript callers who hold a typed VDFRevealReceipt should call
  // verifyVDFReceipt() directly for the richer VDFVerificationResult type.
  if (isVDFReceipt(receipt as unknown)) {
    const vdfResult = await verifyVDFReceipt(receipt as unknown as Parameters<typeof verifyVDFReceipt>[0]);
    return mapVDFResult(vdfResult);
  }
  // ───────────────────────────────────────────────────────────────────

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
  //
  // P0 fix (Batch 2): this check previously only compared relay-fetched data
  // against the receipt — it never called beacon.verifyBeacon(), so any receipt
  // whose stored signature happened to match the relay response would receive
  // beaconVerified:true without BLS12-381 cryptographic verification.
  //
  // Attack vectors closed by this fix:
  //   A) Offline beacon — sha256 "signatures" are not BLS; must be rejected.
  //   B) Compromised relay — relay can serve any {randomness, signature} pair;
  //      BLS verification catches forged signatures independent of the relay.
  //   C) Crafted receipts with zero/garbage signatures that coincidentally match
  //      a relay response (possible if relay is also compromised).
  //
  // Fail-closed semantics: if BLS verification cannot be confirmed, beaconVerified
  // stays false.  "Unverifiable" must never be reported as "verified".
  if (resolution) {
    try {
      const beacon = getBeaconSource(commitment.beacon);

      // ── A) Offline beacon: deterministic sha256 "signatures", NOT BLS. ──────
      // Offline mode is for demos / firewalled environments only.
      // A verifier MUST NOT report beaconVerified:true for non-BLS signatures.
      if (commitment.beacon === 'offline') {
        reasons.push(
          'Offline beacon used — no BLS signature present. ' +
          'Offline mode produces deterministic sha256 outputs, not drand BLS12-381 signatures. ' +
          'Offline receipts cannot be cryptographically attested; do not use in audit contexts.'
        );
        // beaconVerified stays false — fail-closed
      } else {
        // ── B+C) Real beacon: first check relay data, then verify BLS. ──────────
        const beaconRound = await beacon.fetchBeacon(commitment.targetRound);

        if (beaconRound.randomness !== resolution.beaconRandomness ||
            beaconRound.signature !== resolution.beaconSignature) {
          reasons.push('Beacon randomness/signature does not match fetched round');
        } else {
          // Data matches the relay response — now cryptographically verify the
          // BLS12-381 signature.  This is the step that was missing (P0 bug):
          // without it, a compromised relay or crafted receipt could bypass
          // beacon verification entirely.
          const blsValid = await beacon.verifyBeacon(beaconRound);
          if (blsValid) {
            checks.beaconVerified = true;
          } else {
            reasons.push(
              'Beacon data matches relay response but BLS12-381 signature failed cryptographic verification. ' +
              'Possible relay compromise, signature forgery, or malformed beacon data. ' +
              'Fail-closed: beaconVerified set to false.'
            );
          }
        }
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
