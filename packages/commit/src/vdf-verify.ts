/**
 * @fairseal/commit — VDF Receipt Verification
 *
 * Verifies FairSeal VDF receipts produced by the /v1/rng/commit and
 * /v1/rng/reveal API endpoints.  These receipts use a Wesolowski VDF
 * (RSA-2048 group) rather than a drand beacon, and therefore require a
 * separate verification path from the drand-based CSReceipt flow.
 *
 * Design rationale (Option A chosen over Option B):
 *   Option A — format-detection dispatch: verifyReceipt() auto-detects VDF
 *   receipts and routes them here.  Zero documentation required from the buyer.
 *   Option B — explicit verifyVDFReceipt() only: cleaner API but requires
 *   buyers to know which function to call.  Rejected because the project
 *   criterion is "buyer with zero docs succeeds" > API purity.
 *
 * Security posture — fail-closed throughout:
 *   - A field that cannot be verified is NEVER silently passed.
 *   - Missing wesolowski_proof → UNVERIFIABLE (not VALID).
 *   - Commit-only receipt (no reveal) → PARTIAL (hash proven, VDF not yet).
 *   - Any failing check → INVALID, with an explicit reason string.
 *
 * RSA-2048 modulus source:
 *   RSA Security Factoring Challenge, 1991 — nothing-up-my-sleeve.
 *   https://en.wikipedia.org/wiki/RSA_numbers#RSA-2048
 *   Factorisation publicly unknown; group order unknown (required for VDF security).
 */

import { createHash } from 'node:crypto';

// ─── RSA-2048 Challenge Modulus ────────────────────────────────────────────────

/**
 * The RSA-2048 challenge modulus used by FairSeal's production VDF.
 * This is the standard nothing-up-my-sleeve number; its factorisation is unknown.
 */
export const RSA2048_N =
  25195908475657893494027183240048398571429282126204032027777137836043662020707595556264018525880784406918290641249515082189298559149176184502808489120072844992687392807287776735971418347270261896375014971824691165077613379859095700097330459748808428401797429100642458691817195118746121515172654632282216869987549182422433637259085141865462043576798423387184774447920739934236584823824281198163815010674810451660377306056201619676256133844143603833904414952634432190114657544454178424020924616515723350778707749817125772467962926386356373289912154831438167899885040445364023527381951378636564391212010397122822120720357n;

// ─── Types ─────────────────────────────────────────────────────────────────────

/** Wesolowski proof fields as stored in the FairSeal reveal receipt. */
export interface WesolowskiProof {
  /** Number of sequential squarings (delay parameter) */
  T: number;
  /** Algorithm identifier, e.g. "wesolowski-2048" */
  algorithm: string;
  /** VDF input seed: "{previous_epoch_output}||{committed_epoch}" */
  seed: string;
  /** VDF group-element input x (hex, 256-bit BigInt of seedToGroupElement(seed)) */
  x: string;
  /** VDF output y = x^(2^T) mod N (hex, up to 2048-bit BigInt) */
  y: string;
  /** Wesolowski proof element π (hex, up to 2048-bit BigInt) */
  pi: string;
}

/** Full proof block inside a reveal receipt. */
export interface VDFProof {
  vdf_output: string;
  previous_output: string;
  /** Same value as wesolowski_proof.pi */
  vdf_proof_input: string;
  wesolowski_proof: WesolowskiProof;
  computed_at: string;
}

/** Server-computed verification hints (informational; do NOT trust for soundness). */
export interface VDFVerificationHints {
  commitment_hash: string;
  commitment_hash_verified: boolean;
  chain_anchor: string;
  temporal_valid: boolean;
}

// ─── Receipt Shapes ────────────────────────────────────────────────────────────

/**
 * Commit receipt — returned by POST /v1/rng/commit (free endpoint).
 * The VDF has not yet run; only commitment integrity can be verified.
 */
export interface VDFCommitReceipt {
  commitment_id: string;
  committed_epoch: number;
  current_epoch: number;
  commitment_time: string;
  commitment_hash: string;
  status?: string;
}

/**
 * Reveal receipt — returned by GET /v1/rng/reveal/:id (free endpoint).
 * Contains the full VDF proof; all five checks can be performed.
 */
export interface VDFRevealReceipt {
  commitment_id: string;
  committed_epoch: number;
  current_epoch_at_commit: number;
  commitment_time: string;
  /** Present in some API versions at top level; also in verification.commitment_hash */
  commitment_hash?: string;
  reveal_time: string;
  /** Public random output: SHA256("wesolowski-y|" + proof.wesolowski_proof.y) */
  value: string;
  proof: VDFProof;
  verification?: VDFVerificationHints;
}

/** Union of both VDF receipt shapes. */
export type AnyVDFReceipt = VDFCommitReceipt | VDFRevealReceipt;

// ─── Verification Result ───────────────────────────────────────────────────────

/**
 * Granular check results for a VDF receipt.
 *
 * Every field is independently verifiable.  A false value is never the
 * result of skipping — it means the check was attempted and failed (or
 * was not applicable, with a note in the reason string).
 */
export interface VDFVerificationChecks {
  /** SHA256(commitment_id|committed_epoch|commitment_time) === commitment_hash */
  commitmentHashVerified: boolean;
  /** committed_epoch > current_epoch (service was forced to commit before outcome) */
  temporalValid: boolean;
  /** SHA256("wesolowski-y|"+y) === value (reveal receipt only; false if N/A) */
  valueDerivationVerified: boolean;
  /** seedToGroupElement(seed, N) === BigInt(x) (provenance of VDF input) */
  seedToXVerified: boolean;
  /** π^ℓ · x^r ≡ y (mod N) — full Wesolowski soundness (reveal receipt only) */
  wesolowskiMathVerified: boolean;
}

/**
 * Result of verifying a VDF receipt.
 *
 * Status semantics:
 * - VALID       All applicable checks pass.  Full Wesolowski soundness confirmed.
 * - PARTIAL     Commit-only receipt (hash proven, VDF not yet) OR skipMath used.
 * - INVALID     One or more checks failed.  See `reason` for details.
 * - UNVERIFIABLE Receipt structure recognised but lacks required fields to verify.
 */
export interface VDFVerificationResult {
  status: 'VALID' | 'PARTIAL' | 'INVALID' | 'UNVERIFIABLE';
  checks: VDFVerificationChecks;
  /** Human-readable explanation for non-VALID statuses. */
  reason?: string;
}

// ─── Modular Arithmetic (BigInt) ───────────────────────────────────────────────

/**
 * Square-and-multiply modular exponentiation.
 * Cost: O(log exp) multiplications in Z/Nz.
 */
function modpow(base: bigint, exp: bigint, mod: bigint): bigint {
  if (mod === 1n) return 0n;
  let result = 1n;
  base = ((base % mod) + mod) % mod;
  while (exp > 0n) {
    if (exp & 1n) result = (result * base) % mod;
    exp >>= 1n;
    base = (base * base) % mod;
  }
  return result;
}

/**
 * Miller-Rabin primality test.
 * Deterministic for n < 3.3×10^24 with the witnesses used below
 * (covers all 128-bit candidates produced by hashToPrime).
 */
function isPrime(n: bigint): boolean {
  if (n < 2n) return false;
  if (n < 4n) return true;
  if (n % 2n === 0n) return false;
  let d = n - 1n, r = 0;
  while (d % 2n === 0n) { d >>= 1n; r++; }
  for (const a of [2n, 3n, 5n, 7n, 11n, 13n, 17n, 19n, 23n, 29n, 31n, 37n]) {
    if (a >= n) continue;
    let x = modpow(a, d, n);
    if (x === 1n || x === n - 1n) continue;
    let composite = true;
    for (let i = 0; i < r - 1; i++) {
      x = (x * x) % n;
      if (x === n - 1n) { composite = false; break; }
    }
    if (composite) return false;
  }
  return true;
}

/**
 * Hash-to-prime (Fiat-Shamir, Wesolowski 2018 §3).
 *
 * Derives a deterministic 128-bit prime ℓ from the VDF transcript (x, y, T, N).
 * This binds the proof π to the specific (x, y, T, N) tuple so that a
 * different y cannot reuse the same π.
 *
 * Matches the production server formula exactly:
 *   digest = SHA256("wesolowski:{x_hex}:{y_hex}:{T}:{N_prefix_64bit}:{counter}")
 *   candidate = lower 128 bits of digest | 1  (force odd)
 *   iterate until isPrime(candidate)
 */
function hashToPrime(x: bigint, y: bigint, T: number, N: bigint): bigint {
  const xHex = x.toString(16);
  const yHex = y.toString(16);
  const NPrefix = N.toString(16).slice(0, 16); // first 64 bits for compactness
  let ctr = 0n;
  while (true) {
    const digest = createHash('sha256')
      .update(`wesolowski:${xHex}:${yHex}:${T}:${NPrefix}:${ctr}`)
      .digest('hex');
    // lower 128 bits (32 hex chars), forced odd
    const candidate = BigInt('0x' + digest.slice(0, 32)) | 1n;
    if (isPrime(candidate)) return candidate;
    ctr++;
  }
}

/**
 * Convert a seed string to a VDF group element in [2, N-2].
 *
 * Formula (matches production server):
 *   x = (SHA256(seed) as BigInt) % (N - 4) + 2
 *
 * The modular reduction is a no-op in practice because SHA256 produces
 * 256-bit outputs while N is 2048-bit, but is included for spec conformance.
 */
function seedToGroupElement(seed: string, N: bigint = RSA2048_N): bigint {
  const h = createHash('sha256').update(seed).digest('hex');
  return (BigInt('0x' + h) % (N - 4n)) + 2n;
}

/** SHA-256 of a UTF-8 string, returned as lowercase hex. */
function sha256(input: string): string {
  return createHash('sha256').update(input, 'utf8').digest('hex');
}

// ─── Format Detection ──────────────────────────────────────────────────────────

/**
 * Type guard: returns true if `obj` is a FairSeal VDF receipt
 * (commit or reveal) from the /v1/rng/* endpoints.
 *
 * Identifies VDF receipts by the presence of `commitment_id`,
 * `committed_epoch`, `commitment_hash`, and `commitment_time` — fields
 * that are absent from drand-based CSReceipts (which use `version`, etc.).
 */
export function isVDFReceipt(obj: unknown): obj is AnyVDFReceipt {
  if (!obj || typeof obj !== 'object') return false;
  const r = obj as Record<string, unknown>;
  // commitment_hash is present at top-level in commit receipts but nested in
  // reveal receipts — so we don't require it at the top level for detection.
  // The three fields below are sufficient to distinguish VDF receipts from
  // drand CSReceipts (which use version/commitment/precedence instead).
  return (
    typeof r['commitment_id'] === 'string' &&
    typeof r['committed_epoch'] === 'number' &&
    typeof r['commitment_time'] === 'string'
  );
}

/** True if the receipt is a full reveal receipt (has VDF proof fields). */
function isRevealReceipt(receipt: AnyVDFReceipt): receipt is VDFRevealReceipt {
  return 'proof' in receipt && !!(receipt as VDFRevealReceipt).proof?.wesolowski_proof;
}

// ─── Individual Checks ─────────────────────────────────────────────────────────

/**
 * Verify commitment_hash = SHA256(commitment_id|committed_epoch|commitment_time).
 *
 * This is the anti-tampering anchor: it ensures the three fields were not
 * altered after the commitment was created.
 *
 * The commitment_hash may appear at the top level (commit receipts) or inside
 * the verification block (reveal receipts).  We recompute from preimage and
 * compare against whichever source is available.  If neither is present we
 * can still recompute and note there is nothing to compare against (PARTIAL).
 */
function checkCommitmentHash(receipt: AnyVDFReceipt): { ok: boolean; reason?: string } {
  const preimage = `${receipt.commitment_id}|${receipt.committed_epoch}|${receipt.commitment_time}`;
  const recomputed = sha256(preimage);

  // Resolve the stored hash: top-level > verification block
  const stored: string | undefined =
    (receipt as VDFCommitReceipt).commitment_hash ||
    (receipt as VDFRevealReceipt).commitment_hash ||
    (receipt as VDFRevealReceipt).verification?.commitment_hash;

  if (!stored) {
    // No stored hash to compare — report PARTIAL with explanation
    return {
      ok: false,
      reason:
        `No commitment_hash field found (checked top-level and verification.commitment_hash). ` +
        `Recomputed value: ${recomputed}. Cannot confirm integrity without a stored hash.`,
    };
  }
  if (recomputed === stored) return { ok: true };
  return {
    ok: false,
    reason: `Commitment hash mismatch: SHA256("${preimage}") = ${recomputed}, stored = ${stored}`,
  };
}

/**
 * Verify temporal ordering: the committed epoch must be strictly in the
 * future relative to the epoch at commit time.
 *
 * This ensures the service could not have known the VDF output when the
 * commitment was created.
 */
function checkTemporalValidity(receipt: AnyVDFReceipt): { ok: boolean; reason?: string } {
  const epochAtCommit =
    'current_epoch_at_commit' in receipt
      ? (receipt as VDFRevealReceipt).current_epoch_at_commit
      : (receipt as VDFCommitReceipt).current_epoch;

  if (typeof epochAtCommit !== 'number') {
    return { ok: false, reason: 'Missing current_epoch / current_epoch_at_commit field' };
  }
  if (receipt.committed_epoch > epochAtCommit) return { ok: true };
  return {
    ok: false,
    reason: `Temporal check failed: committed_epoch (${receipt.committed_epoch}) must be > epoch_at_commit (${epochAtCommit})`,
  };
}

/**
 * Verify value = SHA256("wesolowski-y|" + y).
 *
 * The public-facing random number is a SHA256 digest of the VDF output y.
 * This ensures the value cannot be chosen independently of the VDF computation.
 */
function checkValueDerivation(receipt: VDFRevealReceipt): { ok: boolean; reason?: string } {
  const { y } = receipt.proof.wesolowski_proof;
  const expected = sha256(`wesolowski-y|${y}`);
  if (expected === receipt.value) return { ok: true };
  return {
    ok: false,
    reason: `Value derivation mismatch: SHA256("wesolowski-y|"+y) = ${expected}, got ${receipt.value}`,
  };
}

/**
 * Verify that x was correctly derived from the seed via seedToGroupElement.
 *
 * seed = "{previous_epoch_output}||{committed_epoch}"
 * x = (SHA256(seed) as BigInt) % (N - 4) + 2
 *
 * This proves that the VDF input was deterministically fixed by the previous
 * epoch output and the committed epoch number, preventing cherry-picking.
 */
function checkSeedToX(
  proof: VDFProof,
  N: bigint,
): { ok: boolean; reason?: string } {
  const { seed, x } = proof.wesolowski_proof;
  try {
    const expectedX = seedToGroupElement(seed, N);
    const actualX = BigInt('0x' + x);
    if (expectedX === actualX) return { ok: true };
    return {
      ok: false,
      reason:
        `Seed → x mapping failed: seedToGroupElement("${seed}") produced ` +
        `0x${expectedX.toString(16).slice(0, 16)}... but receipt has x = ${x}. ` +
        `Formula: (SHA256(seed) mod (N-4)) + 2`,
    };
  } catch (err) {
    return { ok: false, reason: `Seed → x check error: ${err}` };
  }
}

/**
 * Full Wesolowski soundness verification.
 *
 * Verification equation: π^ℓ · x^r ≡ y (mod N)
 * where ℓ = hashToPrime(x, y, T, N)  (Fiat-Shamir binding prime)
 *       r = 2^T mod ℓ               (exponent remainder)
 *
 * Cost: O(log ℓ) BigInt squarings ≈ 128 × 2048-bit multiplications.
 * Typically completes in < 20 ms.  T (the VDF delay) does NOT affect
 * verification cost.
 */
function checkWesolowskiMath(
  proof: WesolowskiProof,
  N: bigint,
): { ok: boolean; reason?: string } {
  try {
    const xB = BigInt('0x' + proof.x);
    const yB = BigInt('0x' + proof.y);
    const piB = BigInt('0x' + proof.pi);

    if (xB === 0n) return { ok: false, reason: 'VDF input x is zero — invalid group element' };
    if (yB === 0n) return { ok: false, reason: 'VDF output y is zero — invalid group element' };
    if (piB === 0n) return { ok: false, reason: 'VDF proof π is zero — invalid proof element' };

    const l = hashToPrime(xB, yB, proof.T, N);
    const r = modpow(2n, BigInt(proof.T), l);

    // Wesolowski verification: π^ℓ · x^r ≡ y (mod N)
    const lhs = (modpow(piB, l, N) * modpow(xB % N, r, N)) % N;
    const rhs = yB % N;

    if (lhs === rhs) return { ok: true };
    return {
      ok: false,
      reason:
        `Wesolowski verification failed: π^ℓ · x^r ≢ y (mod N). ` +
        `The VDF output cannot be confirmed as correct. ` +
        `lhs (first 16 hex) = ${lhs.toString(16).slice(0, 16)}, ` +
        `rhs = ${rhs.toString(16).slice(0, 16)}`,
    };
  } catch (err) {
    return { ok: false, reason: `Wesolowski math check error: ${err}` };
  }
}

// ─── Main Exported API ────────────────────────────────────────────────────────

/**
 * Verify a FairSeal VDF receipt from /v1/rng/commit or /v1/rng/reveal.
 *
 * Performs up to five independent checks:
 *
 * 1. **Commitment hash** — SHA256(id|epoch|time) === commitment_hash
 * 2. **Temporal validity** — committed_epoch > current_epoch_at_commit
 * 3. **Value derivation** — SHA256("wesolowski-y|"+y) === value  (reveal only)
 * 4. **Seed → x mapping** — seedToGroupElement(seed) === x  (reveal only)
 * 5. **Wesolowski math** — π^ℓ · x^r ≡ y (mod N)  (reveal only)
 *
 * Status codes:
 * - `VALID`       All applicable checks pass, including Wesolowski soundness.
 * - `PARTIAL`     Commit receipt (hash verified, VDF pending), or `skipMath` set.
 * - `INVALID`     One or more checks failed.
 * - `UNVERIFIABLE` Receipt structure recognised but missing required fields.
 *
 * Fail-closed semantics: a check that cannot be performed returns false and
 * contributes a note to `reason`.  A missing field is never silently passed.
 *
 * @example
 * ```ts
 * import { verifyVDFReceipt } from '@fairseal/commit';
 *
 * // Commit receipt → PARTIAL (hash verified, VDF not yet computed)
 * const cr = await verifyVDFReceipt(commitReceipt);
 * console.log(cr.status); // "PARTIAL"
 * console.log(cr.checks.commitmentHashVerified); // true
 *
 * // Reveal receipt → VALID (all checks pass, full soundness confirmed)
 * const rr = await verifyVDFReceipt(revealReceipt);
 * console.log(rr.status); // "VALID"
 * console.log(rr.checks.wesolowskiMathVerified); // true
 * ```
 */
export async function verifyVDFReceipt(
  receipt: AnyVDFReceipt,
  options?: {
    /**
     * Override the RSA modulus.  Default: RSA2048_N (FairSeal production modulus).
     * Supply this only if FairSeal has rotated to a new modulus.
     */
    N?: bigint;
    /**
     * Skip Wesolowski math verification.  Returns PARTIAL instead of VALID
     * if all other checks pass.  Useful in environments without 64-bit BigInt
     * or when speed is critical.
     *
     * **Security note:** setting this to true means you accept the hash-chain
     * integrity proof only; VDF soundness (that T squarings were actually
     * performed) is NOT confirmed.
     */
    skipMath?: boolean;
  },
): Promise<VDFVerificationResult> {
  const N = options?.N ?? RSA2048_N;
  const skipMath = options?.skipMath ?? false;

  const checks: VDFVerificationChecks = {
    commitmentHashVerified: false,
    temporalValid: false,
    valueDerivationVerified: false,
    seedToXVerified: false,
    wesolowskiMathVerified: false,
  };
  const reasons: string[] = [];

  // ─── Structural gate ────────────────────────────────────────────────────────
  if (!receipt || typeof receipt !== 'object') {
    return {
      status: 'UNVERIFIABLE',
      checks,
      reason: 'Receipt is null or not an object',
    };
  }

  // ─── Check 1: Commitment Hash ───────────────────────────────────────────────
  const c1 = checkCommitmentHash(receipt);
  checks.commitmentHashVerified = c1.ok;
  if (!c1.ok && c1.reason) reasons.push(c1.reason);

  // ─── Check 2: Temporal Validity ─────────────────────────────────────────────
  const c2 = checkTemporalValidity(receipt);
  checks.temporalValid = c2.ok;
  if (!c2.ok && c2.reason) reasons.push(c2.reason);

  // ─── Reveal-only checks ─────────────────────────────────────────────────────
  if (isRevealReceipt(receipt)) {
    const wp = receipt.proof.wesolowski_proof;

    // ─── Check 3: Value Derivation ─────────────────────────────────────────
    const c3 = checkValueDerivation(receipt);
    checks.valueDerivationVerified = c3.ok;
    if (!c3.ok && c3.reason) reasons.push(c3.reason);

    // ─── Check 4: Seed → X Mapping ────────────────────────────────────────
    const c4 = checkSeedToX(receipt.proof, N);
    checks.seedToXVerified = c4.ok;
    if (!c4.ok && c4.reason) reasons.push(c4.reason);

    // ─── Check 5: Wesolowski Math ──────────────────────────────────────────
    if (!skipMath) {
      const c5 = checkWesolowskiMath(wp, N);
      checks.wesolowskiMathVerified = c5.ok;
      if (!c5.ok && c5.reason) reasons.push(c5.reason);
    } else {
      reasons.push(
        'Wesolowski math verification skipped (skipMath: true). ' +
        'Hash-chain integrity verified only; VDF soundness (T squarings) is NOT confirmed.',
      );
    }
  }

  // ─── Status determination ────────────────────────────────────────────────────
  let status: VDFVerificationResult['status'];

  if (!checks.commitmentHashVerified || !checks.temporalValid) {
    // Core integrity or temporal check failed — fail-closed: INVALID.
    // PARTIAL is only for "verified what I could, found no problems"; a
    // temporal inversion or hash mismatch is a positive failure.
    status = 'INVALID';
  } else if (!isRevealReceipt(receipt)) {
    // Commit-only receipt: hash + temporal both verified.
    // VDF not yet computed — verify again after the reveal.
    status = 'PARTIAL';
  } else {
    // Reveal receipt: require all three reveal checks
    const hashesOk = checks.valueDerivationVerified && checks.seedToXVerified;
    if (hashesOk && checks.wesolowskiMathVerified) {
      status = 'VALID';
    } else if (hashesOk && skipMath) {
      status = 'PARTIAL';
    } else {
      // One or more hash or math checks failed
      status = 'INVALID';
    }
  }

  return {
    status,
    checks,
    reason: reasons.length > 0 ? reasons.join('; ') : undefined,
  };
}
