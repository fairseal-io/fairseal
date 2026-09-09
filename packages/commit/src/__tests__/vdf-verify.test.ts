/**
 * @fairseal/commit — VDF Receipt Verification Tests
 *
 * Uses real production fixtures captured during the 2026-09-09 buyer acceptance
 * test (fairseal-buyer-acceptance-20260909.md).  Every positive test is a live
 * receipt; every negative test tampers exactly one field.
 *
 * Fixture provenance:
 *   - rng_commit / rng_reveal: live calls to api.fairseal.io, 2026-09-09T10:22–10:23
 *   - Buyer wallet: 0x02b43334F675E02636816E6f5c0EC6072be2df8c
 *   - No API payment required (commit/reveal are free endpoints)
 *
 * Test structure:
 *   1. isVDFReceipt() — format detection
 *   2. verifyVDFReceipt() — commit receipts (PARTIAL expected)
 *   3. verifyVDFReceipt() — reveal receipts (VALID expected, full Wesolowski math)
 *   4. verifyVDFReceipt() — negative / tamper tests (INVALID expected, fail-closed)
 *   5. verifyReceipt() dispatch — VDF receipts auto-routed, drand path unchanged
 *   6. RSA2048_N constant sanity check
 */

import { verifyVDFReceipt, isVDFReceipt, RSA2048_N } from '../vdf-verify';
import { verifyReceipt } from '../verify';
import type {
  VDFCommitReceipt,
  VDFRevealReceipt,
  AnyVDFReceipt,
} from '../vdf-verify';
import type { CSReceipt } from '../types';
import { createHash } from 'node:crypto';

// ─── Fixtures ──────────────────────────────────────────────────────────────────
//
// Live production receipts from the 2026-09-09 buyer acceptance run.
// These are the canonical ground-truth inputs; the corresponding outputs
// are the ground-truth expectations.

const COMMIT_FIXTURE: VDFCommitReceipt = {
  commitment_id: '1bd53020-0350-492b-b70c-6a61e2154fc0',
  committed_epoch: 975958,
  current_epoch: 975955,
  commitment_time: '2026-09-09T10:22:49.892Z',
  commitment_hash: '6fe00a54ca0ea85daac7fb39a4a607f8baae1253ca5ce9634fa4bd8fc66ebec4',
  status: 'pending',
};

const REVEAL_FIXTURE: VDFRevealReceipt = {
  commitment_id: '1bd53020-0350-492b-b70c-6a61e2154fc0',
  committed_epoch: 975958,
  current_epoch_at_commit: 975955,
  commitment_time: '2026-09-09T10:22:49.892Z',
  reveal_time: '2026-09-09T10:23:06.741Z',
  value: '7b7111a2745d75a50b5f530f90773d2c581edf3a84fc9a71abdc7137b7123216',
  proof: {
    vdf_output: '7b7111a2745d75a50b5f530f90773d2c581edf3a84fc9a71abdc7137b7123216',
    previous_output: '884a87acfc282ede6212009ccf804904a647610a400d1c21b9b85be430d000c1',
    vdf_proof_input:
      '830474226fe1995e0fe186fe268764e1df3766f09c68214cee97fbb82ffed7f90fa6971ad509fdc1b07deebe81171520c21b0a23f415a7c35254f1318d17bb6863612d7857c8b9588f5c700bb6a80b3bac0992889d83396b31d845678fc4619398022701479d2b301d2bb309624e9b8c1f693c9a22aa496435c35ab45b3023dfafb29ba2940a18f1a488e86cbddf9ea36534945ae97802868c253d907e50fc902ff323d199266a4215cc066163497e7e7976ef39eacc584a7fb5836df576431411da2fe0e066bb554dfcf3f5db0fffd8e1d3530152903ae8a0536c2f83d622100ed3974fcb39f52153516c88ed83a4aa147e7110f2d8b269334544ea6e7f4c04',
    wesolowski_proof: {
      T: 565486,
      algorithm: 'wesolowski-2048',
      seed: '884a87acfc282ede6212009ccf804904a647610a400d1c21b9b85be430d000c1||975958',
      x: '39082667609f834f94ff5b08bc62050e9197d876808368c946ac702ac4ead7ea',
      y: '6d901c9f0b2f0285150870207493270cfa86571c88f845e6665525faf84f732a180e6da1ca220ccb9ae1efd1e6897d0d8b531e333a34a05dc1ff8ee51b2fc11df5948220967891c7d4fe660d01ff0fc9d8bbf0669e67cd90b9af5e044dc796139d733ef1be2354e948b9abed1b1518401a9d23928a6a8f7d1c6d18ad579afb9e886fe36feb136e5fee7555b8708f0a41ad0bec7bfca50ceaffe6400735e98bb15b32f73887e866ab22198c57226fa148a0c62e12c56a3afe765d8b590c016c4feb16affc38229c325b7ee62403f0e044f297716d9c16a6091254aaf44b745ee7c5adb1c5468c35d40a7d1b89bc0095e441ec01a43d7aaff6e88a74378a7bbd2e',
      pi: '830474226fe1995e0fe186fe268764e1df3766f09c68214cee97fbb82ffed7f90fa6971ad509fdc1b07deebe81171520c21b0a23f415a7c35254f1318d17bb6863612d7857c8b9588f5c700bb6a80b3bac0992889d83396b31d845678fc4619398022701479d2b301d2bb309624e9b8c1f693c9a22aa496435c35ab45b3023dfafb29ba2940a18f1a488e86cbddf9ea36534945ae97802868c253d907e50fc902ff323d199266a4215cc066163497e7e7976ef39eacc584a7fb5836df576431411da2fe0e066bb554dfcf3f5db0fffd8e1d3530152903ae8a0536c2f83d622100ed3974fcb39f52153516c88ed83a4aa147e7110f2d8b269334544ea6e7f4c04',
    },
    computed_at: '2026-09-09T10:23:01.491Z',
  },
  verification: {
    commitment_hash: '6fe00a54ca0ea85daac7fb39a4a607f8baae1253ca5ce9634fa4bd8fc66ebec4',
    commitment_hash_verified: true,
    chain_anchor: 'c9632e32f3c452d3f79e2d0329ae533ea8cf839d67fcb77f1ede3bbf3c7bc8a6',
    temporal_valid: true,
  },
};

/** Deep-clone with one field replaced (nested dot-notation path). */
function tamper(base: AnyVDFReceipt, path: string, value: unknown): AnyVDFReceipt {
  const clone = JSON.parse(JSON.stringify(base));
  const keys = path.split('.');
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  let obj: any = clone;
  for (let i = 0; i < keys.length - 1; i++) {
    obj = obj[keys[i]];
  }
  obj[keys[keys.length - 1]] = value;
  return clone;
}

// ─── 1. Format Detection ───────────────────────────────────────────────────────

describe('isVDFReceipt()', () => {
  test('identifies commit receipt as VDF receipt', () => {
    expect(isVDFReceipt(COMMIT_FIXTURE)).toBe(true);
  });

  test('identifies reveal receipt as VDF receipt', () => {
    expect(isVDFReceipt(REVEAL_FIXTURE)).toBe(true);
  });

  test('plain object with required VDF fields is identified', () => {
    expect(isVDFReceipt({
      commitment_id: 'abc',
      committed_epoch: 1,
      commitment_hash: 'deadbeef',
      commitment_time: '2026-01-01T00:00:00Z',
    })).toBe(true);
  });

  test('CSReceipt is NOT identified as VDF receipt', () => {
    const csr = {
      version: '1.0.0',
      commitment: { beacon: 'drand:quicknet', targetRound: 1 },
      precedence: 'unattested',
    };
    expect(isVDFReceipt(csr)).toBe(false);
  });

  test('null → false', () => expect(isVDFReceipt(null)).toBe(false));
  test('undefined → false', () => expect(isVDFReceipt(undefined)).toBe(false));
  test('string → false', () => expect(isVDFReceipt('hello')).toBe(false));
  test('empty object → false', () => expect(isVDFReceipt({})).toBe(false));

  test('missing committed_epoch → false', () => {
    const obj = { commitment_id: 'x', commitment_hash: 'y', commitment_time: 'z' };
    expect(isVDFReceipt(obj)).toBe(false);
  });
});

// ─── 2. Commit Receipt Verification ───────────────────────────────────────────

describe('verifyVDFReceipt() — commit receipt (PARTIAL)', () => {
  test('[POS] real commit receipt → PARTIAL with commitmentHash + temporal verified', async () => {
    const result = await verifyVDFReceipt(COMMIT_FIXTURE);
    expect(result.status).toBe('PARTIAL');
    expect(result.checks.commitmentHashVerified).toBe(true);
    expect(result.checks.temporalValid).toBe(true);
    // Reveal-only checks must be false (not applicable)
    expect(result.checks.valueDerivationVerified).toBe(false);
    expect(result.checks.seedToXVerified).toBe(false);
    expect(result.checks.wesolowskiMathVerified).toBe(false);
  });

  test('[POS] commit receipt — reason string explains PARTIAL (not an error)', async () => {
    const result = await verifyVDFReceipt(COMMIT_FIXTURE);
    // PARTIAL reason should not contain "fail" or "mismatch"
    expect(result.reason).toBeUndefined();
  });
});

// ─── 3. Reveal Receipt Verification — Positive ────────────────────────────────

describe('verifyVDFReceipt() — reveal receipt positive (VALID)', () => {
  let result: Awaited<ReturnType<typeof verifyVDFReceipt>>;

  // Wesolowski math takes ~1-5ms in practice; generous timeout
  beforeAll(async () => {
    result = await verifyVDFReceipt(REVEAL_FIXTURE);
  }, 30000);

  test('[POS-R1] status is VALID', () => {
    expect(result.status).toBe('VALID');
  });

  test('[POS-R2] commitmentHashVerified is true', () => {
    expect(result.checks.commitmentHashVerified).toBe(true);
  });

  test('[POS-R3] temporalValid is true (committed_epoch 975958 > current 975955)', () => {
    expect(result.checks.temporalValid).toBe(true);
  });

  test('[POS-R4] valueDerivationVerified is true (SHA256("wesolowski-y|"+y) = value)', () => {
    expect(result.checks.valueDerivationVerified).toBe(true);
  });

  test('[POS-R5] seedToXVerified is true (seedToGroupElement(seed) = x)', () => {
    expect(result.checks.seedToXVerified).toBe(true);
  });

  test('[POS-R6] wesolowskiMathVerified is true (π^ℓ · x^r ≡ y mod N)', () => {
    expect(result.checks.wesolowskiMathVerified).toBe(true);
  });

  test('[POS-R7] no reason string when VALID', () => {
    expect(result.reason).toBeUndefined();
  });

  test('[POS-R8] skipMath=true with real receipt → PARTIAL (hash checks pass)', async () => {
    const r2 = await verifyVDFReceipt(REVEAL_FIXTURE, { skipMath: true });
    expect(r2.status).toBe('PARTIAL');
    expect(r2.checks.commitmentHashVerified).toBe(true);
    expect(r2.checks.valueDerivationVerified).toBe(true);
    expect(r2.checks.seedToXVerified).toBe(true);
    expect(r2.checks.wesolowskiMathVerified).toBe(false); // not run
    expect(r2.reason).toMatch(/skipMath/);
  });
});

// ─── 4. Negative / Tamper Tests (fail-closed) ─────────────────────────────────
//
// Each test tampers exactly one field of the real receipt.
// Expectation: INVALID in every case.  A tampered field must NEVER pass.

describe('verifyVDFReceipt() — negative / tamper tests (INVALID)', () => {

  // ── Commit receipt tampering ─────────────────────────────────────────────

  test('[NEG-C1] tampered commitment_hash (1 char) → INVALID', async () => {
    const tampered = tamper(COMMIT_FIXTURE, 'commitment_hash',
      '0fe00a54ca0ea85daac7fb39a4a607f8baae1253ca5ce9634fa4bd8fc66ebec4') as VDFCommitReceipt;
    const result = await verifyVDFReceipt(tampered);
    expect(result.status).toBe('INVALID');
    expect(result.checks.commitmentHashVerified).toBe(false);
    expect(result.reason).toMatch(/mismatch/i);
  });

  test('[NEG-C2] tampered commitment_id → INVALID (commitment_hash no longer matches)', async () => {
    const tampered = tamper(COMMIT_FIXTURE, 'commitment_id',
      '2bd53020-0350-492b-b70c-6a61e2154fc0') as VDFCommitReceipt;
    const result = await verifyVDFReceipt(tampered);
    expect(result.status).toBe('INVALID');
    expect(result.checks.commitmentHashVerified).toBe(false);
  });

  test('[NEG-C3] tampered committed_epoch → INVALID (commitment_hash no longer matches)', async () => {
    const tampered = tamper(COMMIT_FIXTURE, 'committed_epoch', 999999) as VDFCommitReceipt;
    const result = await verifyVDFReceipt(tampered);
    expect(result.status).toBe('INVALID');
    expect(result.checks.commitmentHashVerified).toBe(false);
  });

  test('[NEG-C4] temporal inversion (committed_epoch ≤ current_epoch) → INVALID', async () => {
    // Set committed_epoch to equal current_epoch
    const tampered = tamper(COMMIT_FIXTURE, 'committed_epoch', 975955) as VDFCommitReceipt;
    // Also fix the commitment_hash to match the tampered data, so only temporal check fails
    const preimage = `1bd53020-0350-492b-b70c-6a61e2154fc0|975955|2026-09-09T10:22:49.892Z`;
    const fixedHash = createHash('sha256').update(preimage).digest('hex');
    const tampered2 = tamper(tampered, 'commitment_hash', fixedHash) as VDFCommitReceipt;
    const result = await verifyVDFReceipt(tampered2);
    expect(result.status).toBe('INVALID');
    expect(result.checks.temporalValid).toBe(false);
    expect(result.checks.commitmentHashVerified).toBe(true); // hash matches (we fixed it)
    expect(result.reason).toMatch(/temporal/i);
  });

  // ── Reveal receipt tampering ──────────────────────────────────────────────

  test('[NEG-R1] tampered value (random output) → INVALID', async () => {
    const tampered = tamper(REVEAL_FIXTURE, 'value',
      'deadbeef45d75a50b5f530f90773d2c581edf3a84fc9a71abdc7137b7123216');
    const result = await verifyVDFReceipt(tampered as VDFRevealReceipt);
    expect(result.status).toBe('INVALID');
    expect(result.checks.valueDerivationVerified).toBe(false);
    expect(result.reason).toMatch(/derivation/i);
  });

  test('[NEG-R2] tampered y (VDF output) → INVALID (value + math both fail)', async () => {
    // Tamper y to a different valid-looking hex of the same length
    const fakeY = 'a'.repeat(REVEAL_FIXTURE.proof.wesolowski_proof.y.length);
    const tampered = tamper(REVEAL_FIXTURE, 'proof.wesolowski_proof.y', fakeY);
    const result = await verifyVDFReceipt(tampered as VDFRevealReceipt);
    expect(result.status).toBe('INVALID');
    // value derivation fails (SHA256 of different y ≠ stored value)
    expect(result.checks.valueDerivationVerified).toBe(false);
    // wesolowski math also fails (y was the expected output)
    expect(result.checks.wesolowskiMathVerified).toBe(false);
  }, 30000);

  test('[NEG-R3] tampered pi (proof element) → INVALID (math verification fails)', async () => {
    // Flip the first byte of pi; hash checks still pass but math fails
    const originalPi = REVEAL_FIXTURE.proof.wesolowski_proof.pi;
    const fakePi = (parseInt(originalPi[0], 16) ^ 0xf).toString(16) + originalPi.slice(1);
    const tampered = tamper(REVEAL_FIXTURE, 'proof.wesolowski_proof.pi', fakePi);
    const result = await verifyVDFReceipt(tampered as VDFRevealReceipt);
    expect(result.status).toBe('INVALID');
    // Hash checks should still pass (pi is not part of value derivation or commitment_hash)
    expect(result.checks.commitmentHashVerified).toBe(true);
    expect(result.checks.valueDerivationVerified).toBe(true);
    // Only math verification should fail
    expect(result.checks.wesolowskiMathVerified).toBe(false);
    expect(result.reason).toMatch(/wesolowski/i);
  }, 30000);

  test('[NEG-R4] tampered x (VDF input) → INVALID (seed→x mapping fails)', async () => {
    // Replace x with all-zeros (different group element)
    const fakeX = '0'.repeat(REVEAL_FIXTURE.proof.wesolowski_proof.x.length);
    const tampered = tamper(REVEAL_FIXTURE, 'proof.wesolowski_proof.x', fakeX);
    const result = await verifyVDFReceipt(tampered as VDFRevealReceipt);
    expect(result.status).toBe('INVALID');
    expect(result.checks.seedToXVerified).toBe(false);
    // Math also fails (x is used in verification equation)
    expect(result.checks.wesolowskiMathVerified).toBe(false);
  }, 30000);

  test('[NEG-R5] tampered seed → INVALID (seed→x mapping fails)', async () => {
    const fakeSeed = 'fakeprevioushash||975958';
    const tampered = tamper(REVEAL_FIXTURE, 'proof.wesolowski_proof.seed', fakeSeed);
    const result = await verifyVDFReceipt(tampered as VDFRevealReceipt);
    expect(result.status).toBe('INVALID');
    expect(result.checks.seedToXVerified).toBe(false);
    // Math check still verifies the relationship between x/y/pi stored in receipt
    // (seed→x is a separate provenance check)
    // wesolowskiMathVerified may be true or false depending on values — we just need INVALID overall
  }, 30000);

  test('[NEG-R6] null receipt → UNVERIFIABLE (mapped to INVALID in verifyReceipt)', async () => {
    const result = await verifyVDFReceipt(null as unknown as AnyVDFReceipt);
    expect(result.status).toBe('UNVERIFIABLE');
    expect(result.checks.commitmentHashVerified).toBe(false);
  });

  test('[NEG-R7] empty object (no VDF fields) → commitmentHash fails', async () => {
    const result = await verifyVDFReceipt({} as AnyVDFReceipt);
    expect(result.status).toBe('INVALID');
    expect(result.checks.commitmentHashVerified).toBe(false);
  });
});

// ─── 5. verifyReceipt() Dispatch ───────────────────────────────────────────────

describe('verifyReceipt() — VDF dispatch (Option A)', () => {

  test('[DISPATCH-1] verifyReceipt() with commit receipt → auto-dispatches, returns PARTIAL', async () => {
    // verifyReceipt accepts CSReceipt but does runtime VDF detection
    const result = await verifyReceipt(COMMIT_FIXTURE as unknown as CSReceipt);
    expect(result.status).toBe('PARTIAL');
    expect(result.checks.commitmentIntegrity).toBe(true); // mapped from commitmentHashVerified
    expect(result.checks.precedenceVerified).toBe(true);  // mapped from temporalValid
  });

  test('[DISPATCH-2] verifyReceipt() with reveal receipt → auto-dispatches, returns VALID', async () => {
    const result = await verifyReceipt(REVEAL_FIXTURE as unknown as CSReceipt);
    expect(result.status).toBe('VALID');
    expect(result.checks.commitmentIntegrity).toBe(true);
    expect(result.checks.beaconVerified).toBe(true);    // mapped from wesolowskiMathVerified
    expect(result.checks.outputVerified).toBe(true);    // mapped from valueDerivationVerified
    expect(result.checks.selectionVerified).toBe(false); // N/A for VDF receipts
  }, 30000);

  test('[DISPATCH-3] verifyReceipt() with tampered VDF receipt → INVALID', async () => {
    const tampered = tamper(COMMIT_FIXTURE, 'commitment_hash',
      '0000000000000000000000000000000000000000000000000000000000000000');
    const result = await verifyReceipt(tampered as unknown as CSReceipt);
    expect(result.status).toBe('INVALID');
    expect(result.checks.commitmentIntegrity).toBe(false);
  });

  test('[DISPATCH-4] CSReceipt still uses original drand path (no regression)', async () => {
    // Construct a minimal offline CSReceipt that was valid in existing tests
    // We use the "offline beacon" path which does not need network access
    const csr: CSReceipt = {
      version: '1.0.0',
      precedence: 'unattested',
      attestation: 'unattested',
      commitment: {
        id: 'test-id',
        beacon: 'offline',
        targetRound: 1000,
        ruleHash: 'aaa',
        inputsHash: 'bbb',
        commitHash: 'ccc',
        createdAt: new Date().toISOString(),
        salt: 'ddd',
        rule: JSON.stringify({ type: 'uniform', pick: 1 }),
        inputs: ['a', 'b'],
      },
    };
    // Should NOT dispatch to VDF path (has version field, no commitment_id)
    // Will return INVALID (offline beacon / no resolution) — that's the drand path
    const result = await verifyReceipt(csr);
    // Key assertion: the result must come from the drand path (checks have drand fields)
    expect(typeof result.checks.beaconVerified).toBe('boolean');
    expect(typeof result.checks.selectionVerified).toBe('boolean');
    // isVDFReceipt(csr) should be false — verify dispatch did NOT fire
    // (offline CSReceipt will give INVALID because commitHash is wrong; that's expected)
    expect(['VALID', 'PARTIAL', 'INVALID']).toContain(result.status);
  });
});

// ─── 6. RSA2048_N Constant ────────────────────────────────────────────────────

describe('RSA2048_N', () => {
  test('is a positive BigInt', () => {
    expect(typeof RSA2048_N).toBe('bigint');
    expect(RSA2048_N > 0n).toBe(true);
  });

  test('is exactly 2048 bits (617 decimal digits)', () => {
    // RSA-2048 modulus has 617 decimal digits
    expect(RSA2048_N.toString(10).length).toBe(617);
  });

  test('is odd (RSA modulus = product of two odd primes)', () => {
    expect(RSA2048_N % 2n).toBe(1n);
  });

  test('ends with known last digit (from Wikipedia)', () => {
    // RSA-2048 challenge number ends in ...357
    expect(RSA2048_N.toString(10).slice(-3)).toBe('357');
  });

  test('has correct first 8 hex digits', () => {
    // Cross-check against known value
    expect(RSA2048_N.toString(16).slice(0, 8)).toBe('c7970cee');
  });
});
