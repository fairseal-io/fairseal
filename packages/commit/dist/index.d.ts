/**
 * @fairseal/commit — Trustless committed selections
 *
 * Types for the commitment protocol: commit to a rule before
 * the entropy is knowable, then verify the selection was fair.
 */
interface BeaconConfig {
    /** Beacon identifier, e.g. "drand:quicknet" */
    id: string;
    /** Chain hash for the beacon network */
    chainHash: string;
    /** Round period in seconds */
    period: number;
    /** Genesis time (Unix seconds) */
    genesisTime: number;
    /** BLS public key (hex) for signature verification */
    publicKey: string;
    /** Relay URLs for fetching beacon rounds */
    relays: string[];
}
interface BeaconRound {
    round: number;
    randomness: string;
    signature: string;
}
interface BeaconSource {
    readonly config: BeaconConfig;
    /** Compute the round number for a given Unix timestamp */
    getRound(unixSeconds: number): number;
    /** Compute the wall-clock time a round will be available */
    getRoundTime(round: number): number;
    /** Fetch a specific beacon round from relays */
    fetchBeacon(round: number): Promise<BeaconRound>;
    /** Verify a beacon round's BLS signature */
    verifyBeacon(beacon: BeaconRound): Promise<boolean>;
}
interface CommitmentOptions {
    /** Canonical JSON of the selection rule */
    rule: string;
    /** Candidate set or input identifiers */
    inputs: string[];
    /** Seconds from now until reveal (mapped to targetRound) */
    revealAfter: number;
    /** Beacon identifier (default: "drand:quicknet") */
    beacon?: string;
    /** Random salt (generated if omitted) */
    salt?: Uint8Array;
    /** Optional metadata */
    metadata?: Record<string, unknown>;
}
interface Commitment {
    /** Unique commitment ID (hex, derived from commitHash) */
    id: string;
    /** Beacon identifier */
    beacon: string;
    /** Target beacon round (commitment is valid if anchored before this round) */
    targetRound: number;
    /** SHA-256 of the canonical rule */
    ruleHash: string;
    /** SHA-256 of the sorted, joined inputs */
    inputsHash: string;
    /** SHA-256(beacon ‖ targetRound ‖ ruleHash ‖ inputsHash ‖ salt) */
    commitHash: string;
    /** ISO 8601 creation timestamp */
    createdAt: string;
    /** Random salt (hex) */
    salt: string;
    /** The original rule (needed for resolution) */
    rule: string;
    /** The original inputs (needed for resolution) */
    inputs: string[];
    /** Optional metadata */
    metadata?: Record<string, unknown>;
}
type PrecedenceType = 'onchain' | 'counterparty-signed' | 'unattested';
interface AnchorProof {
    /** On-chain transaction hash */
    txHash: string;
    /** Block number containing the anchor tx */
    blockNumber: number;
    /** Block timestamp (Unix seconds) */
    blockTimestamp: number;
    /** Chain ID (e.g. 8453 for Base, 84532 for Base Sepolia) */
    chainId: number;
    /** Precedence type */
    precedence: PrecedenceType;
}
interface Resolution {
    /** The beacon round used */
    beaconRound: number;
    /** The beacon's BLS signature (hex) */
    beaconSignature: string;
    /** Beacon randomness (hex) */
    beaconRandomness: string;
    /** Whether the BLS signature was verified */
    verified: boolean;
    /** HMAC-SHA256(beacon.randomness, ruleHash ‖ inputsHash) */
    output: string;
    /** The derived selection result (rule applied to output) */
    selection: unknown;
}
interface CSReceipt {
    /** Receipt format version */
    version: '1.0.0';
    /** The original commitment */
    commitment: Commitment;
    /** Anchor proof (if anchored) */
    anchor?: AnchorProof;
    /** Resolution (if resolved) */
    resolution?: Resolution;
    /** Precedence type */
    precedence: PrecedenceType;
    /** Attestation tier */
    attestation: 'self-anchored' | 'fairseal' | 'unattested';
}
type VerificationStatus = 'VALID' | 'PARTIAL' | 'INVALID';
interface VerificationResult {
    /** Overall verification status */
    status: VerificationStatus;
    /** Individual check results */
    checks: {
        /** Commitment hash matches recomputed hash */
        commitmentIntegrity: boolean;
        /** Anchor timestamp precedes target round time */
        precedenceVerified: boolean;
        /** Beacon BLS signature is valid */
        beaconVerified: boolean;
        /** Output matches HMAC derivation from beacon + commitment */
        outputVerified: boolean;
        /** Selection matches rule applied to output */
        selectionVerified: boolean;
    };
    /** Human-readable reason if not VALID */
    reason?: string;
}

/**
 * @fairseal/commit — Commitment creation
 *
 * Creates a cryptographic commitment to a selection rule,
 * bound to a future drand beacon round.
 */

/**
 * Create a commitment to a selection rule, bound to a future beacon round.
 *
 * The commitment hash proves what rule and inputs were selected BEFORE
 * the beacon output is knowable. The targetRound is computed from
 * `revealAfter` seconds in the future.
 *
 * @example
 * ```typescript
 * const commitment = createCommitment({
 *   rule: JSON.stringify({ type: 'uniform', pick: 1 }),
 *   inputs: ['alice', 'bob', 'charlie'],
 *   revealAfter: 30, // reveal after 30 seconds
 * });
 * ```
 */
declare function createCommitment(opts: CommitmentOptions): Commitment;

/**
 * @fairseal/commit — Commitment resolution
 *
 * After the target beacon round elapses: fetch the beacon output,
 * verify its BLS signature, and derive the selection via HMAC.
 */

/**
 * Options for {@link resolveCommitment}.
 */
interface ResolveOptions {
    /**
     * If true, wait (poll) until the target beacon round becomes available
     * instead of throwing. Bounded by `maxWaitMs`.
     */
    wait?: boolean;
    /** Maximum total milliseconds to wait when `wait` is true. Default: 15000. */
    maxWaitMs?: number;
}
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
declare function resolveCommitment(commitment: Commitment, opts?: ResolveOptions): Promise<Resolution>;
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
declare function waitAndResolve(commitment: Commitment, opts?: Omit<ResolveOptions, 'wait'>): Promise<Resolution>;
/**
 * Create a complete receipt from a commitment, optional anchor, and resolution.
 */
declare function createReceipt(commitment: Commitment, resolution: Resolution, anchor?: {
    txHash: string;
    blockNumber: number;
    blockTimestamp: number;
    chainId: number;
}): CSReceipt;

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
declare function verifyReceipt(receipt: CSReceipt, options?: {
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
}): Promise<VerificationResult>;

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
/**
 * The RSA-2048 challenge modulus used by FairSeal's production VDF.
 * This is the standard nothing-up-my-sleeve number; its factorisation is unknown.
 */
declare const RSA2048_N = 25195908475657893494027183240048398571429282126204032027777137836043662020707595556264018525880784406918290641249515082189298559149176184502808489120072844992687392807287776735971418347270261896375014971824691165077613379859095700097330459748808428401797429100642458691817195118746121515172654632282216869987549182422433637259085141865462043576798423387184774447920739934236584823824281198163815010674810451660377306056201619676256133844143603833904414952634432190114657544454178424020924616515723350778707749817125772467962926386356373289912154831438167899885040445364023527381951378636564391212010397122822120720357n;
/** Wesolowski proof fields as stored in the FairSeal reveal receipt. */
interface WesolowskiProof {
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
interface VDFProof {
    vdf_output: string;
    previous_output: string;
    /** Same value as wesolowski_proof.pi */
    vdf_proof_input: string;
    wesolowski_proof: WesolowskiProof;
    computed_at: string;
}
/** Server-computed verification hints (informational; do NOT trust for soundness). */
interface VDFVerificationHints {
    commitment_hash: string;
    commitment_hash_verified: boolean;
    chain_anchor: string;
    temporal_valid: boolean;
}
/**
 * Commit receipt — returned by POST /v1/rng/commit (free endpoint).
 * The VDF has not yet run; only commitment integrity can be verified.
 */
interface VDFCommitReceipt {
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
interface VDFRevealReceipt {
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
type AnyVDFReceipt = VDFCommitReceipt | VDFRevealReceipt;
/**
 * Granular check results for a VDF receipt.
 *
 * Every field is independently verifiable.  A false value is never the
 * result of skipping — it means the check was attempted and failed (or
 * was not applicable, with a note in the reason string).
 */
interface VDFVerificationChecks {
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
interface VDFVerificationResult {
    status: 'VALID' | 'PARTIAL' | 'INVALID' | 'UNVERIFIABLE';
    checks: VDFVerificationChecks;
    /** Human-readable explanation for non-VALID statuses. */
    reason?: string;
}
/**
 * Type guard: returns true if `obj` is a FairSeal VDF receipt
 * (commit or reveal) from the /v1/rng/* endpoints.
 *
 * Identifies VDF receipts by the presence of `commitment_id`,
 * `committed_epoch`, `commitment_hash`, and `commitment_time` — fields
 * that are absent from drand-based CSReceipts (which use `version`, etc.).
 */
declare function isVDFReceipt(obj: unknown): obj is AnyVDFReceipt;
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
declare function verifyVDFReceipt(receipt: AnyVDFReceipt, options?: {
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
}): Promise<VDFVerificationResult>;

/**
 * @fairseal/commit — Beacon sources
 *
 * drand quicknet implementation with multi-relay failover.
 * Abstract interface supports future beacon sources (RANDAO, Pyth, etc.)
 */

declare const DRAND_QUICKNET: BeaconConfig;
declare class DrandBeaconSource implements BeaconSource {
    readonly config: BeaconConfig;
    constructor(config?: Partial<BeaconConfig>);
    /**
     * Compute the drand round number for a given Unix timestamp.
     * round = floor((t - genesis) / period) + 1
     */
    getRound(unixSeconds: number): number;
    /**
     * Compute the wall-clock time (Unix seconds) when a round becomes available.
     * time = genesis + (round - 1) * period
     */
    getRoundTime(round: number): number;
    /**
     * Fetch a beacon round from relays with failover.
     * Tries each relay in order; throws if all fail.
     */
    fetchBeacon(round: number): Promise<BeaconRound>;
    /**
     * Verify a beacon round's BLS12-381 signature cryptographically.
     *
     * This is REAL cryptographic verification using @noble/curves:
     * 1. Constructs the signed message: SHA-256(round as 8-byte big-endian)
     * 2. Hashes to G1 curve point using the quicknet DST
     * 3. Verifies BLS pairing: e(sig, G2_gen) == e(H(msg), pubkey)
     * 4. Confirms randomness = SHA-256(signature)
     *
     * No trust in any relay or server required.
     */
    verifyBeacon(beacon: BeaconRound): Promise<boolean>;
}
/**
 * Offline beacon source for demos and firewall environments.
 *
 * Generates deterministic (but NOT cryptographically random) beacons
 * from the round number using SHA-256. NOT suitable for production —
 * the output is predictable from the round number alone.
 *
 * Use `{ beaconId: 'offline' }` in CommitmentOptions to activate.
 */
declare class OfflineBeaconSource implements BeaconSource {
    readonly config: BeaconConfig;
    constructor();
    getRound(unixSeconds: number): number;
    getRoundTime(round: number): number;
    /**
     * Generate a deterministic beacon from the round number.
     * randomness = SHA-256("offline-beacon:" + round)
     * signature  = SHA-256("offline-sig:" + round)
     *
     * ⚠️ NOT cryptographically secure — suitable for demos only.
     */
    fetchBeacon(round: number): Promise<BeaconRound>;
    /**
     * Offline beacons are self-generated, so "verification" just checks
     * the deterministic derivation is consistent.
     */
    verifyBeacon(beacon: BeaconRound): Promise<boolean>;
}
/**
 * Caching wrapper around any BeaconSource.
 *
 * Caches fetched beacons in-memory. On fetch failure, returns the
 * cached value if available. Helps with intermittent connectivity
 * and avoids redundant relay requests.
 */
declare class CachedBeaconSource implements BeaconSource {
    readonly config: BeaconConfig;
    private readonly inner;
    private readonly cache;
    constructor(inner: BeaconSource);
    getRound(unixSeconds: number): number;
    getRoundTime(round: number): number;
    fetchBeacon(round: number): Promise<BeaconRound>;
    verifyBeacon(beacon: BeaconRound): Promise<boolean>;
    /** Check if a round is in the cache. */
    has(round: number): boolean;
    /** Pre-populate the cache (e.g. from stored receipts). */
    seed(beacon: BeaconRound): void;
    /** Clear all cached entries. */
    clear(): void;
}
/**
 * Default beacon source — drand quicknet with standard relays.
 */
declare function createDefaultBeacon(): BeaconSource;
declare function getBeaconSource(id: string): BeaconSource;
declare function registerBeacon(id: string, factory: () => BeaconSource): void;

/**
 * Apply a selection rule to derive a deterministic result from entropy.
 *
 * @param rule - Canonical JSON string of the rule
 * @param inputs - Candidate set
 * @param outputHex - HMAC output (hex string used as entropy source)
 * @returns The deterministic selection result
 */
declare function applyRule(rule: string, inputs: string[], outputHex: string): unknown;
/**
 * Validate a rule string. Returns true if the rule is parseable
 * and has a known type.
 */
declare function validateRule(rule: string): {
    valid: boolean;
    error?: string;
};

/**
 * @fairseal/commit — Cryptographic primitives
 *
 * SHA-256 hashing and HMAC derivation using Node.js built-in crypto.
 * No external dependencies.
 */
/**
 * SHA-256 hash of a UTF-8 string, returned as hex.
 */
declare function sha256(input: string): string;
/**
 * Generate a canonical hash for a selection rule.
 * The rule must be canonical JSON (deterministic key order).
 */
declare function hashRule(rule: string): string;
/**
 * Generate a canonical hash for input identifiers.
 * Inputs are sorted lexicographically and joined with newlines.
 */
declare function hashInputs(inputs: string[]): string;
/**
 * Generate a commitment hash.
 * commitHash = SHA-256(beacon ‖ targetRound ‖ ruleHash ‖ inputsHash ‖ salt)
 *
 * The separator '‖' is implemented as ':' to keep the hash deterministic
 * and avoid ambiguity.
 */
declare function computeCommitHash(beacon: string, targetRound: number, ruleHash: string, inputsHash: string, saltHex: string): string;
/**
 * Convert Uint8Array to hex string.
 */
declare function toHex(bytes: Uint8Array): string;
/**
 * Convert hex string to Uint8Array.
 */
declare function fromHex(hex: string): Uint8Array;
/**
 * Derive the selection output from beacon randomness and commitment data.
 * output = HMAC-SHA256(beacon.randomness, ruleHash ‖ inputsHash)
 */
declare function deriveOutput(beaconRandomness: string, ruleHash: string, inputsHash: string): string;

export { type AnchorProof, type AnyVDFReceipt, type BeaconConfig, type BeaconRound, type BeaconSource, type CSReceipt, CachedBeaconSource, type Commitment, type CommitmentOptions, DRAND_QUICKNET, DrandBeaconSource, OfflineBeaconSource, type PrecedenceType, RSA2048_N, type Resolution, type ResolveOptions, type VDFCommitReceipt, type VDFProof, type VDFRevealReceipt, type VDFVerificationChecks, type VDFVerificationHints, type VDFVerificationResult, type VerificationResult, type VerificationStatus, type WesolowskiProof, applyRule, computeCommitHash, createCommitment, createDefaultBeacon, createReceipt, deriveOutput, fromHex, getBeaconSource, hashInputs, hashRule, isVDFReceipt, registerBeacon, resolveCommitment, sha256, toHex, validateRule, verifyReceipt, verifyVDFReceipt, waitAndResolve };
