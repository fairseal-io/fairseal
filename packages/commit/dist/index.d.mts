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
 * Verify a complete CSReceipt from scratch — no trust in the issuer.
 * Every check is independently reproducible.
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

export { type AnchorProof, type BeaconConfig, type BeaconRound, type BeaconSource, type CSReceipt, CachedBeaconSource, type Commitment, type CommitmentOptions, DRAND_QUICKNET, DrandBeaconSource, OfflineBeaconSource, type PrecedenceType, type Resolution, type ResolveOptions, type VerificationResult, type VerificationStatus, applyRule, computeCommitHash, createCommitment, createDefaultBeacon, createReceipt, deriveOutput, fromHex, getBeaconSource, hashInputs, hashRule, registerBeacon, resolveCommitment, sha256, toHex, validateRule, verifyReceipt, waitAndResolve };
