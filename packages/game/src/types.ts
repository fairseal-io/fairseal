/**
 * @fairseal/game — Type definitions
 * Based on RFC-001: Seed Commitment Model
 */

/** Session configuration for createSession(). */
export interface GameSessionConfig {
  /** Mode A: full PF. Mode B: GLI-safe audit-only. */
  mode: 'provably-fair' | 'audit-only';

  /** Server-generated cryptographic seed. */
  serverSeed: string;

  /** Optional player-provided seed (Mode A only; ignored in Mode B). */
  clientSeed?: string;

  /** Beacon source. Default: 'drand:quicknet'. Use 'offline' for demos. */
  beaconId?: string;

  /** Game identifier for receipt anchoring. */
  gameId: string;

  /** Paytable hash — committed at session start for verification. */
  paytableHash: string;

  /** Session timeout in ms. Default: 30 minutes. */
  timeoutMs?: number;
}

/** Active game session with locked session seed. */
export interface GameSession {
  /** Unique session identifier. */
  sessionId: string;

  /** Locked session seed (available after beacon resolves). */
  sessionSeed: string;

  /** Commitment hash (shown to player before play). */
  commitmentHash: string;

  /** drand round used for seed locking. */
  beaconRound: number;

  /** Beacon randomness value. */
  beaconOutput: string;

  /** Active mode. */
  mode: 'provably-fair' | 'audit-only';

  /** Committed paytable hash. */
  paytableHash: string;

  /** Session state. */
  state: 'pending' | 'active' | 'closed' | 'expired';

  // ── Internal fields (not serialized to player) ──

  /** @internal Server seed for receipt generation. */
  _serverSeed: string;

  /** @internal Client seed for receipt generation. */
  _clientSeed?: string;

  /** @internal Game ID. */
  _gameId: string;

  /** @internal Ordered log of committed spins. */
  _spinLog: SpinLogEntry[];
}

/** Result of a single spin derivation. */
export interface SpinResult {
  /** Sequential spin index (0-based). */
  spinIndex: number;

  /** Raw entropy: HMAC(session_seed, derivation_path). */
  entropy: string;

  /** Derivation path used (e.g., "spin:0"). */
  path: string;

  /** Result hash for compact API response. */
  resultHash: string;
}

/** Sub-result for free spins, cascades, bonuses. */
export interface SubResult extends SpinResult {
  /** Parent spin index. */
  parentSpinIndex: number;

  /** Sub-event type. */
  subType: 'freespin' | 'cascade' | 'respin' | 'bonus' | string;

  /** Sub-event index within parent. */
  subIndex: number;
}

/** Entry in the session spin log. */
export interface SpinLogEntry {
  spinIndex: number;
  path: string;
  resultHash: string;
  subResults?: SubResult[];
  /** Operator transaction reference (opaque to FairSeal). */
  txRef?: string;
}

/** Full session receipt (returned on closeSession). */
export interface SessionReceipt {
  /** Session metadata. */
  sessionId: string;
  gameId: string;
  mode: 'provably-fair' | 'audit-only';
  commitmentHash: string;
  beaconRound: number;
  beaconOutput: string;
  paytableHash: string;

  /** Server seed (revealed at session close). */
  serverSeed: string;

  /** Client seed (Mode A only). */
  clientSeed?: string;

  /** Ordered log of all committed spins. */
  spinLog: SpinLogEntry[];

  /** Merkle root of all spin results. */
  merkleRoot: string;

  /** On-chain anchor reference (if anchored). */
  anchor?: {
    chain: string;
    txHash: string;
    blockNumber: number;
  };
}

/** Result of verifySession(). */
export interface VerificationResult {
  valid: boolean;
  sessionId: string;
  /** Per-spin verification. */
  spins: Array<{
    spinIndex: number;
    valid: boolean;
    expected: string;
    actual: string;
  }>;
  /** Beacon verification (drand signature check). */
  beaconValid: boolean | null;
  /** Merkle root verification. */
  merkleValid: boolean;
  /** Anchor verification (if anchored). */
  anchorValid?: boolean;
  /** Human-readable summary. */
  summary: string;
}
