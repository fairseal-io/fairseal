/**
 * @fairseal/game — Session lifecycle
 * createSession, awaitSession, closeSession, rotateClientSeed
 */

import { createHash, createHmac, randomBytes } from 'node:crypto';
import type { GameSession, GameSessionConfig, SessionReceipt } from './types.js';
import { computeMerkleRoot } from './receipt.js';

/**
 * Create a new game session.
 *
 * Commits serverSeed hash and derives session_seed using a beacon output.
 * For v0.1.0: uses an offline/simulated beacon (immediate resolution).
 * Future versions will integrate with @fairseal/commit for real drand beacons.
 *
 * @param config - Session configuration
 * @returns Active GameSession with locked session seed
 */
export async function createSession(config: GameSessionConfig): Promise<GameSession> {
  const serverSeedHash = createHash('sha256').update(config.serverSeed).digest('hex');
  const sessionId = 'fs_' + randomBytes(6).toString('hex');

  // v0.1.0: offline beacon (immediate resolution)
  // Future: integrate with @fairseal/commit for real drand
  const beaconOutput = randomBytes(32).toString('hex');
  const beaconRound = Math.floor(Date.now() / 3000); // simulated round

  // Derive session seed
  // Mode A (provably-fair): beacon + clientSeed
  // Mode B (audit-only): beacon only
  const sessionSeedInput =
    config.mode === 'provably-fair' && config.clientSeed
      ? beaconOutput + config.clientSeed
      : beaconOutput;

  const sessionSeed = createHmac('sha256', config.serverSeed)
    .update(sessionSeedInput)
    .digest('hex');

  return {
    sessionId,
    sessionSeed,
    commitmentHash: serverSeedHash,
    beaconRound,
    beaconOutput,
    mode: config.mode,
    paytableHash: config.paytableHash,
    state: 'active',
    _serverSeed: config.serverSeed,
    _clientSeed: config.clientSeed,
    _gameId: config.gameId,
    _spinLog: [],
  };
}

/**
 * Wait for session to become active (beacon resolved).
 * In v0.1.0 with offline beacon, this resolves immediately.
 *
 * @param session - Pending or active session
 * @returns Active session
 */
export async function awaitSession(session: GameSession): Promise<GameSession> {
  // v0.1.0: offline beacon means session is immediately active
  if (session.state === 'active') {
    return session;
  }
  throw new Error(`Session ${session.sessionId} is in state '${session.state}', expected 'pending' or 'active'`);
}

/**
 * Close a session. Reveals serverSeed and generates receipt.
 *
 * @param session - Active session to close
 * @returns Full session receipt with Merkle root
 */
export async function closeSession(session: GameSession): Promise<SessionReceipt> {
  if (session.state === 'closed') {
    throw new Error(`Session ${session.sessionId} is already closed`);
  }

  session.state = 'closed';

  // Generate Merkle root from spin log
  const leaves = session._spinLog.map((s) => s.resultHash);
  const merkleRoot = computeMerkleRoot(leaves);

  return {
    sessionId: session.sessionId,
    gameId: session._gameId,
    mode: session.mode,
    commitmentHash: session.commitmentHash,
    beaconRound: session.beaconRound,
    beaconOutput: session.beaconOutput,
    paytableHash: session.paytableHash,
    serverSeed: session._serverSeed,
    clientSeed: session._clientSeed,
    spinLog: [...session._spinLog],
    merkleRoot,
  };
}

/**
 * Rotate client seed mid-session (Mode A only).
 * Closes the current session, generates receipt, and opens a new session
 * inheriting the gameId and paytableHash.
 *
 * @param session - Active session to rotate
 * @param newClientSeed - New player-provided seed
 * @returns Closed receipt + new active session
 */
export async function rotateClientSeed(
  session: GameSession,
  newClientSeed: string,
): Promise<{ closedReceipt: SessionReceipt; newSession: GameSession }> {
  if (session.mode !== 'provably-fair') {
    throw new Error('rotateClientSeed is only available in provably-fair mode');
  }

  const closedReceipt = await closeSession(session);

  const newSession = await createSession({
    mode: 'provably-fair',
    serverSeed: randomBytes(32).toString('hex'), // fresh server seed
    clientSeed: newClientSeed,
    gameId: session._gameId,
    paytableHash: session.paytableHash,
  });

  return { closedReceipt, newSession };
}
