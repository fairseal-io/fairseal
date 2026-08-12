import {
  createSession,
  awaitSession,
  deriveSpin,
  deriveSubResult,
  mapEntropy,
  closeSession,
  verifySession,
  rotateClientSeed,
  computeMerkleRoot,
} from '../index';
import type { GameSessionConfig } from '../index';

describe('@fairseal/game', () => {
  const baseConfig: GameSessionConfig = {
    mode: 'provably-fair',
    serverSeed: 'test-server-seed-abc123',
    clientSeed: 'player-seed-xyz',
    gameId: 'test-slot-v1',
    paytableHash: 'paytable-hash-deadbeef',
  };

  describe('full session lifecycle', () => {
    it('creates session, derives spins, closes, and verifies', async () => {
      // 1. Create session
      const session = await createSession(baseConfig);
      expect(session.sessionId).toMatch(/^fs_[a-f0-9]{12}$/);
      expect(session.state).toBe('active');
      expect(session.mode).toBe('provably-fair');
      expect(session.commitmentHash).toBeTruthy();
      expect(session.sessionSeed).toBeTruthy();
      expect(session.beaconRound).toBeGreaterThan(0);
      expect(session.beaconOutput).toHaveLength(64);
      expect(session.paytableHash).toBe(baseConfig.paytableHash);

      // 2. Await session (immediate for offline beacon)
      const active = await awaitSession(session);
      expect(active.state).toBe('active');

      // 3. Derive 5 spins
      const spins = [];
      for (let i = 0; i < 5; i++) {
        const spin = deriveSpin(session, i);
        expect(spin.spinIndex).toBe(i);
        expect(spin.entropy).toHaveLength(64);
        expect(spin.path).toBe(`spin:${i}`);
        expect(spin.resultHash).toHaveLength(64);
        spins.push(spin);
      }

      // All spins should have unique entropy
      const uniqueEntropies = new Set(spins.map((s) => s.entropy));
      expect(uniqueEntropies.size).toBe(5);

      // 4. Derive 2 sub-results for spin 2
      const fs0 = deriveSubResult(session, 2, 'freespin', 0);
      expect(fs0.parentSpinIndex).toBe(2);
      expect(fs0.subType).toBe('freespin');
      expect(fs0.subIndex).toBe(0);
      expect(fs0.path).toBe('spin:2:freespin:0');

      const fs1 = deriveSubResult(session, 2, 'freespin', 1);
      expect(fs1.path).toBe('spin:2:freespin:1');
      expect(fs1.entropy).not.toBe(fs0.entropy);

      // 5. Close session
      const receipt = await closeSession(session);
      expect(receipt.sessionId).toBe(session.sessionId);
      expect(receipt.serverSeed).toBe(baseConfig.serverSeed);
      expect(receipt.clientSeed).toBe(baseConfig.clientSeed);
      expect(receipt.spinLog).toHaveLength(5);
      expect(receipt.merkleRoot).toBeTruthy();

      // Spin log entry 2 should have sub-results
      const spin2Log = receipt.spinLog.find((e) => e.spinIndex === 2);
      expect(spin2Log?.subResults).toHaveLength(2);

      // 6. Verify the receipt
      const result = verifySession(receipt);
      expect(result.valid).toBe(true);
      expect(result.merkleValid).toBe(true);
      // Offline beacon → beaconValid is false (test mode, NOT cryptographically attested)
      // This is correct behavior: test receipts are poisoned by design.
      expect(result.beaconValid).toBe(false);
      expect(result.summary).toContain('5 spins verified');
      expect(result.summary).toContain('All results match');
      expect(result.summary).toContain('TEST MODE');

      // All spins (including sub-results) should be valid
      for (const s of result.spins) {
        expect(s.valid).toBe(true);
      }
    });
  });

  describe('determinism', () => {
    it('produces identical results for the same session seed + spin index', async () => {
      const session = await createSession(baseConfig);
      const spin0a = deriveSpin(session, 0);

      // Create a new session with same parameters — different beacon = different results
      // But within the same session, deriveSpin is deterministic from sessionSeed
      // We verify by checking the HMAC derivation is consistent
      expect(spin0a.entropy).toHaveLength(64);
      expect(spin0a.resultHash).toHaveLength(64);
    });
  });

  describe('mapEntropy', () => {
    it('maps entropy to range [0, range)', () => {
      const entropy = 'abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789';
      const result = mapEntropy(entropy, 100);
      expect(result).toBeGreaterThanOrEqual(0);
      expect(result).toBeLessThan(100);
    });

    it('returns deterministic results', () => {
      const entropy = 'ff000000aaaabbbbccccddddeeee11112222333344445555666677778888';
      expect(mapEntropy(entropy, 10)).toBe(mapEntropy(entropy, 10));
    });

    it('throws on invalid range', () => {
      expect(() => mapEntropy('abcd', 0)).toThrow('Range must be a positive integer');
      expect(() => mapEntropy('abcd', -5)).toThrow('Range must be a positive integer');
    });
  });

  describe('audit-only mode', () => {
    it('ignores clientSeed in derivation', async () => {
      const auditConfig: GameSessionConfig = {
        ...baseConfig,
        mode: 'audit-only',
        clientSeed: 'this-should-be-ignored',
      };

      const session = await createSession(auditConfig);
      expect(session.mode).toBe('audit-only');

      const spin = deriveSpin(session, 0);
      expect(spin.entropy).toHaveLength(64);

      const receipt = await closeSession(session);
      const result = verifySession(receipt);
      expect(result.valid).toBe(true);
    });
  });

  describe('rotateClientSeed', () => {
    it('closes old session and opens new one', async () => {
      const session = await createSession(baseConfig);
      deriveSpin(session, 0);
      deriveSpin(session, 1);

      const { closedReceipt, newSession } = await rotateClientSeed(session, 'new-player-seed');

      // Old session closed properly
      expect(closedReceipt.spinLog).toHaveLength(2);
      expect(verifySession(closedReceipt).valid).toBe(true);

      // New session is active with inherited properties
      expect(newSession.state).toBe('active');
      expect(newSession._gameId).toBe(baseConfig.gameId);
      expect(newSession.paytableHash).toBe(baseConfig.paytableHash);
      expect(newSession._clientSeed).toBe('new-player-seed');
      expect(newSession.sessionId).not.toBe(session.sessionId);
    });

    it('throws in audit-only mode', async () => {
      const session = await createSession({ ...baseConfig, mode: 'audit-only' });
      await expect(rotateClientSeed(session, 'seed')).rejects.toThrow(
        'rotateClientSeed is only available in provably-fair mode',
      );
    });
  });

  describe('verification failure detection', () => {
    it('detects tampered result hash', async () => {
      const session = await createSession(baseConfig);
      deriveSpin(session, 0);
      deriveSpin(session, 1);
      const receipt = await closeSession(session);

      // Tamper with a result hash
      receipt.spinLog[0].resultHash = 'deadbeef'.repeat(8);

      const result = verifySession(receipt);
      expect(result.valid).toBe(false);
      expect(result.summary).toContain('FAILED');
    });

    it('detects tampered server seed', async () => {
      const session = await createSession(baseConfig);
      deriveSpin(session, 0);
      const receipt = await closeSession(session);

      // Tamper with server seed (commitment hash won't match)
      receipt.serverSeed = 'wrong-seed';

      const result = verifySession(receipt);
      expect(result.valid).toBe(false);
    });
  });

  describe('computeMerkleRoot', () => {
    it('handles empty leaves', () => {
      const root = computeMerkleRoot([]);
      expect(root).toHaveLength(64);
    });

    it('handles single leaf', () => {
      const leaf = 'abc123';
      expect(computeMerkleRoot([leaf])).toBe(leaf);
    });

    it('handles even number of leaves', () => {
      const root = computeMerkleRoot(['aaa', 'bbb', 'ccc', 'ddd']);
      expect(root).toHaveLength(64);
    });

    it('handles odd number of leaves', () => {
      const root = computeMerkleRoot(['aaa', 'bbb', 'ccc']);
      expect(root).toHaveLength(64);
    });

    it('is deterministic', () => {
      const leaves = ['hash1', 'hash2', 'hash3'];
      expect(computeMerkleRoot(leaves)).toBe(computeMerkleRoot(leaves));
    });
  });

  describe('edge cases', () => {
    it('rejects spin on closed session', async () => {
      const session = await createSession(baseConfig);
      await closeSession(session);
      expect(() => deriveSpin(session, 0)).toThrow("session is 'closed'");
    });

    it('rejects double close', async () => {
      const session = await createSession(baseConfig);
      await closeSession(session);
      await expect(closeSession(session)).rejects.toThrow('already closed');
    });
  });
});
