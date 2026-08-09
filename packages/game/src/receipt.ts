/**
 * @fairseal/game — Receipt utilities
 * Merkle tree construction for session receipts.
 */

import { createHash } from 'node:crypto';

/**
 * Compute the Merkle root of an array of hex-encoded leaf hashes.
 * Uses SHA-256 for internal nodes. Odd leaves are promoted unpaired.
 *
 * @param leaves - Array of hex-encoded hash strings
 * @returns Merkle root as hex string
 */
export function computeMerkleRoot(leaves: string[]): string {
  if (leaves.length === 0) {
    return createHash('sha256').update('empty').digest('hex');
  }
  if (leaves.length === 1) {
    return leaves[0];
  }

  let level = [...leaves];
  while (level.length > 1) {
    const next: string[] = [];
    for (let i = 0; i < level.length; i += 2) {
      if (i + 1 < level.length) {
        next.push(
          createHash('sha256')
            .update(level[i] + level[i + 1])
            .digest('hex'),
        );
      } else {
        // Odd leaf promoted unpaired
        next.push(level[i]);
      }
    }
    level = next;
  }
  return level[0];
}
