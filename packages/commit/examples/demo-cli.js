#!/usr/bin/env node
/**
 * 🦭 Fairseal Demo — run with: npx @fairseal/commit
 * 
 * Shows a verifiable gacha pull in your terminal.
 * No setup. No account. Just run it.
 */

const { createCommitment } = require('../dist/index.js');
const { resolveCommitment, createReceipt } = require('../dist/index.js');
const { verifyReceipt } = require('../dist/index.js');

const ITEMS = ['🌟 SSR Dragon Blade', '✨ SR Phoenix Staff', '✨ SR Thunder Bow', '🔵 R Iron Shield', '🔵 R Wind Cloak', '⚪ N Wooden Sword', '⚪ N Leather Armor'];

async function main() {
  console.log('');
  console.log('  🦭 Fairseal — Provably Fair Gacha Pull');
  console.log('  ═══════════════════════════════════════');
  console.log('');
  console.log('  Loot table: ' + ITEMS.length + ' items');
  console.log('  Committing to drop table before outcome...');

  const commitment = createCommitment({
    rule: JSON.stringify({ type: 'uniform', pick: 1 }),
    inputs: ITEMS,
    revealAfter: 6,
  });

  console.log('  ✅ Committed: ' + commitment.commitHash.slice(0, 16) + '...');
  console.log('  ⏳ Waiting for drand beacon (max ~6s)...');

  // Wait for beacon
  const { DrandBeaconSource } = require('../dist/index.js');
  const beacon = new DrandBeaconSource();
  const roundTime = beacon.getRoundTime(commitment.targetRound);
  const wait = Math.max(roundTime - Math.floor(Date.now() / 1000) + 1, 3) * 1000;
  await new Promise(r => setTimeout(r, wait));

  const resolution = await resolveCommitment(commitment);
  const receipt = createReceipt(commitment, resolution);
  const result = await verifyReceipt(receipt);

  console.log('');
  console.log('  ╔═══════════════════════════════════╗');
  console.log('  ║  DROP: ' + (resolution.selection + '').padEnd(28) + '║');
  console.log('  ╚═══════════════════════════════════╝');
  console.log('');
  console.log('  Verification:');
  console.log('    Commitment locked before outcome: ' + (result.checks.commitmentIntegrity ? '✅' : '❌'));
  console.log('    Beacon cryptographically verified: ' + (result.checks.beaconVerified ? '✅' : '❌'));
  console.log('    Output matches derivation:         ' + (result.checks.outputVerified ? '✅' : '❌'));
  console.log('    Selection matches rule:            ' + (result.checks.selectionVerified ? '✅' : '❌'));
  console.log('');
  console.log('  Receipt: ' + JSON.stringify(receipt).length + ' bytes — paste anywhere to verify.');
  console.log('  Integrate: npm install @fairseal/commit');
  console.log('  Docs: https://github.com/ned-del/fairseal');
  console.log('');
}

main().catch(e => { console.error('Error:', e.message); process.exit(1); });
