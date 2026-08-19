#!/usr/bin/env node
/**
 * 🦭 Fairseal Demo — run with: npx @fairseal/commit
 *
 * Shows a verifiable gacha pull in your terminal.
 * No setup. No account. Just run it.
 *
 * Flags:
 *   --help, -h     show usage
 *   --no-file      don't write the receipt JSON to disk
 */

const args = process.argv.slice(2);

if (args.includes('--help') || args.includes('-h')) {
  console.log(`
  🦭 Fairseal Demo — provably fair gacha pull

  Usage:
    npx @fairseal/commit            run the demo pull
    npx @fairseal/commit --no-file  run without writing the receipt file
    npx @fairseal/commit --help     show this help

  What it does:
    1. Commits to a loot table BEFORE the randomness exists (SHA-256 commitment)
    2. Waits for a public drand beacon round (~6s)
    3. Resolves the pull and verifies the BLS signature client-side
    4. Writes a portable receipt to ./fairseal-receipt-<id>.json
    5. Prints a deep link to inspect it at https://verify.fairseal.io

  Integrate: npm install @fairseal/commit
  Docs:      https://github.com/ned-del/fairseal
`);
  process.exit(0);
}

const fs = require('fs');
const path = require('path');
const {
  createCommitment,
  resolveCommitment,
  createReceipt,
  verifyReceipt,
} = require('../dist/index.js');

const ITEMS = ['🌟 SSR Dragon Blade', '✨ SR Phoenix Staff', '✨ SR Thunder Bow', '🔵 R Iron Shield', '🔵 R Wind Cloak', '⚪ N Wooden Sword', '⚪ N Leather Armor'];

// Rarity mapping for the verify.fairseal.io demo view (ASCII-safe payload)
function describeItem(sel) {
  const s = String(sel);
  const name = s.replace(/[^\x20-\x7E]/g, '').trim(); // strip emoji → ASCII-safe for atob()
  if (/^SSR /.test(name)) return { name, rarity: 5, type: 'weapon (SSR)' };
  if (/^SR /.test(name)) return { name, rarity: 4, type: 'weapon (SR)' };
  if (/^R /.test(name)) return { name, rarity: 3, type: 'gear (R)' };
  return { name, rarity: 2, type: 'gear (N)' };
}

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

  // { wait: true } polls until the target round is available (max ~15s)
  const resolution = await resolveCommitment(commitment, { wait: true });
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

  const shortId = commitment.commitHash.slice(0, 12);

  // Write the portable receipt to disk
  if (!args.includes('--no-file')) {
    const receiptPath = path.join(process.cwd(), `fairseal-receipt-${shortId}.json`);
    try {
      fs.writeFileSync(receiptPath, JSON.stringify(receipt, null, 2) + '\n');
      console.log('');
      console.log('  📄 Receipt saved: ' + receiptPath);
    } catch (e) {
      console.log('');
      console.log('  ⚠️  Could not write receipt file: ' + e.message);
    }
  }

  // Deep link to the hosted verifier (demo view)
  const item = describeItem(resolution.selection);
  const demoPayload = {
    game_id: commitment.commitHash,
    game_type: 'gacha (npx @fairseal/commit demo)',
    item_name: item.name,
    item_type: item.type,
    rarity: item.rarity,
    pull_index: 1,
    pull_total: 1,
    timestamp: Date.now(),
    commitHash: commitment.commitHash,
    nonce: commitment.targetRound,
    hmac_output: resolution.output,
    serverSeed: resolution.beaconRandomness,
    clientSeed: commitment.inputsHash,
    pity_5star: 0,
    pity_4star: 0,
    total_pulls: 1,
  };
  const b64 = Buffer.from(JSON.stringify(demoPayload), 'utf8').toString('base64');
  console.log('');
  console.log('  🔗 View in browser (demo view):');
  console.log('     https://verify.fairseal.io/#demo/' + b64);
  console.log('');
  console.log('  Receipt: ' + JSON.stringify(receipt).length + ' bytes — paste anywhere to verify.');
  console.log('  Integrate: npm install @fairseal/commit');
  console.log('  Docs: https://github.com/ned-del/fairseal');
  console.log('');
}

main().catch(e => { console.error('Error:', e.message); process.exit(1); });
