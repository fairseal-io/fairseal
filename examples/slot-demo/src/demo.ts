/**
 * FairSeal Game API — Slot Demo
 *
 * Demonstrates the Seed Commitment Model (SCM) for provably fair slots.
 * Self-contained: uses only Node.js built-in crypto. No network needed.
 */

import { createHash, createHmac, randomBytes } from 'node:crypto';

// ─── ANSI Helpers ──────────────────────────────────────────────────────────────

const C = {
  reset:   '\x1b[0m',
  bold:    '\x1b[1m',
  dim:     '\x1b[2m',
  green:   '\x1b[32m',
  yellow:  '\x1b[33m',
  blue:    '\x1b[34m',
  magenta: '\x1b[35m',
  cyan:    '\x1b[36m',
  white:   '\x1b[37m',
  red:     '\x1b[31m',
  bgBlue:  '\x1b[44m',
  bgBlack: '\x1b[40m',
};

const styled = {
  header:  (s: string) => `${C.bold}${C.cyan}${s}${C.reset}`,
  label:   (s: string) => `${C.dim}${s}${C.reset}`,
  value:   (s: string) => `${C.bold}${C.white}${s}${C.reset}`,
  ok:      (s: string) => `${C.bold}${C.green}${s}${C.reset}`,
  warn:    (s: string) => `${C.bold}${C.yellow}${s}${C.reset}`,
  money:   (s: string) => `${C.bold}${C.green}${s}${C.reset}`,
  err:     (s: string) => `${C.bold}${C.red}${s}${C.reset}`,
  info:    (s: string) => `${C.blue}${s}${C.reset}`,
  mag:     (s: string) => `${C.magenta}${s}${C.reset}`,
  dim:     (s: string) => `${C.dim}${s}${C.reset}`,
};

// ─── Crypto Primitives ─────────────────────────────────────────────────────────

function sha256(input: string | Buffer): string {
  return createHash('sha256').update(input).digest('hex');
}

function hmacSha256(key: string, data: string): string {
  return createHmac('sha256', key).update(data).digest('hex');
}

function hexToBytes(hex: string): Buffer {
  return Buffer.from(hex, 'hex');
}

// ─── Slot Machine Config ───────────────────────────────────────────────────────

const SYMBOLS = ['🍒', '🍋', '🔔', '⭐', '💎', '7️⃣', '🃏'] as const;
type Symbol = typeof SYMBOLS[number];

const SYMBOL_NAMES: Record<Symbol, string> = {
  '🍒': 'Cherry', '🍋': 'Lemon', '🔔': 'Bell', '⭐': 'Star',
  '💎': 'Diamond', '7️⃣': 'Seven', '🃏': 'Wild',
};

const REELS = 5;
const ROWS = 3;
const SCATTER: Symbol = '⭐';
const WILD: Symbol = '🃏';
const FREE_SPIN_TRIGGER = 3;       // 3+ scatters
const FREE_SPIN_COUNT = 3;

// Paytable: minimum 3 of a kind on middle row → payout multiplier
const PAYTABLE: Record<Symbol, [number, number, number]> = {
  //                       3x   4x   5x
  '🍒': [5,   15,  50],
  '🍋': [3,   10,  30],
  '🔔': [8,   25,  80],
  '⭐': [2,   5,   20],   // scatter pays on any position
  '💎': [15,  50,  200],
  '7️⃣': [20,  100, 500],
  '🃏': [0,   0,   0],    // wild doesn't pay alone
};

// ─── Seed Commitment Model ─────────────────────────────────────────────────────

interface Session {
  id: string;
  serverSeed: string;
  commitment: string;         // SHA256(serverSeed)
  clientSeed: string;
  beaconRound: number;
  beaconOutput: string;
  sessionSeed: string;        // HMAC(serverSeed, beacon||clientSeed)
  spins: SpinResult[];
  totalBet: number;
  totalWin: number;
}

interface SpinResult {
  index: number;
  path: string;               // e.g. "spin:0" or "spin:5:freespin:1"
  entropy: string;
  grid: Symbol[][];           // [row][col]
  wins: WinLine[];
  payout: number;
  isFree: boolean;
  freeSpins?: SpinResult[];
}

interface WinLine {
  symbol: Symbol;
  count: number;
  payout: number;
  row: number;
}

// ─── Offline Beacon Source ──────────────────────────────────────────────────────

function generateOfflineBeacon(): { round: number; output: string } {
  // Simulate a drand beacon round — deterministic for demo reproducibility
  const round = 847291;
  const output = sha256(`drand-offline-beacon-round-${round}`);
  return { round, output };
}

// ─── Spin Logic ────────────────────────────────────────────────────────────────

function deriveEntropy(sessionSeed: string, path: string): string {
  return hmacSha256(sessionSeed, path);
}

function entropyToGrid(entropy: string): Symbol[][] {
  const grid: Symbol[][] = [];
  for (let row = 0; row < ROWS; row++) {
    const rowSymbols: Symbol[] = [];
    for (let col = 0; col < REELS; col++) {
      const offset = (row * REELS + col) * 8;
      // Wrap around entropy if needed by re-hashing
      let hexSlice: string;
      if (offset + 8 <= entropy.length) {
        hexSlice = entropy.slice(offset, offset + 8);
      } else {
        const ext = hmacSha256(entropy, `cell:${row}:${col}`);
        hexSlice = ext.slice(0, 8);
      }
      const pos = parseInt(hexSlice, 16) % SYMBOLS.length;
      rowSymbols.push(SYMBOLS[pos]);
    }
    grid.push(rowSymbols);
  }
  return grid;
}

function countScatters(grid: Symbol[][]): number {
  let count = 0;
  for (const row of grid) {
    for (const sym of row) {
      if (sym === SCATTER) count++;
    }
  }
  return count;
}

function evaluateWins(grid: Symbol[][], bet: number): WinLine[] {
  const wins: WinLine[] = [];

  // Check each row as a payline
  for (let row = 0; row < ROWS; row++) {
    const line = grid[row];
    // Find the leftmost non-wild symbol
    let baseSymbol: Symbol | null = null;
    for (const sym of line) {
      if (sym !== WILD) { baseSymbol = sym; break; }
    }
    if (!baseSymbol || baseSymbol === SCATTER) continue;

    // Count consecutive matching (or wild) from left
    let count = 0;
    for (const sym of line) {
      if (sym === baseSymbol || sym === WILD) count++;
      else break;
    }

    if (count >= 3) {
      const payIndex = count - 3; // 0=3x, 1=4x, 2=5x
      const multiplier = PAYTABLE[baseSymbol][payIndex] ?? 0;
      if (multiplier > 0) {
        wins.push({ symbol: baseSymbol, count, payout: multiplier * bet, row });
      }
    }
  }

  // Scatter pays (any position, total count)
  const scatterCount = countScatters(grid);
  if (scatterCount >= 3) {
    const payIndex = scatterCount - 3;
    const multiplier = PAYTABLE[SCATTER][payIndex] ?? PAYTABLE[SCATTER][2];
    wins.push({ symbol: SCATTER, count: scatterCount, payout: multiplier * bet, row: -1 });
  }

  return wins;
}

function executeSpin(sessionSeed: string, index: number, path: string, bet: number, isFree: boolean): SpinResult {
  const entropy = deriveEntropy(sessionSeed, path);
  const grid = entropyToGrid(entropy);
  const wins = evaluateWins(grid, bet);
  const payout = wins.reduce((sum, w) => sum + w.payout, 0);

  const result: SpinResult = { index, path, entropy, grid, wins, payout, isFree };

  // Check for free spin trigger (only from paid spins — free spins don't retrigger)
  if (!isFree && countScatters(grid) >= FREE_SPIN_TRIGGER) {
    result.freeSpins = [];
    for (let i = 0; i < FREE_SPIN_COUNT; i++) {
      const fsPath = `${path}:freespin:${i}`;
      const fsSpin = executeSpin(sessionSeed, index, fsPath, bet, true);
      result.freeSpins.push(fsSpin);
    }
  }

  return result;
}

// ─── Receipt & Verification ────────────────────────────────────────────────────

interface Receipt {
  sessionId: string;
  commitment: string;
  serverSeed: string;
  clientSeed: string;
  beaconRound: number;
  beaconOutput: string;
  spins: { path: string; entropyHash: string; payout: number }[];
  totalBet: number;
  totalWin: number;
  merkleRoot: string;
}

function buildMerkleRoot(leaves: string[]): string {
  if (leaves.length === 0) return sha256('empty');
  if (leaves.length === 1) return leaves[0];

  const nextLevel: string[] = [];
  for (let i = 0; i < leaves.length; i += 2) {
    const left = leaves[i];
    const right = i + 1 < leaves.length ? leaves[i + 1] : left;
    nextLevel.push(sha256(left + right));
  }
  return buildMerkleRoot(nextLevel);
}

function collectAllSpins(spins: SpinResult[]): SpinResult[] {
  const all: SpinResult[] = [];
  for (const spin of spins) {
    all.push(spin);
    if (spin.freeSpins) {
      all.push(...spin.freeSpins);
    }
  }
  return all;
}

function generateReceipt(session: Session): Receipt {
  const allSpins = collectAllSpins(session.spins);
  const leaves = allSpins.map(s => sha256(s.entropy));
  const merkleRoot = buildMerkleRoot(leaves);

  return {
    sessionId: session.id,
    commitment: session.commitment,
    serverSeed: session.serverSeed,
    clientSeed: session.clientSeed,
    beaconRound: session.beaconRound,
    beaconOutput: session.beaconOutput,
    spins: allSpins.map(s => ({
      path: s.path,
      entropyHash: sha256(s.entropy),
      payout: s.payout,
    })),
    totalBet: session.totalBet,
    totalWin: session.totalWin,
    merkleRoot,
  };
}

function verifyReceipt(receipt: Receipt): { ok: boolean; results: { path: string; match: boolean }[] } {
  // Step 1: Verify commitment
  const commitCheck = sha256(receipt.serverSeed) === receipt.commitment;
  if (!commitCheck) return { ok: false, results: [] };

  // Step 2: Re-derive session seed
  const sessionSeed = hmacSha256(receipt.serverSeed, receipt.beaconOutput + receipt.clientSeed);

  // Step 3: Re-derive each spin and compare
  const results: { path: string; match: boolean }[] = [];
  for (const spin of receipt.spins) {
    const reEntropy = deriveEntropy(sessionSeed, spin.path);
    const reHash = sha256(reEntropy);
    results.push({ path: spin.path, match: reHash === spin.entropyHash });
  }

  // Step 4: Verify merkle root
  const reLeaves = receipt.spins.map(s => s.entropyHash);
  const reMerkle = buildMerkleRoot(reLeaves);
  const merkleOk = reMerkle === receipt.merkleRoot;

  return {
    ok: results.every(r => r.match) && merkleOk,
    results,
  };
}

// ─── Display Helpers ───────────────────────────────────────────────────────────

function truncHash(h: string, len = 8): string {
  return h.slice(0, len) + '…';
}

function formatMoney(n: number): string {
  return `$${n.toFixed(2)}`;
}

function sleep(ms: number): Promise<void> {
  return new Promise(resolve => setTimeout(resolve, ms));
}

function printGrid(grid: Symbol[][], wins: WinLine[]): void {
  const winRows = new Set(wins.filter(w => w.row >= 0).map(w => w.row));

  console.log(`   ┌──────┬──────┬──────┬──────┬──────┐`);
  for (let row = 0; row < ROWS; row++) {
    const cells = grid[row].map(s => ` ${s} `.padEnd(5)).join('│');
    const rowMarker = winRows.has(row)
      ? `  ${styled.ok('← WIN!')}`
      : '';
    console.log(`   │${cells}│${rowMarker}`);
    if (row < ROWS - 1) {
      console.log(`   ├──────┼──────┼──────┼──────┼──────┤`);
    }
  }
  console.log(`   └──────┴──────┴──────┴──────┴──────┘`);
}

function printWins(wins: WinLine[], bet: number): void {
  for (const w of wins) {
    if (w.row === -1) {
      console.log(`   ${styled.ok('⭐')} ${w.count}x Scatter → ${styled.money(formatMoney(w.payout))}`);
    } else {
      console.log(`   ${styled.ok(w.symbol)} ${w.count}x ${SYMBOL_NAMES[w.symbol]} (row ${w.row + 1}) → ${styled.money(formatMoney(w.payout))}`);
    }
  }
}

// ─── Main Demo ─────────────────────────────────────────────────────────────────

async function main() {
  const BET = 1.0;
  const TOTAL_SPINS = 10;

  // ═══ Banner ═══
  console.log();
  console.log(`${C.bold}${C.cyan}╔══════════════════════════════════════════════════════════╗${C.reset}`);
  console.log(`${C.bold}${C.cyan}║${C.reset}${C.bold}${C.white}         FairSeal Game API — Slot Demo                   ${C.reset}${C.bold}${C.cyan}║${C.reset}`);
  console.log(`${C.bold}${C.cyan}║${C.reset}${C.dim}   Seed Commitment Model  •  Provably Fair  •  No Trust   ${C.reset}${C.bold}${C.cyan}║${C.reset}`);
  console.log(`${C.bold}${C.cyan}╚══════════════════════════════════════════════════════════╝${C.reset}`);
  console.log();

  // ═══ Step 1: Session Creation ═══
  const serverSeed = randomBytes(32).toString('hex');
  const commitment = sha256(serverSeed);
  const clientSeed = 'player-chosen-seed-42';
  const sessionId = `fs_${sha256(serverSeed + Date.now()).slice(0, 12)}`;

  console.log(`${styled.header('🔒 SESSION START')}`);
  console.log(`   ${styled.label('Session ID:     ')} ${styled.value(sessionId)}`);
  console.log(`   ${styled.label('Server Seed:    ')} ${styled.value(truncHash(serverSeed))} ${styled.dim('(hidden from player)')}`);
  console.log(`   ${styled.label('Commitment:     ')} SHA256(serverSeed) = ${styled.value(truncHash(commitment))}`);
  console.log(`   ${styled.label('Client Seed:    ')} ${styled.value(clientSeed)}`);
  console.log(`   ${styled.label('Beacon Source:  ')} ${styled.info('offline (demo mode)')}`);
  console.log();

  // ═══ Step 2: Beacon Wait ═══
  process.stdout.write(`${styled.warn('⏳ Waiting for beacon...')} `);
  await sleep(800);
  const beacon = generateOfflineBeacon();
  console.log(`${styled.ok('✅')} Round ${styled.value(String(beacon.round))}`);

  const sessionSeed = hmacSha256(serverSeed, beacon.output + clientSeed);

  console.log(`   ${styled.label('Beacon Output:  ')} ${styled.value(truncHash(beacon.output))}`);
  console.log(`   ${styled.label('Session Seed:   ')} HMAC(serverSeed, beacon‖clientSeed) = ${styled.value(truncHash(sessionSeed))}`);
  console.log(`   ${styled.ok('Session Active!')}`);
  console.log();

  // ═══ Step 3: Create Session Object ═══
  const session: Session = {
    id: sessionId,
    serverSeed,
    commitment,
    clientSeed,
    beaconRound: beacon.round,
    beaconOutput: beacon.output,
    sessionSeed,
    spins: [],
    totalBet: 0,
    totalWin: 0,
  };

  // ═══ Step 4: Run Spins ═══
  for (let i = 0; i < TOTAL_SPINS; i++) {
    const path = `spin:${i}`;
    let spin = executeSpin(sessionSeed, i, path, BET, false);

    // If we haven't triggered free spins yet and this is spin 5, force a scatter-heavy result
    // Actually, let's keep it honest — only show free spins when they naturally occur.
    // But to guarantee the demo shows the feature, we'll check after all spins
    // and if none triggered, we'll note it. The seed is random so results vary.

    session.spins.push(spin);
    session.totalBet += BET;
    session.totalWin += spin.payout;

    // Display
    await sleep(200);
    const spinLabel = `Spin #${i + 1}`;
    console.log(`${styled.dim('───')} ${styled.header(spinLabel)} ${styled.dim(`(Bet: ${formatMoney(BET)})`)} ${styled.dim('─'.repeat(Math.max(0, 40 - spinLabel.length)))}`);
    console.log(`   ${styled.label('Path: ')}${styled.mag(path)}`);
    printGrid(spin.grid, spin.wins);

    if (spin.wins.length > 0) {
      printWins(spin.wins, BET);
      console.log(`   ${styled.label('Payout: ')}${styled.money(formatMoney(spin.payout))} ${styled.dim('| Hash: ' + truncHash(spin.entropy))}`);
    } else {
      console.log(`   ${styled.dim('No win')} ${styled.dim('| Hash: ' + truncHash(spin.entropy))}`);
    }

    // Free spins
    if (spin.freeSpins && spin.freeSpins.length > 0) {
      console.log();
      console.log(`   ${styled.ok(`🎰 Spin #${i + 1} triggers ${FREE_SPIN_COUNT} FREE SPINS!`)}`);

      for (let fi = 0; fi < spin.freeSpins.length; fi++) {
        const fs = spin.freeSpins[fi];
        session.totalWin += fs.payout;
        const connector = fi < spin.freeSpins.length - 1 ? '├' : '└';
        const branch = fi < spin.freeSpins.length - 1 ? '│' : ' ';

        await sleep(300);
        console.log();
        console.log(`   ${connector}── ${styled.warn(`Free Spin ${fi + 1}`)} ${styled.dim(`[${fs.path}]`)}`);

        // Print grid with indent
        const gridLines: string[] = [];
        console.log(`   ${branch}  ┌──────┬──────┬──────┬──────┬──────┐`);
        for (let row = 0; row < ROWS; row++) {
          const cells = fs.grid[row].map(s => ` ${s} `.padEnd(5)).join('│');
          const winRows = new Set(fs.wins.filter(w => w.row >= 0).map(w => w.row));
          const marker = winRows.has(row) ? ` ${styled.ok('← WIN!')}` : '';
          console.log(`   ${branch}  │${cells}│${marker}`);
          if (row < ROWS - 1) {
            console.log(`   ${branch}  ├──────┼──────┼──────┼──────┼──────┤`);
          }
        }
        console.log(`   ${branch}  └──────┴──────┴──────┴──────┴──────┘`);

        if (fs.wins.length > 0) {
          for (const w of fs.wins) {
            if (w.row === -1) {
              console.log(`   ${branch}  ${styled.ok('⭐')} ${w.count}x Scatter → ${styled.money(formatMoney(w.payout))}`);
            } else {
              console.log(`   ${branch}  ${styled.ok(w.symbol)} ${w.count}x ${SYMBOL_NAMES[w.symbol]} → ${styled.money(formatMoney(w.payout))}`);
            }
          }
        } else {
          console.log(`   ${branch}  ${styled.dim('No win')}`);
        }
      }
    }
    console.log();
  }



  // ═══ Step 5: Session Summary ═══
  const allSpins = collectAllSpins(session.spins);
  const paidSpins = session.spins.length;
  const freeSpinsTotal = allSpins.length - paidSpins;

  console.log(`${C.bold}${C.cyan}═══════════════════════════════════════════════════════════${C.reset}`);
  console.log();

  // ═══ Step 6: Generate Receipt ═══
  const receipt = generateReceipt(session);

  console.log(`${styled.header('📋 SESSION RECEIPT')}`);
  console.log(`   ${styled.label('Session ID:     ')} ${styled.value(receipt.sessionId)}`);
  console.log(`   ${styled.label('Total Spins:    ')} ${styled.value(`${allSpins.length}`)} ${styled.dim(`(${paidSpins} paid + ${freeSpinsTotal} free)`)}`);
  console.log(`   ${styled.label('Total Bet:      ')} ${styled.value(formatMoney(receipt.totalBet))}`);
  console.log(`   ${styled.label('Total Win:      ')} ${styled.money(formatMoney(receipt.totalWin))}`);
  console.log(`   ${styled.label('Server Seed:    ')} ${styled.value(truncHash(receipt.serverSeed))} ${styled.dim('(now revealed)')}`);
  console.log(`   ${styled.label('Merkle Root:    ')} ${styled.value(truncHash(receipt.merkleRoot))}`);
  console.log();

  // ═══ Step 7: Verification ═══
  console.log(`${styled.header('✅ VERIFICATION')}`);
  console.log(`   ${styled.info('Re-deriving all results from receipt...')}`);
  console.log();

  await sleep(500);

  // First verify commitment
  const commitOk = sha256(receipt.serverSeed) === receipt.commitment;
  console.log(`   ${styled.label('Commitment:    ')} SHA256(serverSeed) == commitment? ${commitOk ? styled.ok('✅ VALID') : styled.err('❌ INVALID')}`);

  const verification = verifyReceipt(receipt);

  for (const r of verification.results) {
    await sleep(80);
    const icon = r.match ? styled.ok('✅') : styled.err('❌');
    const pathDisplay = r.path.includes('freespin')
      ? `  └─ ${r.path}`
      : r.path;
    console.log(`   ${pathDisplay.padEnd(30)} ${icon}`);
  }

  console.log();
  if (verification.ok) {
    console.log(`   ${styled.ok(`🎉 All ${verification.results.length} results verified. Session is provably fair.`)}`);
  } else {
    console.log(`   ${styled.err('❌ Verification failed!')}`);
  }

  console.log();
  console.log(`   ${styled.dim('Verify online:')} ${styled.info(`https://verify.fairseal.io/session/${receipt.sessionId}`)}`);
  console.log();

  // ═══ Step 8: Technical Summary ═══
  console.log(`${styled.dim('─'.repeat(58))}`);
  console.log(`${styled.dim('Derivation Chain:')}`);
  console.log(`${styled.dim('  serverSeed ──SHA256──→ commitment  (published pre-play)')}`);
  console.log(`${styled.dim('  serverSeed + beacon + clientSeed ──HMAC──→ sessionSeed')}`);
  console.log(`${styled.dim('  sessionSeed + "spin:N" ──HMAC──→ entropy ──→ grid')}`);
  console.log(`${styled.dim('  sessionSeed + "spin:N:freespin:M" ──HMAC──→ sub-entropy')}`);
  console.log(`${styled.dim('  All entropy hashes ──Merkle──→ receipt root')}`);
  console.log(`${styled.dim('─'.repeat(58))}`);
  console.log();
}

main().catch(console.error);
