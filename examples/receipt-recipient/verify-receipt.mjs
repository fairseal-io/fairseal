/**
 * FairSeal Receipt Recipient — Independent Verification
 * ======================================================
 * Designed for: downstream agents, auditors, and reviewers who received a
 * FairSeal notarize receipt and want to verify it independently.
 *
 * ZERO wallet. ZERO payment. ZERO trust in the FairSeal server's own
 * `verification` block.
 *
 * Three independent checks (using @fairseal/verify v0.4.1 + node:crypto):
 *
 *   [1] Leaf recompute  — SHA256(receipt_id + '||' + payload_hash) must equal
 *                          proof.leaf_hash  (confirms payload_hash wasn't swapped)
 *   [2] Merkle path     — verifyMerklePath() or pair-sorted walk must produce
 *                          proof.merkle_root from the recomputed leaf
 *   [3] On-chain anchor — verifyAnchor() → getBatchRoot(batch_id) on Base mainnet
 *                          must equal proof.merkle_root
 *
 * Usage:
 *   node verify-receipt.mjs <path-to-receipt.json>
 *   node verify-receipt.mjs fixtures/receipt-real.json
 *   node verify-receipt.mjs fixtures/receipt-tampered.json   # must FAIL
 *
 * Or live fetch:
 *   node verify-receipt.mjs nr_<receipt_id>
 */

import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { verifyMerklePath, verifyAnchor } from "@fairseal/verify";

// ─── Helpers ────────────────────────────────────────────────────────────────

const sha256hex = (s) =>
  createHash("sha256").update(s, "utf8").digest("hex");

/** Pair-sorted SHA256 walk (matches FairSeal notarize pair_formula). */
function pairSortedRoot(leafHex, siblings) {
  let node = leafHex.toLowerCase();
  for (const sib of siblings) {
    const s = sib.toLowerCase();
    node = node < s ? sha256hex(node + s) : sha256hex(s + node);
  }
  return node;
}

// ─── Load receipt ────────────────────────────────────────────────────────────

const arg = process.argv[2];
if (!arg) {
  console.error("Usage: node verify-receipt.mjs <receipt.json | nr_<id>>");
  process.exit(1);
}

let receipt;
if (arg.startsWith("nr_")) {
  // Live fetch — free endpoint, no payment needed
  console.log(`Fetching live receipt: ${arg} …`);
  const res = await fetch(`https://api.fairseal.io/v1/notarize/${arg}`);
  if (!res.ok) {
    console.error(`Receipt fetch failed: HTTP ${res.status}`);
    process.exit(1);
  }
  receipt = await res.json();
} else {
  receipt = JSON.parse(readFileSync(arg, "utf8"));
}

const { receipt_id, payload_hash, proof } = receipt;

console.log(`\n═══════════════════════════════════════════════════════════`);
console.log(` FairSeal Receipt Verification`);
console.log(`═══════════════════════════════════════════════════════════`);
console.log(` Receipt ID : ${receipt_id}`);
console.log(` Status     : ${receipt.status}`);
console.log(` Agent ID   : ${receipt.metadata?.agent_id ?? "—"}`);
console.log(` Decided At : ${receipt.metadata?.decided_at ?? "—"}`);
console.log(`═══════════════════════════════════════════════════════════\n`);

if (receipt.status !== "anchored") {
  console.error(
    `❌ Cannot verify: status is "${receipt.status}" (requires "anchored").`
  );
  console.error(`   Poll ${arg.startsWith("nr_") ? arg : receipt_id} again later.`);
  process.exit(1);
}

// Sanity: require proof fields
const missingFields = ["leaf_hash", "merkle_root", "batch_id", "anchor_tx", "anchor_chain", "anchor_contract"]
  .filter((k) => !proof?.[k]);
if (!proof || missingFields.length > 0) {
  console.error(`❌ Malformed receipt — missing proof fields: ${missingFields.join(", ")}`);
  process.exit(1);
}

// ─── Check 1: Leaf recompute ────────────────────────────────────────────────
// Independently verify that the receipt's payload_hash was committed.
// The leaf is SHA256(receipt_id + '||' + payload_hash) per the leaf_formula.
// If payload_hash was tampered, this check will fail.

const recomputedLeaf = sha256hex(`${receipt_id}||${payload_hash}`);
const c1 = recomputedLeaf === proof.leaf_hash.toLowerCase();

console.log(`[1] Leaf recompute (node:crypto — independent of server)`);
console.log(`    formula    : SHA256("${receipt_id}" + "||" + "<payload_hash>")`);
console.log(`    expected   : ${proof.leaf_hash}`);
console.log(`    computed   : ${recomputedLeaf}`);
console.log(`    result     : ${c1 ? "✅ PASS — payload_hash is committed" : "❌ FAIL — payload_hash mismatch (receipt may be forged)"}\n`);

// ─── Check 2: Merkle path ───────────────────────────────────────────────────
// Walk the merkle path from the recomputed leaf to the claimed root.
// Uses @fairseal/verify's verifyMerklePath for the empty-path (single-leaf)
// case; falls back to pair-sorted walk for non-empty string[] paths.

const merklePathRaw = proof.merkle_path ?? [];
let c2;
let c2Detail;

if (merklePathRaw.length === 0) {
  // Single-leaf batch: leaf === root  (verifyMerklePath handles empty path correctly)
  c2 = verifyMerklePath(recomputedLeaf, [], proof.merkle_root);
  c2Detail = `single-leaf batch: recomputed leaf must equal merkle_root`;
} else {
  // Multi-leaf batch: pair-sorted string[] walk (FairSeal notarize pair_formula)
  // @fairseal/verify verifyMerklePath uses position-based MerkleStep[] — not
  // directly usable for this format. We implement the pair-sorted walk ourselves.
  const computedRoot = pairSortedRoot(recomputedLeaf, merklePathRaw);
  c2 = computedRoot === proof.merkle_root.toLowerCase();
  c2Detail = `merkle path length ${merklePathRaw.length}, pair-sorted walk`;
}

console.log(`[2] Merkle path (@fairseal/verify verifyMerklePath + pair-sorted fallback)`);
console.log(`    path length: ${merklePathRaw.length}`);
console.log(`    detail     : ${c2Detail}`);
console.log(`    merkle_root: ${proof.merkle_root}`);
console.log(`    result     : ${c2 ? "✅ PASS — leaf is in committed tree" : "❌ FAIL — leaf not in tree (receipt may be forged)"}\n`);

// ─── Check 3: On-chain anchor (@fairseal/verify verifyAnchor) ───────────────
// Calls getBatchRoot(batch_id) on the FairSeal anchor contract (Base mainnet)
// via public RPC. Compares the on-chain root to proof.merkle_root.
// Uses the agent_decision auto-mapping added in @fairseal/verify v0.4.0.

console.log(`[3] On-chain anchor (@fairseal/verify verifyAnchor — Base mainnet)`);
console.log(`    contract   : ${proof.anchor_contract}`);
console.log(`    batch_id   : ${proof.batch_id}`);
console.log(`    anchor_tx  : ${proof.anchor_tx} (block ${proof.anchor_block})`);
console.log(`    RPC        : public Base mainnet (https://mainnet.base.org)`);

let c3;
let anchorResult;
try {
  // Pass the full receipt JSON — v0.4.1 agent_decision auto-mapping
  // extracts proof.{anchor_chain, anchor_tx, merkle_root, batch_id, anchor_contract, leaf_hash}
  anchorResult = await verifyAnchor(receipt);
  c3 = anchorResult.anchored === true;
  if (anchorResult.checks?.contractState?.detail) {
    console.log(`    on-chain   : ${anchorResult.checks.contractState.detail}`);
  }
  if (anchorResult.errors?.length) {
    console.log(`    errors     : ${anchorResult.errors.join("; ")}`);
  }
} catch (err) {
  c3 = false;
  console.log(`    RPC error  : ${err.message}`);
}
console.log(`    result     : ${c3 ? "✅ PASS — merkle_root confirmed on Base mainnet" : "❌ FAIL — on-chain root mismatch or RPC error"}\n`);

// ─── Verdict ─────────────────────────────────────────────────────────────────

const allPass = c1 && c2 && c3;

console.log(`═══════════════════════════════════════════════════════════`);
if (allPass) {
  console.log(` ✅  VERIFIED`);
  console.log(``);
  console.log(`    This receipt independently confirms that the payload_hash`);
  console.log(`    committed by ${receipt.metadata?.agent_id ?? "the agent"} at`);
  console.log(`    ${receipt.metadata?.decided_at ?? receipt.created_at} was`);
  console.log(`    anchored on Base mainnet (tx ${proof.anchor_tx.slice(0, 18)}…)`);
  console.log(`    and has not been tampered with.`);
} else {
  console.log(` ❌  VERIFICATION FAILED`);
  console.log(``);
  if (!c1) console.log(`    • payload_hash does not match the committed leaf`);
  if (!c2) console.log(`    • merkle path does not resolve to the claimed root`);
  if (!c3) console.log(`    • on-chain anchor not confirmed`);
  console.log(`\n    This receipt should be treated as invalid.`);
}
console.log(`═══════════════════════════════════════════════════════════\n`);

process.exit(allPass ? 0 : 1);
