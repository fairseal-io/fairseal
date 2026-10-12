/**
 * Anchor API v2 — PREVIEW STUB (in-memory simulation; the real service is
 * not deployed yet).
 *
 * Lets MCP clients exercise the anchor submit/status flow locally before
 * the real service exists. Zero network calls, zero chain writes.
 *
 * Real service (future): POST https://api.fairseal.io/v2/anchor
 *   → x402 payment gate (USDC on Base) → Merkle batch → Base mainnet anchor
 *   → receipt with Merkle inclusion proof + tx hash.
 */

import { createHash, randomBytes } from "node:crypto";

export interface AnchorSubmission {
  anchor_id: string;
  status: "queued" | "batched" | "anchored";
  commitment_hash: string;
  batch_id: string | null;
  merkle_root: string | null;
  merkle_proof: string[] | null;
  chain: "base-mainnet";
  tx_hash: string | null;
  submitted_at: string;
  anchored_at: string | null;
  stub: true;
  note: string;
}

const store = new Map<string, AnchorSubmission>();

const sha256 = (s: string) => createHash("sha256").update(s).digest("hex");

/** Simulate POST /v2/anchor (after x402 payment would have cleared). */
export function anchorSubmit(payloadHash: string): AnchorSubmission {
  if (!/^[0-9a-fA-F]{64}$/.test(payloadHash)) {
    throw new Error(
      "payload_hash must be a 64-char hex SHA-256 digest of the receipt/commitment being anchored",
    );
  }
  const anchor_id = `anc_${randomBytes(8).toString("hex")}`;
  const sub: AnchorSubmission = {
    anchor_id,
    status: "queued",
    commitment_hash: payloadHash.toLowerCase(),
    batch_id: null,
    merkle_root: null,
    merkle_proof: null,
    chain: "base-mainnet",
    tx_hash: null,
    submitted_at: new Date().toISOString(),
    anchored_at: null,
    stub: true,
    note: "PREVIEW STUB — no payment taken, nothing written on-chain. Real Anchor API v2 coming soon at api.fairseal.io.",
  };
  store.set(anchor_id, sub);
  return sub;
}

/** Simulate GET /v2/anchor/{id} — advances lifecycle deterministically per poll. */
export function anchorStatus(anchorId: string): AnchorSubmission | null {
  const sub = store.get(anchorId);
  if (!sub) return null;
  if (sub.status === "queued") {
    // simulate batch assembly
    sub.status = "batched";
    sub.batch_id = `batch_${sha256(sub.anchor_id).slice(0, 12)}`;
    // fake sibling hashes for a depth-2 Merkle proof
    const sib1 = sha256(`${sub.commitment_hash}:sibling1`);
    const parent = sha256(sub.commitment_hash + sib1);
    const sib2 = sha256(`${parent}:sibling2`);
    sub.merkle_proof = [sib1, sib2];
    sub.merkle_root = sha256(parent + sib2);
  } else if (sub.status === "batched") {
    // simulate on-chain anchoring
    sub.status = "anchored";
    sub.tx_hash = `0x${sha256(`${sub.batch_id}:tx`)}`;
    sub.anchored_at = new Date().toISOString();
  }
  return sub;
}
