/**
 * Anchor API v2 — real service implementation (flag-gated; NOT deployed).
 *
 * Design: fairseal-mcp-staging/docs/anchor-api-design.md
 * Semantics: fail-closed — degraded pipeline rejects submissions with 503;
 * a wrong/unbacked "anchored" status is worse than no answer.
 *
 * Zero production impact until ANCHOR_V2_ENABLED=1 AND service restart
 * (separate approved change). Dry-run backend writes nothing on-chain.
 */

import { createHash, randomBytes } from "node:crypto";
import express from "express";
import type { Express, Request, Response, NextFunction } from "express";

// ─── Types ───────────────────────────────────────────────────

export interface ChainAnchorBackend {
  name: string;
  dryRun: boolean;
  healthy(): boolean;
  anchorBatch(params: {
    batchId: string;
    merkleRoot: string; // 0x-prefixed bytes32
    batchSize: number;
    clientId: string;
  }): Promise<{ txHash: string; blockNumber: number; timestampMs: number }>;
}

export type AnchorStatus = "queued" | "batched" | "anchored";

export interface ProofStep {
  sibling: string; // 64-char hex
  position: "left" | "right"; // position of sibling relative to running hash
}

export interface Submission {
  anchor_id: string;
  status: AnchorStatus;
  commitment_hash: string; // 64-char hex (lowercase)
  tier: "batch" | "realtime";
  metadata: unknown;
  submitted_by: string; // api key id, payer addr, or ip
  batch_id: string | null;
  leaf_index: number | null;
  merkle_root: string | null;
  merkle_proof: ProofStep[] | null;
  chain: string;
  contract: string | null;
  tx_hash: string | null;
  block_number: number | null;
  submitted_at: string;
  anchored_at: string | null;
  dry_run: boolean;
  anchor_error?: string;
}

export interface BatchRec {
  batch_id: string;
  status: "anchoring" | "anchored" | "failed";
  merkle_root: string;
  leaf_count: number;
  anchor_ids: string[];
  tx_hash: string | null;
  block_number: number | null;
  created_at: string;
  anchored_at: string | null;
  dry_run: boolean;
  error?: string;
}

export interface ApiKeyRec {
  key: string;
  tier: "starter" | "pro";
  quota: number; // max anchors in current period
  used: number;
}

// ─── Helpers ─────────────────────────────────────────────────

const sha256hex = (b: Buffer) => createHash("sha256").update(b).digest("hex");
const HEX64 = /^[0-9a-fA-F]{64}$/;

/** Build a binary SHA-256 Merkle tree (odd node duplicated). Returns root + per-leaf proofs. */
export function buildMerkle(leaves: string[]): { root: string; proofs: ProofStep[][] } {
  if (leaves.length === 0) throw new Error("empty batch");
  let level = leaves.map((h) => h.toLowerCase());
  const proofs: ProofStep[][] = leaves.map(() => []);
  // track which original leaves each node covers
  let owners: number[][] = leaves.map((_, i) => [i]);
  while (level.length > 1) {
    const nextLevel: string[] = [];
    const nextOwners: number[][] = [];
    for (let i = 0; i < level.length; i += 2) {
      const left = level[i];
      const right = i + 1 < level.length ? level[i + 1] : level[i]; // duplicate odd
      const leftOwners = owners[i];
      const rightOwners = i + 1 < level.length ? owners[i + 1] : [];
      for (const o of leftOwners) proofs[o].push({ sibling: right, position: "right" });
      for (const o of rightOwners) proofs[o].push({ sibling: left, position: "left" });
      nextLevel.push(sha256hex(Buffer.concat([Buffer.from(left, "hex"), Buffer.from(right, "hex")])));
      nextOwners.push([...leftOwners, ...rightOwners]);
    }
    level = nextLevel;
    owners = nextOwners;
  }
  return { root: level[0], proofs };
}

/** Offline verification: fold proof from leaf, compare to root. */
export function verifyProof(leaf: string, proof: ProofStep[], root: string): boolean {
  let h = leaf.toLowerCase();
  for (const step of proof) {
    const pair =
      step.position === "right"
        ? Buffer.concat([Buffer.from(h, "hex"), Buffer.from(step.sibling, "hex")])
        : Buffer.concat([Buffer.from(step.sibling, "hex"), Buffer.from(h, "hex")]);
    h = sha256hex(pair);
  }
  return h === root.toLowerCase();
}

// ─── Backends ────────────────────────────────────────────────

/** Dry-run backend: no network, no chain writes, fake tx marked dry_run. */
export function createDryRunBackend(): ChainAnchorBackend {
  let block = 30_000_000;
  return {
    name: "dry-run",
    dryRun: true,
    healthy: () => true,
    async anchorBatch(p) {
      return {
        txHash: `0xDRYRUN${sha256hex(Buffer.from(p.batchId + p.merkleRoot)).slice(6)}`,
        blockNumber: ++block,
        timestampMs: Date.now(),
      };
    },
  };
}

/** Backend that always fails — used to test fail-closed semantics. */
export function createFailingBackend(): ChainAnchorBackend {
  return {
    name: "failing",
    dryRun: true,
    healthy: () => false,
    async anchorBatch() {
      throw new Error("simulated chain outage");
    },
  };
}

/**
 * Real Base-mainnet backend: reuses the existing MerkleAnchor pipeline
 * (src/blockchain/anchor.ts, PolygonAnchor class — chain-agnostic, serialized
 * tx queue, nonce-safe). Lazily imported so dry-run mode never touches ethers.
 */
export async function createBaseMainnetBackend(): Promise<ChainAnchorBackend> {
  const mod = await import("../src/blockchain/anchor.js");
  const rpcUrl = process.env.ANCHOR_RPC_URL || process.env.BASE_RPC_URL;
  const privateKey = process.env.ANCHOR_PRIVATE_KEY || process.env.DEPLOYER_PRIVATE_KEY;
  const contractAddress = process.env.ANCHOR_CONTRACT || process.env.MERKLE_ANCHOR_CONTRACT;
  if (!rpcUrl || !privateKey || !contractAddress) {
    throw new Error("Base backend requires ANCHOR_RPC_URL, ANCHOR_PRIVATE_KEY, ANCHOR_CONTRACT");
  }
  const anchor = new mod.PolygonAnchor({ rpcUrl, privateKey, contractAddress, chainId: 8453 });
  return {
    name: "base-mainnet",
    dryRun: false,
    healthy: () => true, // liveness verified per-tx; failures flip engine to degraded (fail-closed)
    async anchorBatch(p) {
      const r = await anchor.anchorBatch(p);
      return { txHash: r.txHash, blockNumber: r.blockNumber, timestampMs: r.timestampMs };
    },
  };
}

// ─── Engine ──────────────────────────────────────────────────

export interface AnchorEngineOpts {
  backend: ChainAnchorBackend;
  batchThreshold?: number; // default 10
  batchIntervalMs?: number; // default 60_000
  clientId?: string;
  contract?: string | null;
  chain?: string;
}

export class AnchorEngine {
  readonly subs = new Map<string, Submission>();
  readonly byPayload = new Map<string, string>();
  readonly batches = new Map<string, BatchRec>();
  private pending: string[] = [];
  degraded = false;
  degradedReason: string | null = null;
  private timer: ReturnType<typeof setInterval> | null = null;
  private flushing = false;
  private readonly backend: ChainAnchorBackend;
  private readonly threshold: number;
  private readonly clientId: string;
  private readonly contract: string | null;
  private readonly chain: string;

  constructor(opts: AnchorEngineOpts) {
    this.backend = opts.backend;
    this.threshold = opts.batchThreshold ?? 10;
    this.clientId = opts.clientId ?? "fairseal-anchor-v2";
    this.contract = opts.contract ?? process.env.ANCHOR_CONTRACT ?? null;
    this.chain = opts.chain ?? "base-mainnet";
    const interval = opts.batchIntervalMs ?? 60_000;
    this.timer = setInterval(() => void this.flush("timer"), interval);
    if (this.timer.unref) this.timer.unref();
  }

  stop() {
    if (this.timer) clearInterval(this.timer);
  }

  acceptingSubmissions(): { ok: boolean; reason?: string } {
    if (this.degraded) return { ok: false, reason: this.degradedReason ?? "pipeline_degraded" };
    if (!this.backend.healthy()) return { ok: false, reason: "anchor_backend_unhealthy" };
    return { ok: true };
  }

  submit(payloadHash: string, metadata: unknown, tier: "batch" | "realtime", submittedBy: string):
    | { ok: true; sub: Submission }
    | { ok: false; code: number; error: string; anchor_id?: string } {
    const gate = this.acceptingSubmissions();
    if (!gate.ok) return { ok: false, code: 503, error: gate.reason! }; // fail-closed
    const hash = payloadHash.toLowerCase();
    const existing = this.byPayload.get(hash);
    if (existing) return { ok: false, code: 409, error: "duplicate_payload", anchor_id: existing };
    const anchor_id = `anc_${randomBytes(10).toString("hex")}`;
    const sub: Submission = {
      anchor_id,
      status: "queued",
      commitment_hash: hash,
      tier,
      metadata: metadata ?? null,
      submitted_by: submittedBy,
      batch_id: null,
      leaf_index: null,
      merkle_root: null,
      merkle_proof: null,
      chain: this.chain,
      contract: this.contract,
      tx_hash: null,
      block_number: null,
      submitted_at: new Date().toISOString(),
      anchored_at: null,
      dry_run: this.backend.dryRun,
    };
    this.subs.set(anchor_id, sub);
    this.byPayload.set(hash, anchor_id);
    this.pending.push(anchor_id);
    if (tier === "realtime" || this.pending.length >= this.threshold) void this.flush(tier);
    return { ok: true, sub };
  }

  async flush(_reason: string): Promise<void> {
    if (this.flushing || this.pending.length === 0) return;
    this.flushing = true;
    try {
      const ids = this.pending.splice(0, Math.max(this.threshold, this.pending.length));
      const items = ids.map((id) => this.subs.get(id)!).filter(Boolean);
      if (items.length === 0) return;
      const batch_id = `batch_${Date.now()}_${randomBytes(4).toString("hex")}`;
      const { root, proofs } = buildMerkle(items.map((s) => s.commitment_hash));
      const batch: BatchRec = {
        batch_id,
        status: "anchoring",
        merkle_root: root,
        leaf_count: items.length,
        anchor_ids: ids,
        tx_hash: null,
        block_number: null,
        created_at: new Date().toISOString(),
        anchored_at: null,
        dry_run: this.backend.dryRun,
      };
      this.batches.set(batch_id, batch);
      items.forEach((s, i) => {
        s.status = "batched";
        s.batch_id = batch_id;
        s.leaf_index = i;
        s.merkle_root = root;
        s.merkle_proof = proofs[i];
      });
      try {
        const r = await this.backend.anchorBatch({
          batchId: batch_id,
          merkleRoot: "0x" + root,
          batchSize: items.length,
          clientId: this.clientId,
        });
        batch.status = "anchored";
        batch.tx_hash = r.txHash;
        batch.block_number = r.blockNumber;
        batch.anchored_at = new Date(r.timestampMs).toISOString();
        for (const s of items) {
          s.status = "anchored";
          s.tx_hash = r.txHash;
          s.block_number = r.blockNumber;
          s.anchored_at = batch.anchored_at;
        }
      } catch (err: any) {
        // FAIL-CLOSED: mark degraded; stop accepting; never fake "anchored".
        batch.status = "failed";
        batch.error = String(err?.message ?? err);
        this.degraded = true;
        this.degradedReason = "anchor_tx_failed";
        for (const s of items) s.anchor_error = batch.error;
      }
    } finally {
      this.flushing = false;
    }
  }

  receipt(sub: Submission) {
    if (sub.status !== "anchored") return null;
    return {
      schema: "fairseal-anchor-receipt-v1",
      anchor_id: sub.anchor_id,
      commitment_hash: sub.commitment_hash,
      batch_id: sub.batch_id,
      leaf_index: sub.leaf_index,
      merkle_root: sub.merkle_root,
      merkle_proof: sub.merkle_proof,
      chain: sub.chain,
      contract: sub.contract,
      tx_hash: sub.tx_hash,
      block_number: sub.block_number,
      submitted_at: sub.submitted_at,
      anchored_at: sub.anchored_at,
      dry_run: sub.dry_run,
      semantics: {
        proves: "commitment_hash existed no later than the Base block timestamp of tx_hash (bounded precedence); receipt intact since creation",
        does_not_prove: "what the hash represents; that any claimed execution occurred; input authenticity",
      },
      verify: {
        offline: "leaf=commitment_hash; fold merkle_proof (sha256(left||right), sibling.position tells side); compare to merkle_root",
        onchain: "MerkleAnchor.getBatchRoot(batch_id) on contract must equal 0x<merkle_root> (any Base RPC)",
      },
    };
  }
}

// ─── HTTP surface ────────────────────────────────────────────

interface RateBucket { count: number; windowStart: number; }

export interface MountOpts {
  engine: AnchorEngine;
  apiKeys?: Map<string, ApiKeyRec>; // Bearer keys that bypass x402 up to quota
  rateMax?: number; // per key/ip per window (default 20)
  rateWindowMs?: number; // default 60_000
  price?: string; // x402 price, default $0.01
  // x402 wiring (from server.ts): omit all three to run without payment gate (tests use apiKeys only)
  paymentMiddleware?: any;
  resourceServer?: any;
  network?: string;
  payTo?: string;
}

/** Parse ANCHOR_API_KEYS env: "key1:starter:1000,key2:pro:100000" */
export function parseApiKeys(envVal: string | undefined): Map<string, ApiKeyRec> {
  const m = new Map<string, ApiKeyRec>();
  if (!envVal) return m;
  for (const entry of envVal.split(",").map((s) => s.trim()).filter(Boolean)) {
    const [key, tier = "starter", quota = "1000"] = entry.split(":");
    m.set(key, { key, tier: tier === "pro" ? "pro" : "starter", quota: parseInt(quota, 10) || 1000, used: 0 });
  }
  return m;
}

export function mountAnchorApiV2(app: Express, opts: MountOpts) {
  const { engine } = opts;
  const apiKeys = opts.apiKeys ?? parseApiKeys(process.env.ANCHOR_API_KEYS);
  const rateMax = opts.rateMax ?? 20;
  const rateWindowMs = opts.rateWindowMs ?? 60_000;
  const buckets = new Map<string, RateBucket>();

  // Body parsing scoped to /v2 only (no-op if body already parsed upstream).
  app.use("/v2", express.json({ limit: "16kb" }));

  const rateOk = (key: string): boolean => {
    const now = Date.now();
    let b = buckets.get(key);
    if (!b || now - b.windowStart >= rateWindowMs) {
      b = { count: 0, windowStart: now };
      buckets.set(key, b);
    }
    b.count++;
    return b.count <= rateMax;
  };

  const submitHandler = (req: Request, res: Response, auth: { id: string; keyRec?: ApiKeyRec }) => {
    const { payload_hash, metadata, tier } = (req.body ?? {}) as any;
    if (typeof payload_hash !== "string" || !HEX64.test(payload_hash)) {
      return res.status(400).json({ error: "invalid_payload_hash", detail: "payload_hash must be a 64-char hex SHA-256 digest" });
    }
    if (metadata !== undefined && JSON.stringify(metadata).length > 1024) {
      return res.status(400).json({ error: "metadata_too_large", limit_bytes: 1024 });
    }
    const t = tier === "realtime" ? "realtime" : "batch";
    if (t === "realtime" && auth.keyRec?.tier !== "pro") {
      return res.status(403).json({ error: "realtime_requires_pro" });
    }
    const r = engine.submit(payload_hash, metadata, t, auth.id);
    if (!r.ok) {
      const body: any = { error: r.error };
      if (r.anchor_id) body.anchor_id = r.anchor_id;
      if (r.code === 503) body.detail = "anchoring pipeline degraded — submission rejected (fail-closed), no payment settled";
      return res.status(r.code).json(body);
    }
    if (auth.keyRec) auth.keyRec.used++;
    const s = r.sub;
    return res.status(202).json({
      anchor_id: s.anchor_id,
      status: s.status,
      commitment_hash: s.commitment_hash,
      chain: s.chain,
      tier: s.tier,
      dry_run: s.dry_run,
      estimated_anchor_seconds: t === "realtime" ? 5 : 60,
      status_url: `/v2/anchor/${s.anchor_id}`,
    });
  };

  // Fail-closed pre-flight: reject BEFORE x402 negotiation so buyers are never charged into a degraded pipeline.
  app.use("/v2/anchor", (req: Request, res: Response, next: NextFunction) => {
    if (req.method !== "POST") return next();
    const gate = engine.acceptingSubmissions();
    if (!gate.ok) return res.status(503).json({ error: gate.reason, retry_after_ms: 30_000 });
    next();
  });

  // API-key path (bypasses x402 up to quota) + rate limit for everyone.
  app.post("/v2/anchor", (req: Request, res: Response, next: NextFunction) => {
    const authz = req.headers.authorization ?? "";
    const bearer = authz.startsWith("Bearer ") ? authz.slice(7) : null;
    const keyRec = bearer ? apiKeys.get(bearer) : undefined;
    const rlKey = keyRec ? `key:${keyRec.key}` : `ip:${req.ip}`;
    if (!rateOk(rlKey)) {
      return res.status(429).json({ error: "rate_limited", limit: rateMax, window_ms: rateWindowMs });
    }
    if (keyRec) {
      if (keyRec.used >= keyRec.quota) {
        return res.status(402).json({ error: "quota_exhausted", quota: keyRec.quota, used: keyRec.used, detail: "top up subscription or pay per-call via x402" });
      }
      return submitHandler(req, res, { id: `key:${keyRec.key.slice(0, 8)}`, keyRec });
    }
    next(); // fall through to x402 payment gate
  });

  // x402 payment gate for keyless callers.
  if (opts.paymentMiddleware && opts.resourceServer) {
    app.use(
      opts.paymentMiddleware(
        {
          "POST /v2/anchor": {
            accepts: [{ scheme: "exact", price: opts.price ?? "$0.01", network: opts.network, payTo: opts.payTo }],
            description: "Anchor a 32-byte commitment hash into a Merkle batch on Base mainnet. Returns anchor_id; poll status for merkle proof + tx hash receipt.",
            mimeType: "application/json",
          },
        },
        opts.resourceServer,
      ),
    );
  }

  // Paid handler (reached only after x402 settle when payment stack mounted).
  app.post("/v2/anchor", (req: Request, res: Response) =>
    submitHandler(req, res, { id: `x402:${req.ip}` }),
  );

  // Free read endpoints (light IP rate limit shares the same buckets).
  const readGuard = (req: Request, res: Response, next: NextFunction) => {
    if (!rateOk(`read:${req.ip}`)) return res.status(429).json({ error: "rate_limited" });
    next();
  };

  const statusBody = (s: Submission) => ({
    anchor_id: s.anchor_id,
    status: s.status,
    commitment_hash: s.commitment_hash,
    batch_id: s.batch_id,
    merkle_root: s.merkle_root,
    merkle_proof: s.merkle_proof,
    chain: s.chain,
    contract: s.contract,
    tx_hash: s.tx_hash,
    block_number: s.block_number,
    submitted_at: s.submitted_at,
    anchored_at: s.anchored_at,
    dry_run: s.dry_run,
    ...(s.anchor_error ? { anchor_error: s.anchor_error } : {}),
    ...(s.status === "anchored" ? { receipt: engine.receipt(s) } : {}),
  });

  const getSub = (res: Response, id: string): Submission | null => {
    const s = engine.subs.get(id);
    if (!s) {
      res.status(404).json({ error: "anchor_not_found" });
      return null;
    }
    return s;
  };

  app.get("/v2/anchor/batches", readGuard, (_req, res) => {
    res.json({
      batches: [...engine.batches.values()].map((b) => ({
        batch_id: b.batch_id, status: b.status, merkle_root: b.merkle_root,
        leaf_count: b.leaf_count, tx_hash: b.tx_hash, block_number: b.block_number,
        created_at: b.created_at, anchored_at: b.anchored_at, dry_run: b.dry_run,
      })),
    });
  });
  app.get("/v2/anchor/status/:id", readGuard, (req, res) => {
    const s = getSub(res, req.params.id as string);
    if (s) res.json(statusBody(s));
  });
  app.get("/v2/anchor/receipt/:id", readGuard, (req, res) => {
    const s = getSub(res, req.params.id as string);
    if (!s) return;
    const r = engine.receipt(s);
    if (!r) return res.status(409).json({ error: "not_anchored_yet", status: s.status });
    res.json(r);
  });
  app.get("/v2/anchor/:id/receipt", readGuard, (req, res) => {
    const s = getSub(res, req.params.id as string);
    if (!s) return;
    const r = engine.receipt(s);
    if (!r) return res.status(409).json({ error: "not_anchored_yet", status: s.status });
    res.json(r);
  });
  app.get("/v2/anchor/:id", readGuard, (req, res) => {
    const s = getSub(res, req.params.id as string);
    if (s) res.json(statusBody(s));
  });
  app.get("/v2/batches/:id", readGuard, (req, res) => {
    const b = engine.batches.get(req.params.id as string);
    if (!b) return res.status(404).json({ error: "batch_not_found" });
    res.json(b);
  });
}
