/**
 * Anchor API v2 — end-to-end dev test (dry-run backend, dev port, zero gas,
 * zero production impact). Run: npx tsx test-anchor-v2.ts
 *
 * Covers:
 *  T1 402 without payment/key (x402 challenge)
 *  T2 lifecycle queued→batched→anchored (dry-run) + proof verifies offline
 *  T3 dedupe replay → 409
 *  T4 rate limit → 429
 *  T5 fail-closed: degraded pipeline → 503 (and failed batch never reports anchored)
 *  T6 quota metering → 402 quota_exhausted
 */
import express from "express";
import { createHash, randomBytes } from "node:crypto";
import {
  AnchorEngine,
  createDryRunBackend,
  createFailingBackend,
  mountAnchorApiV2,
  verifyProof,
  type ApiKeyRec,
} from "./anchor-api.ts";

const PORT = 8433; // dev-only port, NOT production (prod x402 = 8402)
const BASE = `http://127.0.0.1:${PORT}`;
const sha = (s: string) => createHash("sha256").update(s).digest("hex");
const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));

let pass = 0, fail = 0;
const check = (name: string, ok: boolean, detail = "") => {
  if (ok) { pass++; console.log(`  ✅ ${name}`); }
  else { fail++; console.error(`  ❌ ${name} ${detail}`); }
};

async function main() {
  // ── x402 stack (same libs as production server.ts; URL facilitator, never settles) ──
  const { paymentMiddleware, x402ResourceServer } = await import("@x402/express");
  const { ExactEvmScheme } = await import("@x402/evm/exact/server");
  const { HTTPFacilitatorClient } = await import("@x402/core/server");
  const NETWORK = "eip155:84532"; // testnet network id — challenge only, nothing settles
  const facilitator = new HTTPFacilitatorClient({ url: "https://x402.org/facilitator" });
  const resourceServer = new (x402ResourceServer as any)(facilitator).register(NETWORK, new (ExactEvmScheme as any)());

  const app = express();
  app.use(express.json({ limit: "16kb" }));

  const engine = new AnchorEngine({
    backend: createDryRunBackend(),
    batchThreshold: 3,
    batchIntervalMs: 500, // fast timer for tests
    contract: "0xEE09671Bbc6B932BF1461CAff360bfDD9bEA55ca",
  });
  const keys = new Map<string, ApiKeyRec>([
    ["test-key-pro", { key: "test-key-pro", tier: "pro", quota: 100, used: 0 }],
    ["test-key-tiny", { key: "test-key-tiny", tier: "starter", quota: 2, used: 0 }],
  ]);
  mountAnchorApiV2(app, {
    engine, apiKeys: keys, rateMax: 15, rateWindowMs: 60_000,
    paymentMiddleware, resourceServer, network: NETWORK,
    payTo: "0x6323610984fE1eB0F27E12F7B04A8b88BB1810dC",
  });

  const server = app.listen(PORT);
  await sleep(300);

  const post = (body: any, key?: string) =>
    fetch(`${BASE}/v2/anchor`, {
      method: "POST",
      headers: { "content-type": "application/json", ...(key ? { authorization: `Bearer ${key}` } : {}) },
      body: JSON.stringify(body),
    });

  // ── T1: no payment, no key → 402 with x402 challenge ──
  console.log("T1: 402 without payment");
  const r1 = await post({ payload_hash: sha("t1") });
  check("returns 402", r1.status === 402, `got ${r1.status}`);
  // x402 v2 puts the challenge in the PAYMENT-REQUIRED header (base64 JSON) — same as prod /v1/rng/latest
  const chalHdr = r1.headers.get("payment-required");
  let chal: any = null;
  try { chal = chalHdr ? JSON.parse(Buffer.from(chalHdr, "base64").toString("utf8")) : null; } catch {}
  check("x402 challenge present", !!(chal?.accepts?.length && chal?.x402Version), (chalHdr ?? "no header").slice(0, 60));

  // ── T2: lifecycle via API key ──
  console.log("T2: lifecycle queued→batched→anchored (dry-run)");
  const h2 = sha("t2-" + randomBytes(4).toString("hex"));
  const r2 = await post({ payload_hash: h2, metadata: { source: "e2e-test" } }, "test-key-pro");
  const b2: any = await r2.json();
  check("202 accepted", r2.status === 202, `got ${r2.status}`);
  check("status queued", b2.status === "queued");
  check("dry_run flagged", b2.dry_run === true);
  // fill batch to threshold to trigger flush
  await post({ payload_hash: sha("t2b-" + randomBytes(4).toString("hex")) }, "test-key-pro");
  await post({ payload_hash: sha("t2c-" + randomBytes(4).toString("hex")) }, "test-key-pro");
  await sleep(700); // timer + flush
  const s2: any = await (await fetch(`${BASE}/v2/anchor/status/${b2.anchor_id}`)).json();
  check("anchored", s2.status === "anchored", `status=${s2.status}`);
  check("tx_hash dry-run marked", typeof s2.tx_hash === "string" && s2.tx_hash.startsWith("0xDRYRUN"), s2.tx_hash);
  check("merkle proof verifies offline", !!s2.merkle_proof && verifyProof(h2, s2.merkle_proof, s2.merkle_root));
  const rec: any = await (await fetch(`${BASE}/v2/anchor/receipt/${b2.anchor_id}`)).json();
  check("receipt endpoint (alias) works", rec.schema === "fairseal-anchor-receipt-v1" && rec.anchor_id === b2.anchor_id);
  const rec2: any = await (await fetch(`${BASE}/v2/anchor/${b2.anchor_id}/receipt`)).json();
  check("receipt endpoint (doc path) works", rec2.schema === "fairseal-anchor-receipt-v1");
  const batches: any = await (await fetch(`${BASE}/v2/anchor/batches`)).json();
  check("batches list shows anchored batch", batches.batches?.some((b: any) => b.batch_id === s2.batch_id && b.status === "anchored"));
  const bd: any = await (await fetch(`${BASE}/v2/batches/${s2.batch_id}`)).json();
  check("batch detail root matches", bd.merkle_root === s2.merkle_root);

  // ── T3: dedupe replay → 409 ──
  console.log("T3: dedupe replay rejection");
  const r3 = await post({ payload_hash: h2 }, "test-key-pro");
  const b3: any = await r3.json();
  check("409 duplicate", r3.status === 409 && b3.error === "duplicate_payload", `got ${r3.status}`);
  check("points to existing anchor_id", b3.anchor_id === b2.anchor_id);

  // ── T6: quota metering ──
  console.log("T6: quota metering");
  await post({ payload_hash: sha("q1-" + randomBytes(4).toString("hex")) }, "test-key-tiny");
  await post({ payload_hash: sha("q2-" + randomBytes(4).toString("hex")) }, "test-key-tiny");
  const r6 = await post({ payload_hash: sha("q3-" + randomBytes(4).toString("hex")) }, "test-key-tiny");
  const b6: any = await r6.json();
  check("quota_exhausted after 2 uses", r6.status === 402 && b6.error === "quota_exhausted", `got ${r6.status} ${b6.error}`);

  // ── T4: rate limit → 429 ──
  console.log("T4: rate limit");
  let got429 = false;
  for (let i = 0; i < 20; i++) {
    const r = await post({ payload_hash: sha(`rl-${i}-${randomBytes(4).toString("hex")}`) }, "test-key-pro");
    if (r.status === 429) { got429 = true; break; }
  }
  check("429 triggered within burst", got429);

  // ── T5: fail-closed 503 ──
  console.log("T5: fail-closed semantics");
  const app5 = express();
  app5.use(express.json());
  const engine5 = new AnchorEngine({ backend: createFailingBackend(), batchThreshold: 1, batchIntervalMs: 200 });
  mountAnchorApiV2(app5, { engine: engine5, apiKeys: new Map([["k", { key: "k", tier: "pro", quota: 10, used: 0 } as ApiKeyRec]]) });
  const server5 = app5.listen(PORT + 1);
  await sleep(200);
  const r5 = await fetch(`http://127.0.0.1:${PORT + 1}/v2/anchor`, {
    method: "POST",
    headers: { "content-type": "application/json", authorization: "Bearer k" },
    body: JSON.stringify({ payload_hash: sha("fc") }),
  });
  check("unhealthy backend → 503 (no acceptance, fail-closed)", r5.status === 503, `got ${r5.status}`);
  // degraded-after-tx-failure path
  const engine5b = new AnchorEngine({
    backend: { name: "flaky", dryRun: true, healthy: () => true, anchorBatch: async () => { throw new Error("boom"); } },
    batchThreshold: 1, batchIntervalMs: 200,
  });
  const rA = engine5b.submit(sha("fc2"), null, "batch", "test");
  await sleep(300);
  const subA = rA.ok ? engine5b.subs.get(rA.sub.anchor_id)! : null;
  check("failed tx never reports anchored", !!subA && subA.status !== "anchored" && !!subA.anchor_error);
  const rB = engine5b.submit(sha("fc3"), null, "batch", "test");
  check("engine degrades → subsequent submit 503", !rB.ok && (rB as any).code === 503);

  engine.stop(); engine5.stop(); engine5b.stop();
  server.close(); server5.close();

  console.log(`\nRESULT: ${pass} passed, ${fail} failed`);
  process.exit(fail === 0 ? 0 : 1);
}

main().catch((e) => { console.error("FATAL", e); process.exit(1); });
