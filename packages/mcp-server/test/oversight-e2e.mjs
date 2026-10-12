#!/usr/bin/env node
/**
 * Oversight e2e — real API, no mocks.
 *
 * Flow: hash_content(input) → hash_content(decision) → notarize_decision (real 201
 * receipt) → anchor_submit → poll anchor_status until anchored or 120s timeout.
 *
 * Requires env:
 *   FAIRSEAL_NOTARY_API_KEY  (or FAIRSEAL_API_KEY)  — notary Bearer key
 *   FAIRSEAL_ANCHOR_API_KEY  (or FAIRSEAL_API_KEY)  — anchor v2 Bearer key
 *
 * Run: npm run build && FAIRSEAL_NOTARY_API_KEY=... FAIRSEAL_ANCHOR_API_KEY=... node test/oversight-e2e.mjs
 */
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { InMemoryTransport } from "@modelcontextprotocol/sdk/inMemory.js";

if (!process.env.FAIRSEAL_NOTARY_API_KEY && !process.env.FAIRSEAL_API_KEY) {
  console.error("Missing FAIRSEAL_NOTARY_API_KEY / FAIRSEAL_API_KEY — cannot run e2e.");
  process.exit(2);
}
if (!process.env.FAIRSEAL_ANCHOR_API_KEY && !process.env.FAIRSEAL_API_KEY) {
  console.error("Missing FAIRSEAL_ANCHOR_API_KEY / FAIRSEAL_API_KEY — cannot run e2e.");
  process.exit(2);
}

const { buildServer } = await import("../dist/build-server.js");

const [clientTransport, serverTransport] = InMemoryTransport.createLinkedPair();
const server = buildServer();
await server.connect(serverTransport);
const client = new Client({ name: "oversight-e2e", version: "0.0.0" });
await client.connect(clientTransport);

const call = async (name, args) => {
  const r = await client.callTool({ name, arguments: args });
  return { isError: r.isError === true, body: JSON.parse(r.content[0].text) };
};
const die = (msg, obj) => {
  console.error(`E2E FAIL: ${msg}`, JSON.stringify(obj, null, 2));
  process.exit(1);
};

// 1+2. Hash input & decision locally.
const inputText = `e2e input @ ${new Date().toISOString()} — user asked for a refund decision`;
const decisionText = `e2e decision @ ${new Date().toISOString()} — approve refund, policy §4.2`;
const h1 = await call("fairseal_hash_content", { content: inputText });
const h2 = await call("fairseal_hash_content", { content: decisionText });
if (h1.isError || h2.isError) die("hash_content failed", { h1, h2 });
console.log(`input_hash    = ${h1.body.sha256}`);
console.log(`decision_hash = ${h2.body.sha256}`);

// 3. Notarize (real receipt).
const nz = await call("fairseal_notarize_decision", {
  agent_id: "fairseal-mcp-e2e",
  input_hash: h1.body.sha256,
  decision_hash: h2.body.sha256,
  model: "oversight-e2e",
  description: "v0.2.0 e2e test receipt",
});
if (nz.isError || nz.body.http_status !== 201) die("notarize_decision did not return 201", nz);
const receiptId = nz.body.receipt_id;
console.log(`RECEIPT: ${receiptId} (http ${nz.body.http_status}, status=${nz.body.status})`);
console.log(`verify_url: ${nz.body.verify_url}`);

// 3b. Receipt lookup (free).
const rl = await call("fairseal_notarize_status", { receipt_id: receiptId });
if (rl.isError || rl.body.receipt_id !== receiptId) die("notarize_status lookup failed", rl);
console.log(`receipt lookup OK (status=${rl.body.status})`);

// 4. Anchor the receipt's leaf hash.
const az = await call("fairseal_anchor_submit", {
  payload_hash: nz.body.leaf_hash,
  metadata: { source: "fairseal-mcp oversight e2e", receipt_id: receiptId },
});
if (az.isError || !az.body.anchor_id) die("anchor_submit failed", az);
const anchorId = az.body.anchor_id;
console.log(`ANCHOR: ${anchorId} (http ${az.body.http_status}, status=${az.body.status})`);

// 5. Poll until anchored or 120s.
const deadline = Date.now() + 120_000;
let last = null;
while (Date.now() < deadline) {
  await new Promise((r) => setTimeout(r, 5000));
  const st = await call("fairseal_anchor_status", { anchor_id: anchorId });
  if (st.isError) die("anchor_status errored", st);
  last = st.body;
  console.log(`  poll: status=${last.status} tx=${last.tx_hash ?? "-"}`);
  if (last.status === "anchored") break;
}

await client.close();
await server.close();

if (!last || last.status !== "anchored") {
  console.error("E2E FAIL: not anchored within 120s. Last:", JSON.stringify(last, null, 2));
  process.exit(1);
}

console.log("\n=== E2E PASS ===");
console.log(`receipt_id : ${receiptId}`);
console.log(`anchor_id  : ${anchorId}`);
console.log(`merkle_root: ${last.merkle_root}`);
console.log(`tx_hash    : ${last.tx_hash}`);
console.log(`block      : ${last.block_number}`);
console.log(`basescan   : https://basescan.org/tx/${last.tx_hash}`);
process.exit(0);
