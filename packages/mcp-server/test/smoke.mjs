#!/usr/bin/env node
/**
 * Smoke test — builds the MCP server in-process, lists tools, and exercises
 * the local-only + free tools. No API key required.
 *
 * Run: npm run build && node test/smoke.mjs
 */
import { createHash } from "node:crypto";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { InMemoryTransport } from "@modelcontextprotocol/sdk/inMemory.js";
import { buildServer } from "../dist/build-server.js";

let failures = 0;
const check = (name, cond, detail = "") => {
  console.log(`${cond ? "PASS" : "FAIL"}  ${name}${detail ? " — " + detail : ""}`);
  if (!cond) failures++;
};

const [clientTransport, serverTransport] = InMemoryTransport.createLinkedPair();
const server = buildServer();
await server.connect(serverTransport);
const client = new Client({ name: "smoke-test", version: "0.0.0" });
await client.connect(clientTransport);

// 1. Tool inventory — existing tools must not regress; oversight tools must exist.
const { tools } = await client.listTools();
const names = tools.map((t) => t.name).sort();
const expected = [
  // existing (v0.1.x)
  "fairseal_entropy",
  "fairseal_games_catalog",
  "fairseal_stats",
  "fairseal_recent_games",
  "fairseal_game_result",
  "fairseal_verify_game",
  "fairseal_rng_generate",
  "fairseal_sicbo_bet",
  "fairseal_dice_bet",
  "fairseal_gacha_pull",
  "fairseal_slots_spin",
  "fairseal_anchor_submit",
  "fairseal_anchor_status",
  // v0.2.0 oversight
  "fairseal_hash_content",
  "fairseal_notarize_decision",
  "fairseal_notarize_status",
  // v0.2.4+ additions
  "fairseal_break_assign",
  "fairseal_verify_receipt",
];
for (const n of expected) check(`tool registered: ${n}`, names.includes(n));
check("tool count", names.length === expected.length, `${names.length} tools`);

// 2. fairseal_hash_content — pure local, deterministic.
const content = "the quick brown fox";
const res = await client.callTool({ name: "fairseal_hash_content", arguments: { content } });
const parsed = JSON.parse(res.content[0].text);
const want = createHash("sha256").update(content, "utf8").digest("hex");
check("hash_content sha256 correct", parsed.sha256 === want, parsed.sha256);
check("hash_content length_bytes", parsed.length_bytes === Buffer.byteLength(content));

// 3. fairseal_games_catalog — free live endpoint (no key).
const cat = await client.callTool({ name: "fairseal_games_catalog", arguments: {} });
const catBody = JSON.parse(cat.content[0].text);
check("games_catalog http 200", catBody.http_status === 200, `status=${catBody.http_status}`);

// 4. fairseal_anchor_status with unknown id — live free endpoint, expect 404-style error relay.
const st = await client.callTool({
  name: "fairseal_anchor_status",
  arguments: { anchor_id: "anc_000000000000000000ff" },
});
const stBody = JSON.parse(st.content[0].text);
check("anchor_status unknown id relays error", st.isError === true && stBody.http_status === 404, `status=${stBody.http_status}`);

// 5. notarize_decision without key — must return a clear error, not silence.
if (!process.env.FAIRSEAL_API_KEY && !process.env.FAIRSEAL_NOTARY_API_KEY) {
  const h = want;
  const nk = await client.callTool({
    name: "fairseal_notarize_decision",
    arguments: { agent_id: "smoke", input_hash: h, decision_hash: h },
  });
  const nkBody = JSON.parse(nk.content[0].text);
  check(
    "notarize without key → explicit error + guidance",
    nk.isError === true && nkBody.error === "missing_api_key" && /hello@fairseal\.io/.test(nkBody.hint),
  );
} else {
  console.log("SKIP  notarize no-key check (key present in env)");
}

await client.close();
await server.close();
console.log(failures === 0 ? "\nSMOKE: ALL PASS" : `\nSMOKE: ${failures} FAILURE(S)`);
process.exit(failures === 0 ? 0 : 1);
