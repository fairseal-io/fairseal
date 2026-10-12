/**
 * FairSeal MCP Server — shared tool registry.
 * Used by both the stdio entry (server.ts) and the HTTP entry (http.ts).
 */

import { createHash } from "node:crypto";
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";
import { verifyAnchor } from "@fairseal/verify";
import {
  apiGet,
  apiPost,
  apiRequestTo,
  ANCHOR_API_KEY,
  BASE_URL,
  NOTARY_API_KEY,
  VERSION,
  X402_URL,
} from "./client.js";

function jsonContent(data: unknown, isError = false) {
  return {
    content: [{ type: "text" as const, text: JSON.stringify(data, null, 2) }],
    isError,
  };
}

const HEX64 = /^[0-9a-f]{64}$/;

const NO_KEY_HINT =
  "No API key configured. Set FAIRSEAL_API_KEY in your MCP server env config " +
  "(e.g. \"env\": { \"FAIRSEAL_API_KEY\": \"...\" }). To request a key, email hello@fairseal.io. " +
  "Zero-account alternative: both endpoints also accept x402 USDC micropayments on Base with no key " +
  "and no signup — POST https://x402.fairseal.io/v1/notarize or /v2/anchor without auth returns an " +
  "HTTP 402 whose PAYMENT-REQUIRED header contains machine-readable payment terms " +
  "(see https://x402.fairseal.io/.well-known/x402).";

const MCP_AUTH_HINT =

  "This tool requires an API key. Set FAIRSEAL_API_KEY in your MCP server env config " +
  "(e.g. \"env\": { \"FAIRSEAL_API_KEY\": \"orn_...\" }). No key yet? Request early access — " +
  "see https://fairseal.io/llms.txt. Free tools that work without a key: fairseal_games_catalog, " +
  "fairseal_recent_games, fairseal_game_result, fairseal_verify_game, and all bet/pull/spin tools.";

async function relay(promise: Promise<{ ok: boolean; status: number; body: unknown }>) {
  try {
    const r = await promise;
    const payload: Record<string, unknown> = { http_status: r.status, ...wrapBody(r.body) };
    if (r.status === 401 || r.status === 403) payload.hint = MCP_AUTH_HINT;
    return jsonContent(payload, !r.ok);
  } catch (err) {
    return jsonContent({ error: String(err) }, true);
  }
}

function wrapBody(body: unknown): Record<string, unknown> {
  return typeof body === "object" && body !== null
    ? (body as Record<string, unknown>)
    : { body };
}

export function buildServer(): McpServer {
  const server = new McpServer({
    name: "fairseal-mcp-server",
    version: VERSION,
  });

  // ---------- Read-only tools ----------

  server.registerTool(
    "fairseal_entropy",
    {
      title: "Get verifiable entropy",
      description:
        "Fetch raw verifiable entropy from the latest resolved VDF epoch at api.fairseal.io. Read-only. [requires FAIRSEAL_API_KEY]",
      inputSchema: {},
    },
    async () => relay(apiGet("/api/v1/entropy")),
  );

  server.registerTool(
    "fairseal_games_catalog",
    {
      title: "List FairSeal games",
      description:
        "List available provably-fair games (sicbo, dice, gacha, slots) with bet types and endpoints. Read-only.",
      inputSchema: {},
    },
    async () => relay(apiGet("/api/v1/games")),
  );

  server.registerTool(
    "fairseal_stats",
    {
      title: "Engine stats",
      description: "FairSeal entropy engine statistics. Read-only. [requires FAIRSEAL_API_KEY]",
      inputSchema: {},
    },
    async () => relay(apiGet("/api/v1/stats")),
  );

  server.registerTool(
    "fairseal_recent_games",
    {
      title: "Recent games",
      description: "List recently resolved games (useful to find game_ids to verify). Read-only.",
      inputSchema: {},
    },
    async () => relay(apiGet("/api/v1/recent")),
  );

  server.registerTool(
    "fairseal_game_result",
    {
      title: "Get game result",
      description: "Fetch the result of a game by game_id (poll until resolved). Read-only.",
      inputSchema: {
        game_id: z
          .string()
          .describe(
            "Game ID — 64-char hex hash, e.g. 64096a172374489ccd4563d7c15efe5e467604dd826149da0511a0fa6109e26f (get one from fairseal_recent_games or a bet tool response)",
          ),
      },
    },
    async ({ game_id }) => relay(apiGet(`/api/v1/games/${encodeURIComponent(game_id)}`)),
  );

  server.registerTool(
    "fairseal_verify_game",
    {
      title: "Verify game fairness",
      description:
        "Verify the fairness of a completed game. Returns VDF proof data and replay steps for independent verification. Read-only.",
      inputSchema: { game_id: z.string().describe("Game ID to verify") },
    },
    async ({ game_id }) => relay(apiGet(`/api/v1/verify/${encodeURIComponent(game_id)}`)),
  );

  // ---------- Write tools (live API, testnet-grade play money) ----------

  server.registerTool(
    "fairseal_rng_generate",
    {
      title: "Generate verifiable RNG",
      description:
        "Request raw verifiable random number generation (resolves after next VDF epoch, ~5s). Returns a poll URL / game_id. [requires FAIRSEAL_API_KEY]",
      inputSchema: {
        client_seed: z.string().optional().describe("Optional client-provided seed"),
      },
    },
    async ({ client_seed }) => relay(apiPost("/api/v1/rng/generate", { client_seed })),
  );

  server.registerTool(
    "fairseal_sicbo_bet",
    {
      title: "Place Sic Bo bet",
      description:
        "Place a three-dice Sic Bo bet. Outcomes provably fair via VDF. Resolves after next epoch (~5s); use fairseal_game_result to poll.",
      inputSchema: {
        bet_type: z.enum([
          "big", "small", "odd", "even", "total", "single", "double", "triple", "anyTriple", "combo",
        ]),
        amount: z.number().positive().default(1),
        target: z.number().int().optional().describe("Target value (total/single/double/triple bets)"),
        combo: z.array(z.number().int()).optional().describe("Dice combination for combo bets"),
        player_id: z.string().default("mcp-client"),
        player_seed: z.string().optional(),
      },
    },
    async (args) => relay(apiPost("/api/v1/games/sicbo/bet", args)),
  );

  server.registerTool(
    "fairseal_dice_bet",
    {
      title: "Place Dice bet",
      description: "Place a two-dice bet (exact/over7/under7/odd/even). Resolves after next epoch (~5s).",
      inputSchema: {
        bet_type: z.enum(["exact", "over7", "under7", "odd", "even"]),
        amount: z.number().positive().default(1),
        target: z.number().int().optional().describe("Target sum for exact bets"),
        player_id: z.string().default("mcp-client"),
        player_seed: z.string().optional(),
      },
    },
    async (args) => relay(apiPost("/api/v1/games/dice/bet", args)),
  );

  server.registerTool(
    "fairseal_gacha_pull",
    {
      title: "Gacha pull",
      description: "Pull a weighted loot box (standard or premium pool). Provably fair via VDF.",
      inputSchema: {
        pool: z.enum(["standard", "premium"]).default("standard"),
        player_id: z.string().default("mcp-client"),
        player_seed: z.string().optional(),
      },
    },
    async (args) => relay(apiPost("/api/v1/games/gacha/pull", args)),
  );

  server.registerTool(
    "fairseal_slots_spin",
    {
      title: "Slots spin",
      description: "Spin the 5-reel 3-row slot machine with wild substitution. Provably fair via VDF.",
      inputSchema: {
        amount: z.number().positive().default(1),
        player_id: z.string().default("mcp-client"),
        player_seed: z.string().optional(),
      },
    },
    async (args) => relay(apiPost("/api/v1/games/slots/spin", args)),
  );

  // ---------- Oversight tools: verifiable audit trails for agent decisions ----------

  server.registerTool(
    "fairseal_hash_content",
    {
      title: "Hash content locally (SHA-256)",
      description:
        "Compute the SHA-256 hex digest of a string locally. Zero network calls — the content never " +
        "leaves this machine. Use it to hash an agent's input and decision text before notarizing, so " +
        "only hashes (never raw content) are sent to FairSeal.",
      inputSchema: {
        content: z.string().describe("Content to hash (UTF-8). Never transmitted anywhere."),
      },
    },
    async ({ content }) => {
      const bytes = Buffer.from(content, "utf8");
      return jsonContent({
        algorithm: "sha256",
        sha256: createHash("sha256").update(bytes).digest("hex"),
        length_bytes: bytes.length,
        note: "Computed locally; content was not sent over the network.",
      });
    },
  );

  server.registerTool(
    "fairseal_notarize_decision",
    {
      title: "Notarize an agent decision",
      description:
        "Create a cryptographic receipt for an AI-agent decision (POST /v1/notarize, schema " +
        "agent_decision). The receipt is Merkle-batched and anchored on Base mainnet; verify offline " +
        "with @fairseal/verify or at the returned verify_url. Receipts prove provenance (this hash " +
        "existed at this time), not correctness of the decision. [requires FAIRSEAL_API_KEY or " +
        "FAIRSEAL_NOTARY_API_KEY]",
      inputSchema: {
        agent_id: z.string().min(1).describe("Stable identifier of the deciding agent"),
        input_hash: z
          .string()
          .regex(HEX64, "64-char lowercase sha256 hex")
          .describe("SHA-256 hex of the decision input (use fairseal_hash_content)"),
        decision_hash: z
          .string()
          .regex(HEX64, "64-char lowercase sha256 hex")
          .describe("SHA-256 hex of the decision content (use fairseal_hash_content)"),
        decided_at: z
          .string()
          .optional()
          .describe("ISO-8601 UTC timestamp of the decision; defaults to now"),
        payload_hash: z
          .string()
          .regex(HEX64, "64-char lowercase sha256 hex")
          .optional()
          .describe(
            "SHA-256 hex of the full payload being notarized; defaults to decision_hash",
          ),
        session_id: z.string().optional().describe("Optional session identifier"),
        model: z.string().optional().describe("Optional model identifier"),
        description: z.string().optional().describe("Optional human-readable description"),
        operator: z.string().optional().describe("Optional operator identifier"),
      },
    },
    async (args) => {
      if (!NOTARY_API_KEY) return jsonContent({ error: "missing_api_key", hint: NO_KEY_HINT }, true);
      const metadata: Record<string, unknown> = {
        agent_id: args.agent_id,
        decided_at: args.decided_at ?? new Date().toISOString(),
        input_hash: args.input_hash,
        decision_hash: args.decision_hash,
      };
      if (args.session_id !== undefined) metadata.session_id = args.session_id;
      if (args.model !== undefined) metadata.model = args.model;
      if (args.description !== undefined) metadata.description = args.description;
      if (args.operator !== undefined) metadata.operator = args.operator;
      return relay(
        apiRequestTo(
          BASE_URL,
          "POST",
          "/v1/notarize",
          {
            schema: "agent_decision",
            payload_hash: args.payload_hash ?? args.decision_hash,
            metadata,
          },
          NOTARY_API_KEY,
        ),
      );
    },
  );

  server.registerTool(
    "fairseal_notarize_status",
    {
      title: "Get notarization receipt",
      description:
        "Fetch a notarization receipt by receipt_id (GET /v1/notarize/{id}). Free, no key needed. " +
        "Returns the receipt, Merkle proof, and on-chain anchor tx once status is 'anchored'.",
      inputSchema: {
        receipt_id: z
          .string()
          .regex(/^nr_[0-9a-f]{32}$/)
          .describe("Receipt ID from fairseal_notarize_decision (nr_...)"),
      },
    },
    async ({ receipt_id }) =>
      relay(apiRequestTo(BASE_URL, "GET", `/v1/notarize/${encodeURIComponent(receipt_id)}`, undefined, null)),
  );

  // ---------- Anchor API v2 (LIVE — x402.fairseal.io) ----------

  server.registerTool(
    "fairseal_anchor_submit",
    {
      title: "Anchor a hash on Base",
      description:
        "Queue a SHA-256 hash for Merkle-batch anchoring to Base mainnet (POST /v2/anchor, live " +
        "service at x402.fairseal.io). Returns anchor_id + status_url; poll with " +
        "fairseal_anchor_status until 'anchored' (typically ~60s). Auth: Bearer key " +
        "(FAIRSEAL_API_KEY / FAIRSEAL_ANCHOR_API_KEY) or keyless x402 USDC micropayment (an HTTP 402 " +
        "response carries machine-readable payment terms).",
      inputSchema: {
        payload_hash: z
          .string()
          .regex(/^[0-9a-fA-F]{64}$/)
          .describe("SHA-256 hex digest of the receipt/commitment to anchor"),
        metadata: z
          .record(z.string(), z.unknown())
          .optional()
          .describe("Optional metadata object stored with the submission"),
      },
    },
    async ({ payload_hash, metadata }) => {
      const body: Record<string, unknown> = {
        payload_hash: payload_hash.toLowerCase(),
        tier: "batch",
      };
      if (metadata !== undefined) body.metadata = metadata;
      const r = await relay(
        apiRequestTo(X402_URL, "POST", "/v2/anchor", body, ANCHOR_API_KEY),
      );
      if (!ANCHOR_API_KEY && r.isError) {
        const first = r.content[0];
        if (first?.type === "text" && first.text.includes("402")) {
          return jsonContent({ error: "payment_or_key_required", hint: NO_KEY_HINT }, true);
        }
      }
      return r;
    },
  );

  server.registerTool(
    "fairseal_anchor_status",
    {
      title: "Anchor status",
      description:
        "Check anchor lifecycle by anchor_id (GET /v2/anchor/{id}, live service). Free, no key " +
        "needed. Lifecycle: queued → batched → anchored (Merkle proof + Base mainnet tx hash).",
      inputSchema: { anchor_id: z.string().describe("Anchor ID from fairseal_anchor_submit") },
    },
    async ({ anchor_id }) =>
      relay(apiRequestTo(X402_URL, "GET", `/v2/anchor/${encodeURIComponent(anchor_id)}`, undefined, null)),
  );

  // ---------- FairBreak: Verifiable spot assignment ----------

  server.registerTool(
    "fairseal_break_assign",
    {
      title: "Verifiable spot assignment (FairBreak)",
      description:
        "Commit-before-entropy spot assignment for live card breaks, giveaways, raffles, or " +
        "any contest where spots must be assigned to participants fairly. Submits {spots[], " +
        "participants[], label?} to POST /v1/break on x402.fairseal.io (commitment immediately, " +
        "then polls until the VDF epoch resolves, ~7-15s) and returns the full verifiable receipt " +
        "with rule_hash, entropy, derivation string, assignment table, and offline verification " +
        "steps. Receipts are cross-verifiable with the break.html web tool. " +
        "Requires FAIRSEAL_ANCHOR_API_KEY or x402 $0.02 USDC payment.",
      inputSchema: {
        spots: z
          .array(z.string().min(1).max(100))
          .min(1)
          .max(500)
          .describe("Ordered list of spots/items to fill (1..500 unique strings, max 100 chars each)"),
        participants: z
          .array(z.string().min(1).max(100))
          .min(1)
          .max(500)
          .describe("Participants to assign (must not exceed spots count; 1..500 unique strings)"),
        label: z
          .string()
          .max(200)
          .optional()
          .describe("Optional label for this break (e.g. 'break-2026-10-07')"),
      },
    },
    async ({ spots, participants, label }) => {
      if (!ANCHOR_API_KEY) return jsonContent({ error: "missing_api_key", hint: NO_KEY_HINT }, true);

      const body: Record<string, unknown> = { spots, participants };
      if (label !== undefined) body.label = label;

      // POST /v1/break
      const postResult = await apiRequestTo(X402_URL, "POST", "/v1/break", body, ANCHOR_API_KEY);
      if (!postResult.ok) {
        const payload: Record<string, unknown> = { http_status: postResult.status, ...wrapBody(postResult.body) };
        if (postResult.status === 402) payload.hint = NO_KEY_HINT;
        return jsonContent(payload, true);
      }

      const commitment = postResult.body as Record<string, unknown>;
      const breakId = commitment?.break_id as string | undefined;
      if (!breakId) return jsonContent({ error: "unexpected_response", body: postResult.body }, true);

      // Poll result_url until resolved (max ~30s)
      const resultPath = `/v1/break/${encodeURIComponent(breakId)}`;
      const startMs = Date.now();
      const MAX_MS = 30_000;
      const POLL_MS = 2_000;

      while (Date.now() - startMs < MAX_MS) {
        await new Promise<void>(r => setTimeout(r, POLL_MS));
        const poll = await apiRequestTo(X402_URL, "GET", resultPath, undefined, null);
        if (poll.ok) {
          const data = poll.body as Record<string, unknown>;
          if (data?.assignment && Array.isArray(data.assignment)) {
            return jsonContent({ http_status: 200, ...wrapBody(poll.body) });
          }
          // Still pending — continue polling
        }
      }

      // Timeout — return commitment with poll hint
      return jsonContent({
        http_status: 202,
        ...wrapBody(commitment),
        hint: `VDF epoch not yet resolved after 30s. Poll manually: GET ${X402_URL}/v1/break/${breakId}`,
      });
    },
  );

  // ---------- Verify receipt: cryptographic local verification ----------

  server.registerTool(
    "fairseal_verify_receipt",
    {
      title: "Verify a FairSeal receipt",
      description:
        "Independently verify any FairSeal receipt (notarize nr_… or anchor anc_…) by fetching it " +
        "from api.fairseal.io and running local cryptographic verification via @fairseal/verify. " +
        "Returns a four-state verdict: verified (on-chain proof passes all checks), invalid (tampered " +
        "or bad proof), unsupported (unrecognized schema or format), or indeterminate (receipt " +
        "unreachable / chain offline / not yet anchored). " +
        "Fail-closed: 'verified' is only returned when ALL checks pass. No API key required. " +
        "AIs can verify, not just humans.",
      inputSchema: {
        receipt_id: z
          .string()
          .optional()
          .describe(
            "Receipt ID to fetch and verify — starts with nr_ (notarize) or anc_ (anchor). " +
            "Provide this OR receipt_json, not both.",
          ),
        receipt_json: z
          .record(z.string(), z.unknown())
          .optional()
          .describe(
            "Full receipt JSON object if you already have it. Provide this OR receipt_id, not both.",
          ),
      },
    },
    async ({ receipt_id, receipt_json }) => {
      // ── Input guard ──────────────────────────────────────────────────────
      if (!receipt_id && !receipt_json) {
        return jsonContent(
          { error: "missing_input", hint: "Provide receipt_id (nr_… or anc_…) or receipt_json." },
          true,
        );
      }
      if (receipt_id && receipt_json) {
        return jsonContent(
          { error: "ambiguous_input", hint: "Provide receipt_id OR receipt_json, not both." },
          true,
        );
      }

      let receipt: unknown = receipt_json;
      let fetched_from: string | undefined;
      let human_view: string | null = null;

      // ── Fetch by ID ──────────────────────────────────────────────────────
      if (receipt_id) {
        const isNotarize = receipt_id.startsWith("nr_");
        const isAnchor   = receipt_id.startsWith("anc_");

        if (!isNotarize && !isAnchor) {
          return jsonContent({
            verdict: "unsupported",
            receipt_id,
            reason:
              "Unrecognized receipt ID prefix — expected nr_… (notarize) or anc_… (anchor).",
            human_view: null,
            verified_with: "@fairseal/verify@0.4.2",
          });
        }

        human_view = `https://verify.fairseal.io/receipt.html?id=${encodeURIComponent(receipt_id)}`;
        const apiBase  = isNotarize ? BASE_URL : X402_URL;
        const apiPath  = isNotarize
          ? `/v1/notarize/${encodeURIComponent(receipt_id)}`
          : `/v2/anchor/${encodeURIComponent(receipt_id)}`;
        fetched_from = `${apiBase}${apiPath}`;

        try {
          const r = await apiRequestTo(apiBase, "GET", apiPath, undefined, null);
          if (!r.ok) {
            return jsonContent({
              verdict: "indeterminate",
              receipt_id,
              reason: `Failed to fetch receipt: HTTP ${r.status} — receipt not found or service unavailable.`,
              http_status: r.status,
              human_view,
              verified_with: "@fairseal/verify@0.4.2",
            });
          }
          receipt = r.body;
        } catch (err) {
          return jsonContent({
            verdict: "indeterminate",
            receipt_id,
            reason: `Network error fetching receipt: ${String(err)}`,
            human_view,
            verified_with: "@fairseal/verify@0.4.2",
          });
        }
      }

      // ── Validate shape ───────────────────────────────────────────────────
      if (!receipt || typeof receipt !== "object" || Array.isArray(receipt)) {
        return jsonContent({
          verdict: "unsupported",
          receipt_id: receipt_id ?? null,
          reason: "Receipt is not a JSON object — unrecognized format.",
          human_view,
          verified_with: "@fairseal/verify@0.4.2",
        });
      }

      const rec = receipt as Record<string, unknown>;

      // Build human_view from receipt fields if not set yet
      if (!human_view) {
        const id = rec["receipt_id"] ?? rec["anchor_id"];
        if (typeof id === "string") {
          human_view = `https://verify.fairseal.io/receipt.html?id=${encodeURIComponent(id)}`;
        }
      }

      // ── Schema recognition pre-check ────────────────────────────────────
      const schema     = rec["schema"];
      const hasKnownSchema =
        schema === "agent_decision" ||
        schema === "fairseal-anchor-receipt-v1" ||
        (typeof rec["object_id"] === "string" && (rec["object_id"] as string).startsWith("veo-"));
      const hasAnchorBlock = Boolean(rec["anchor"]) || Boolean(rec["proof"]);

      if (!hasKnownSchema && !hasAnchorBlock) {
        return jsonContent({
          verdict: "unsupported",
          receipt_id: receipt_id ?? (rec["receipt_id"] as string | undefined) ?? null,
          reason:
            "Receipt schema not recognized — expected schema: agent_decision, " +
            "fairseal-anchor-receipt-v1, or a VEO-2 object with anchor/proof fields.",
          human_view,
          verified_with: "@fairseal/verify@0.4.2",
        });
      }

      // ── Status pre-check: not yet anchored → indeterminate ──────────────
      const receiptStatus = rec["status"];
      if (typeof receiptStatus === "string" && receiptStatus !== "anchored") {
        return jsonContent({
          verdict: "indeterminate",
          receipt_id: receipt_id ?? (rec["receipt_id"] as string | undefined) ?? null,
          reason: `Receipt status is '${receiptStatus}' — not yet anchored. Retry once status is 'anchored'.`,
          human_view,
          verified_with: "@fairseal/verify@0.4.2",
        });
      }

      // ── Run local cryptographic verification ────────────────────────────
      let result: Awaited<ReturnType<typeof verifyAnchor>>;
      try {
        result = await verifyAnchor(receipt);
      } catch (err) {
        return jsonContent({
          verdict: "indeterminate",
          receipt_id: receipt_id ?? null,
          reason: `verifyAnchor threw unexpectedly: ${String(err)}`,
          human_view,
          verified_with: "@fairseal/verify@0.4.2",
        });
      }

      // ── Map to four-state verdict ────────────────────────────────────────
      // verified    — valid:true AND anchored:true (all checks passed)
      // invalid     — valid:false AND anchored:false (tampered or bad proof)
      // indeterminate — anchored:'unknown' (chain unreachable)
      // unsupported — structural:false with schema/format error
      let verdict: "verified" | "invalid" | "unsupported" | "indeterminate";
      let reason: string | undefined;

      if (result.valid === true && result.anchored === true) {
        verdict = "verified";
      } else if (result.anchored === "unknown") {
        verdict = "indeterminate";
        reason  = result.reason ?? "Chain unreachable — cannot verify on-chain anchor. Try again later.";
      } else if (
        !result.structural &&
        result.errors.some(e => /flat_fields_input|not an object|schema/i.test(e))
      ) {
        verdict = "unsupported";
        reason  = result.errors.join("; ");
      } else {
        verdict = "invalid";
        reason  = result.errors.join("; ") || "Verification checks failed — receipt may be tampered or malformed.";
      }

      const effectiveId =
        receipt_id ??
        (rec["receipt_id"] as string | undefined) ??
        (rec["anchor_id"] as string | undefined) ??
        null;

      return jsonContent({
        verdict,
        receipt_id: effectiveId,
        human_view,
        reason,
        structural:  result.structural,
        anchored:    result.anchored,
        checks:      result.checks,
        warnings:    result.warnings.length > 0 ? result.warnings : undefined,
        fetched_from,
        verified_with: "@fairseal/verify@0.4.2",
      });
    },
  );

  return server;
}
