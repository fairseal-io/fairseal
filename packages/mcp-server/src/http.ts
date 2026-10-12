#!/usr/bin/env node
/**
 * FairSeal MCP Server — Streamable HTTP entrypoint.
 *
 * Stateless mode: a fresh McpServer + StreamableHTTPServerTransport per POST.
 * Intended to sit behind nginx at https://api.fairseal.io/mcp with
 * proxy_buffering off (SSE-capable responses).
 *
 * Env:
 *   MCP_HTTP_HOST   default 127.0.0.1
 *   MCP_HTTP_PORT   default 3004
 *   MCP_RATE_LIMIT  requests/min per client IP, default 30
 *   FAIRSEAL_API_URL / FAIRSEAL_API_KEY — upstream (see client.ts)
 */

import http from "node:http";
import { StreamableHTTPServerTransport } from "@modelcontextprotocol/sdk/server/streamableHttp.js";
import { buildServer } from "./build-server.js";
import { BASE_URL } from "./client.js";

const HOST = process.env.MCP_HTTP_HOST ?? "127.0.0.1";
const PORT = Number(process.env.MCP_HTTP_PORT ?? 3004);
const RATE_LIMIT = Number(process.env.MCP_RATE_LIMIT ?? 30); // req/min per IP
const MAX_BODY = 256 * 1024; // 256 KB

// ---- simple per-IP sliding-window rate limiter ----
const rlState = new Map<string, { count: number; windowStart: number }>();
function rateLimited(ip: string): boolean {
  const now = Date.now();
  let s = rlState.get(ip);
  if (!s || now - s.windowStart > 60_000) {
    s = { count: 0, windowStart: now };
    rlState.set(ip, s);
  }
  s.count += 1;
  return s.count > RATE_LIMIT;
}
// periodic cleanup so the map can't grow unbounded
setInterval(() => {
  const now = Date.now();
  for (const [k, v] of rlState) if (now - v.windowStart > 120_000) rlState.delete(k);
}, 60_000).unref();

function clientIp(req: http.IncomingMessage): string {
  const xff = req.headers["x-forwarded-for"];
  if (typeof xff === "string" && xff.length > 0) return xff.split(",")[0]!.trim();
  return req.socket.remoteAddress ?? "unknown";
}

function sendJson(res: http.ServerResponse, status: number, obj: unknown) {
  const body = JSON.stringify(obj);
  res.writeHead(status, { "content-type": "application/json" });
  res.end(body);
}

function readBody(req: http.IncomingMessage): Promise<string> {
  return new Promise((resolve, reject) => {
    let size = 0;
    const chunks: Buffer[] = [];
    req.on("data", (c: Buffer) => {
      size += c.length;
      if (size > MAX_BODY) {
        reject(new Error("body too large"));
        req.destroy();
        return;
      }
      chunks.push(c);
    });
    req.on("end", () => resolve(Buffer.concat(chunks).toString("utf8")));
    req.on("error", reject);
  });
}

const httpServer = http.createServer(async (req, res) => {
  const url = (req.url ?? "").split("?")[0];

  // health probe (local + via nginx if ever exposed)
  if (req.method === "GET" && (url === "/mcp/health" || url === "/health")) {
    sendJson(res, 200, { status: "ok", service: "fairseal-mcp-server", transport: "streamable-http" });
    return;
  }

  if (url !== "/mcp" && url !== "/mcp/") {
    sendJson(res, 404, { jsonrpc: "2.0", error: { code: -32000, message: "Not found" }, id: null });
    return;
  }

  if (req.method !== "POST") {
    // Stateless mode: no GET (SSE resumption) / DELETE (session teardown)
    res.writeHead(405, { "content-type": "application/json", allow: "POST" });
    res.end(JSON.stringify({ jsonrpc: "2.0", error: { code: -32000, message: "Method not allowed" }, id: null }));
    return;
  }

  const ip = clientIp(req);
  if (rateLimited(ip)) {
    res.writeHead(429, { "content-type": "application/json", "retry-after": "60" });
    res.end(JSON.stringify({ jsonrpc: "2.0", error: { code: -32000, message: "Rate limit exceeded (per-IP). Retry in 60s." }, id: null }));
    return;
  }

  let parsedBody: unknown;
  try {
    const raw = await readBody(req);
    parsedBody = raw.length ? JSON.parse(raw) : undefined;
  } catch {
    sendJson(res, 400, { jsonrpc: "2.0", error: { code: -32700, message: "Parse error" }, id: null });
    return;
  }

  // Stateless: fresh server + transport per request, torn down on close.
  try {
    const server = buildServer();
    const transport = new StreamableHTTPServerTransport({
      sessionIdGenerator: undefined, // stateless
      enableJsonResponse: true,
    });
    res.on("close", () => {
      transport.close().catch(() => {});
      server.close().catch(() => {});
    });
    await server.connect(transport);
    await transport.handleRequest(req, res, parsedBody);
  } catch (err) {
    console.error("[fairseal-mcp-http] request error:", err);
    if (!res.headersSent) {
      sendJson(res, 500, { jsonrpc: "2.0", error: { code: -32603, message: "Internal server error" }, id: null });
    } else {
      res.end();
    }
  }
});

httpServer.listen(PORT, HOST, () => {
  console.log(`[fairseal-mcp-server] streamable-http listening on ${HOST}:${PORT} — upstream ${BASE_URL} — rate ${RATE_LIMIT}/min/ip`);
});
