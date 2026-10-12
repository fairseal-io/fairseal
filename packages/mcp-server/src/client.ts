/**
 * FairSeal API HTTP client (thin wrapper).
 *
 * Auth (since API 2026-08-18 key gate): most endpoints are free, but
 * /api/v1/entropy, /api/v1/stats and /api/v1/rng/generate require a real
 * FAIRSEAL_API_KEY. Without one we send "Bearer anonymous" and the upstream
 * returns 401 for gated endpoints (relay adds an MCP-actionable hint).
 */

import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";

function readPkgVersion(): string {
  try {
    const pkgPath = join(dirname(fileURLToPath(import.meta.url)), "..", "package.json");
    const pkg = JSON.parse(readFileSync(pkgPath, "utf8")) as { version?: string };
    return pkg.version ?? "0.0.0";
  } catch {
    return "0.0.0";
  }
}

export const VERSION = readPkgVersion();

export const BASE_URL = process.env.FAIRSEAL_API_URL ?? "https://api.fairseal.io";
/** x402 host — anchor API v2 lives here (Bearer key bypasses the payment gate up to quota). */
export const X402_URL = process.env.FAIRSEAL_X402_URL ?? "https://x402.fairseal.io";
const API_KEY = process.env.FAIRSEAL_API_KEY ?? "anonymous";
/** Service-specific key overrides; both fall back to FAIRSEAL_API_KEY. */
export const NOTARY_API_KEY =
  process.env.FAIRSEAL_NOTARY_API_KEY ?? process.env.FAIRSEAL_API_KEY ?? null;
export const ANCHOR_API_KEY =
  process.env.FAIRSEAL_ANCHOR_API_KEY ?? process.env.FAIRSEAL_API_KEY ?? null;
const TIMEOUT_MS = Number(process.env.FAIRSEAL_TIMEOUT_MS ?? 15000);

export interface ApiResult {
  ok: boolean;
  status: number;
  body: unknown;
}

async function request(
  method: "GET" | "POST",
  path: string,
  body?: unknown,
  opts?: { baseUrl?: string; key?: string | null },
): Promise<ApiResult> {
  const ctrl = new AbortController();
  const timer = setTimeout(() => ctrl.abort(), TIMEOUT_MS);
  try {
    const headers: Record<string, string> = {
      "content-type": "application/json",
      "user-agent": `fairseal-mcp-server/${VERSION}`,
    };
    const key = opts && "key" in opts ? opts.key : API_KEY;
    if (key) headers.authorization = `Bearer ${key}`;
    const res = await fetch(`${opts?.baseUrl ?? BASE_URL}${path}`, {
      method,
      headers,
      body: body === undefined ? undefined : JSON.stringify(body),
      signal: ctrl.signal,
    });
    let parsed: unknown;
    const text = await res.text();
    try {
      parsed = JSON.parse(text);
    } catch {
      parsed = text;
    }
    return { ok: res.ok || res.status === 202, status: res.status, body: parsed };
  } finally {
    clearTimeout(timer);
  }
}

export const apiGet = (path: string) => request("GET", path);
export const apiPost = (path: string, body?: unknown) => request("POST", path, body);

/** Request against an arbitrary FairSeal host with an explicit (or no) Bearer key. */
export const apiRequestTo = (
  baseUrl: string,
  method: "GET" | "POST",
  path: string,
  body?: unknown,
  key?: string | null,
) => request(method, path, body, { baseUrl, key: key ?? null });
