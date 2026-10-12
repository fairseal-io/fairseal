#!/usr/bin/env node
/**
 * FairSeal MCP Server — @fairseal/mcp-server
 * stdio entrypoint (no network listener).
 *
 * Wraps the live FairSeal Verifiable Entropy API (api.fairseal.io v0.2.0)
 * plus a local preview stub of the future Anchor API v2.
 */

import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { buildServer } from "./build-server.js";
import { BASE_URL } from "./client.js";

const server = buildServer();
const transport = new StdioServerTransport();
await server.connect(transport);
console.error(`[fairseal-mcp-server] ready on stdio — upstream ${BASE_URL}`);
