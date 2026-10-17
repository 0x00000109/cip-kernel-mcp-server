#!/usr/bin/env node
import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import { AuditLog } from './engine/audit.js';
import { CacheManager } from './engine/cache.js';
import { CveFeedProvider } from './providers/cve-feeds.js';
import { SystemInventoryProvider } from './providers/system-inventory.js';
import { registerTools } from './tools/register.js';

const CACHE_DIR = process.env.CIP_MCP_CACHE_DIR ?? '.cip-mcp-cache';
const AUDIT_LOG_PATH = process.env.CIP_MCP_AUDIT_LOG ?? '.cip-mcp-audit.log';

async function main(): Promise<void> {
  const audit = new AuditLog(AUDIT_LOG_PATH);
  const cache = new CacheManager(CACHE_DIR);
  const inventory = new SystemInventoryProvider();
  const cveFeed = new CveFeedProvider(cache);

  const server = new McpServer(
    { name: 'cip-kernel-mcp-server', version: '0.1.0' },
    {
      instructions:
        'CIP Kernel MCP Server — dependency and security-patch intelligence for ' +
        'CIP SLTS kernels (5.10.x). Read-only by default; verdicts always carry ' +
        'an evidence chain. See docs/ARCHITECTURE.md and docs/THREAT-MODEL.md.',
    },
  );

  registerTools(server, { audit, inventory, cveFeed });

  const transport = new StdioServerTransport();
  await server.connect(transport);
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
