#!/usr/bin/env node
import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import { AuditLog } from './engine/audit.js';
import { CacheManager } from './engine/cache.js';
import { KernelCveProvider } from './providers/kernel-cve.js';
import { CveService } from './providers/cve-service.js';
import { CveFeedProvider } from './providers/cve-feeds.js';
import { SystemInventoryProvider } from './providers/system-inventory.js';
import { registerTools } from './tools/register.js';

const CACHE_DIR = process.env.CIP_MCP_CACHE_DIR ?? '.cip-mcp-cache';
const AUDIT_LOG_PATH = process.env.CIP_MCP_AUDIT_LOG ?? '.cip-mcp-audit.log';

async function main(): Promise<void> {
  const audit = new AuditLog(AUDIT_LOG_PATH);
  const cache = new CacheManager(CACHE_DIR);
  const inventory = new SystemInventoryProvider();

  // CVE chain: kernel.org cve records first (commit-keyed, Rule R3), NVD as
  // fallback. A provider that is unavailable (e.g. no git CLI, air-gapped
  // host) is skipped with a warning — see CveService.
  const kernelCve = new KernelCveProvider(cache, {
    vulnsDir: process.env.CIP_MCP_VULNS_DIR,
  });
  const nvd = new CveFeedProvider(cache);
  const cveFeed = new CveService([kernelCve, nvd], (providerId, message) => {
    console.error(`[cve] provider ${providerId} unavailable: ${message}`);
  });
  await cveFeed.init();

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
