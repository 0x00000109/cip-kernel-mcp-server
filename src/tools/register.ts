import { z } from 'zod';
import type { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import type { AuditLog } from '../engine/audit.js';
import type { CveProvider } from '../engine/types.js';
import type { CacheManager } from '../engine/cache.js';
import type { SystemInventoryProvider } from '../providers/system-inventory.js';
import { CipGitProvider } from '../providers/cip-git.js';
import { PatchLocator } from '../analysis/patch-locator.js';
import { assessApplicability } from '../analysis/cve-applicability.js';

export interface ToolDeps {
  audit: AuditLog;
  inventory: SystemInventoryProvider;
  /** CVE provider chain — kernel.org first, NVD fallback (Rule R1). */
  cveFeed: CveProvider;
  /** Offline-first cache (module E4) — also throttles mirror syncs. */
  cache: CacheManager;
  /** linux-cip mirror location (default `<cache>/linux-cip`). */
  mirrorDir?: string;
}

/**
 * MCP tool wiring (thin adapters, per ARCHITECTURE.md Layer 3).
 * Every handler goes through the audit trail (R8) and every answer that
 * depends on remote data carries its freshness (R2).
 */
export function registerTools(server: McpServer, deps: ToolDeps): void {
  const patchProvider = new CipGitProvider((cveId) => deps.cveFeed.query(cveId), {
    cache: deps.cache,
    mirrorDir: deps.mirrorDir,
  });
  const patchLocator = new PatchLocator(patchProvider);

  server.registerTool(
    'scan_system',
    {
      title: 'Scan system inventory',
      description:
        'Collect a read-only kernel inventory: version, config, loaded modules, distro. Read-only, least privilege (R2/R3).',
      inputSchema: {},
    },
    async () => {
      try {
        const result = await deps.inventory.collect();
        deps.audit.record('scan_system', {}, result);
        return json(result);
      } catch (e) {
        deps.audit.record('scan_system', {}, undefined, String(e));
        throw e;
      }
    },
  );

  server.registerTool(
    'query_cve',
    {
      title: 'Query CVE record',
      description:
        'Look up a CVE by id (kernel.org cve records first, NVD fallback). Returns a normalized record with affected files, version ranges, and fixing commits (R1/R3).',
      inputSchema: {
        cveId: z
          .string()
          .regex(/^CVE-\d{4}-\d{4,}$/i, 'Expected a CVE id like CVE-2024-1234'),
      },
    },
    async ({ cveId }) => {
      try {
        const result = await deps.cveFeed.query(cveId);
        deps.audit.record('query_cve', { cveId }, result);
        if (!result) {
          return jsonError(`No record found for ${cveId}.`);
        }
        return json(result);
      } catch (e) {
        deps.audit.record('query_cve', { cveId }, undefined, String(e));
        throw e;
      }
    },
  );

  server.registerTool(
    'find_patches',
    {
      title: 'Find patches for a CVE',
      description:
        'Locate existing fixes along the provenance chain: mainline -> stable -> CIP branches. Live linux-cip mirror queries resolve the CIP backports (backport commit, first tagged CIP release, e.g. v5.10.163-cip35); degrades to record-derived candidates when the mirror is unavailable (R1/R2/R4).',
      inputSchema: {
        cveId: z
          .string()
          .regex(/^CVE-\d{4}-\d{4,}$/i, 'Expected a CVE id like CVE-2024-1234'),
      },
    },
    async ({ cveId }) => {
      try {
        const result = await patchLocator.findPatches(cveId);
        deps.audit.record('find_patches', { cveId }, result);
        return json(result);
      } catch (e) {
        deps.audit.record('find_patches', { cveId }, undefined, String(e));
        throw e;
      }
    },
  );

  server.registerTool(
    'cve_applicability',
    {
      title: 'Assess CVE applicability',
      description:
        'Cross-reference a CVE against this system version + config + modules. Two gates: version range (fix already present / not introduced) and config mapping. Verdict always carries an evidence chain (R3).',
      inputSchema: {
        cveId: z
          .string()
          .regex(/^CVE-\d{4}-\d{4,}$/i, 'Expected a CVE id like CVE-2024-1234'),
      },
    },
    async ({ cveId }) => {
      try {
        const inventory = await deps.inventory.collect();
        const record = await deps.cveFeed.query(cveId);
        const result = record
          ? assessApplicability(record, inventory)
          : {
              cve: cveId,
              verdict: 'unknown' as const,
              confidence: 'low' as const,
              evidence: [],
              rationale: `No record found for ${cveId}.`,
            };
        deps.audit.record('cve_applicability', { cveId }, result);
        return json(result);
      } catch (e) {
        deps.audit.record('cve_applicability', { cveId }, undefined, String(e));
        throw e;
      }
    },
  );
}

function json(value: unknown) {
  return { content: [{ type: 'text' as const, text: JSON.stringify(value, null, 2) }] };
}

function jsonError(message: string) {
  return { content: [{ type: 'text' as const, text: message }], isError: true };
}
