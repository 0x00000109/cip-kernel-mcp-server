import { execFile } from 'node:child_process';
import { existsSync, readFileSync } from 'node:fs';
import { join } from 'node:path';
import { promisify } from 'node:util';
import type { AffectedRange, CveProvider, CveRecord, FixingCommit } from '../engine/types.js';
import type { CacheManager } from '../engine/cache.js';

const execFileAsync = promisify(execFile);

const VULNS_URL = 'https://git.kernel.org/pub/scm/linux/security/vulns.git';
const KERNEL_ORG_COMMIT_RE = /git\.kernel\.org\/stable\/c\/([0-9a-f]{7,40})/;
const SERIES_RE = /linux_kernel:(\d+\.\d+)\.\*/;

interface KernelCveJson {
  cveMetadata?: { cveId?: string; state?: string };
  containers?: {
    cna?: {
      descriptions?: Array<{ lang: string; value: string }>;
      affected?: Array<{ programFiles?: string[] }>;
      cpeApplicability?: Array<{
        nodes?: Array<{
          cpeMatch?: Array<{
            criteria?: string;
            versionStartIncluding?: string;
            versionEndExcluding?: string;
          }>;
        }>;
      }>;
      references?: string[];
    };
  };
}

export type RunFn = (cmd: string, args: string[]) => Promise<void>;

export interface KernelCveOptions {
  vulnsDir?: string;
  run?: RunFn;
}

/**
 * kernel.org CVE records provider (Rules R1/R3, module P3).
 *
 * The kernel CVE team publishes commit-keyed CVE records in CVE JSON 5.0
 * format in the vulns.git repository on git.kernel.org (the same source the
 * Yocto Project consumes). The provider lazily clones/pulls that repository
 * via the git CLI and parses records into normalized CveRecords:
 *  - affected files from cna.affected[].programFiles;
 *  - affected version ranges per stable series from cna.cpeApplicability;
 *  - fixing commits from git.kernel.org/stable/c/<sha> references.
 *
 * Parsed records are cached (module E4); note that "record not found" is also
 * cached until TTL expiry, so brand-new CVEs may need a cache refresh.
 */
export class KernelCveProvider implements CveProvider {
  readonly id = 'kernel-cve';

  private readonly vulnsDir: string;
  private readonly run: RunFn;

  constructor(private readonly cache: CacheManager, opts: KernelCveOptions = {}) {
    this.vulnsDir =
      opts.vulnsDir ?? process.env.CIP_MCP_VULNS_DIR ?? join(process.cwd(), '.cip-mcp-cache', 'vulns');
    this.run = opts.run ?? (async (cmd, args) => void (await execFileAsync(cmd, args)));
  }

  async init(): Promise<void> {
    // Fail fast (and get skipped by the CveService) if git is unavailable.
    await this.run('git', ['--version']);
  }

  async query(cveId: string): Promise<CveRecord | undefined> {
    const entry = await this.cache.wrap('kernel-cve', cveId, () => this.fetch(cveId));
    return entry.value;
  }

  private async fetch(cveId: string): Promise<CveRecord | undefined> {
    await this.ensureRepo();
    const file = this.findFile(cveId);
    if (!file) return undefined;
    const raw = JSON.parse(readFileSync(file, 'utf8'));
    return parseKernelCveRecord(raw, new Date().toISOString());
  }

  private async ensureRepo(): Promise<void> {
    if (existsSync(join(this.vulnsDir, '.git'))) {
      // Best-effort refresh; on failure (e.g. air-gapped host) keep the
      // existing checkout — the cache stamp reports freshness (R2).
      try {
        await this.run('git', ['-C', this.vulnsDir, 'fetch', '--all', '--quiet']);
      } catch {
        /* offline: use existing checkout */
      }
      return;
    }
    await this.run('git', ['clone', '--filter=blob:none', '--quiet', VULNS_URL, this.vulnsDir]);
  }

  private findFile(cveId: string): string | undefined {
    const year = /CVE-(\d{4})-/.exec(cveId)?.[1];
    const candidates = [
      year ? join(this.vulnsDir, year, `${cveId}.json`) : null,
      join(this.vulnsDir, `${cveId}.json`),
    ];
    return candidates.find((p): p is string => p !== null && existsSync(p));
  }
}

/**
 * Pure parser: kernel.org CVE JSON 5.0 record -> CveRecord.
 * Returns undefined for rejected records or records without a cve id.
 */
export function parseKernelCveRecord(json: unknown, fetchedAt: string): CveRecord | undefined {
  const root = json as KernelCveJson | undefined;
  const cna = root?.containers?.cna;
  const id = root?.cveMetadata?.cveId;
  if (!id || !cna) return undefined;
  if (root?.cveMetadata?.state === 'REJECTED') return undefined;

  const description =
    cna.descriptions?.find((d) => d.lang === 'en')?.value ?? cna.descriptions?.[0]?.value ?? '';

  const affected = (cna.affected ?? []).flatMap((a) => a.programFiles ?? []).map((file) => ({ file }));

  const affectedRanges: AffectedRange[] = [];
  for (const block of cna.cpeApplicability ?? []) {
    for (const node of block.nodes ?? []) {
      for (const match of node.cpeMatch ?? []) {
        const series = SERIES_RE.exec(match.criteria ?? '')?.[1];
        if (!series) continue;
        affectedRanges.push({
          series,
          branch: `linux-${series}.y`,
          startIncluding: match.versionStartIncluding,
          fixedIn: match.versionEndExcluding,
        });
      }
    }
  }

  const fixingCommits: FixingCommit[] = [];
  const seen = new Set<string>();
  for (const ref of cna.references ?? []) {
    const sha = KERNEL_ORG_COMMIT_RE.exec(ref)?.[1];
    if (sha && !seen.has(sha)) {
      seen.add(sha);
      fixingCommits.push({ sha, branches: [] });
    }
  }

  return { id, description, source: 'kernel.org-cve', affected, affectedRanges, fixingCommits, fetchedAt };
}
