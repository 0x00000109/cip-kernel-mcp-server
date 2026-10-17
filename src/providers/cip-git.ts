import { execFile } from 'node:child_process';
import { existsSync, mkdirSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { promisify } from 'node:util';
import type { CveRecord, PatchCandidate, PatchProvider } from '../engine/types.js';
import type { CacheManager } from '../engine/cache.js';

const execFileAsync = promisify(execFile);

/**
 * Canonical CIP kernel repository on git.kernel.org: stable SLTS branches
 * (linux-5.10.y-cip, linux-5.10.y-cip-rt) and the vX.Y.Z-cipNN releases.
 */
export const CIP_MIRROR_URL =
  'https://git.kernel.org/pub/scm/linux/kernel/git/cip/linux-cip.git';

/** git log record/field separators (control chars never appear in messages). */
const FIELD_SEP = '\x1f';
const RECORD_SEP = '\x1e';

export type RunFn = (cmd: string, args: string[]) => Promise<string>;

export interface CipGitOptions {
  /** Git runner (returns stdout); defaults to the real git CLI. */
  run?: RunFn;
  mirrorUrl?: string;
  mirrorDir?: string;
  /** CIP SLTS branches to search. */
  branches?: string[];
  /** Cache manager used to TTL-throttle mirror syncs (module E4). */
  cache?: CacheManager;
}

/** One commit on a CIP branch, as returned by parseGitLog. */
export interface MirrorCommit {
  sha: string;
  subject: string;
  authoredAt: string;
  message: string;
}

/**
 * CIP git provider (Rules R1/R2/R4, module P2).
 *
 * Resolves fixes along the provenance chain mainline -> stable -> CIP.
 * The kernel.org CVE record gives the upstream/stable fixing commits; this
 * provider queries the linux-cip mirror for the corresponding CIP backports.
 * CIP backports reference the upstream commit in their message via the
 * `commit <sha> upstream.` backport line or a `Fixes: <sha>` tag (Rule R4),
 * so a fixed-string grep for the full upstream sha finds them.
 *
 * The mirror is cloned once, metadata-only (`--filter=blob:none`,
 * `--no-checkout` — commit graph and messages, no blobs, no worktree) and
 * refreshed at most once per cache TTL (module E4). When the mirror is
 * unavailable (no git CLI, air-gapped host, clone failure) the provider
 * degrades to record-derived candidates only — the server never invents
 * patches (Rule R1).
 */
export class CipGitProvider implements PatchProvider {
  readonly id = 'cip-git';

  /** CIP SLTS branches relevant to 5.10.x deployments. */
  static readonly BRANCHES = ['linux-5.10.y-cip', 'linux-5.10.y-cip-rt'] as const;

  private readonly run: RunFn;
  private readonly mirrorUrl: string;
  private readonly mirrorDir: string;
  private readonly branches: string[];
  private readonly cache?: CacheManager;

  constructor(
    private readonly loadCve: (cveId: string) => Promise<CveRecord | undefined>,
    opts: CipGitOptions = {},
  ) {
    this.run =
      opts.run ??
      (async (cmd, args) =>
        (await execFileAsync(cmd, args, { maxBuffer: 32 * 1024 * 1024 })).stdout);
    this.mirrorUrl = opts.mirrorUrl ?? process.env.CIP_MCP_MIRROR_URL ?? CIP_MIRROR_URL;
    this.mirrorDir = opts.mirrorDir ?? join(process.cwd(), '.cip-mcp-cache', 'linux-cip');
    this.branches = opts.branches ?? [...CipGitProvider.BRANCHES];
    this.cache = opts.cache;
  }

  async init(): Promise<void> {}

  async findPatches(cveId: string): Promise<PatchCandidate[]> {
    const record = await this.loadCve(cveId);
    if (!record) return [];

    // Record-derived candidates (per stable series) always come back; the
    // mirror adds the CIP-branch view on top.
    const recordPatches = recordCandidates(record);

    // Mirror queries are only meaningful when the record points at fixing
    // commits and one of our SLTS series is affected (R2 scope).
    const upstreamShas = record.fixingCommits.map((f) => f.sha);
    if (upstreamShas.length === 0 || !this.affectsCipSeries(record)) {
      return recordPatches;
    }

    try {
      await this.syncMirror();
    } catch {
      // Mirror unreachable and no local clone: degrade to record candidates.
      if (!existsSync(join(this.mirrorDir, '.git'))) return recordPatches;
    }

    const mirrorPatches: PatchCandidate[] = [];
    for (const branch of this.branches) {
      const commits = await this.findBackports(branch, upstreamShas);
      if (commits.length === 0) {
        // Explicit negative signal for the admin: the mirror was consulted
        // and no backport exists on this branch yet (fix may be pending).
        mirrorPatches.push({
          branch,
          title: `No backport of ${record.id} found on ${branch} (fix may be pending)`,
          cve: record.id,
          source: 'cip-mirror',
        });
        continue;
      }
      for (const commit of commits) {
        const upstreamSha = upstreamShas.find((s) => commit.message.includes(s));
        mirrorPatches.push({
          upstreamSha,
          patchSha: commit.sha,
          branch,
          title: commit.subject,
          cve: record.id,
          fixedIn: stableFixedIn(record, upstreamSha),
          cipRelease: await this.firstReleaseContaining(commit.sha),
          url: `${this.mirrorUrl}/commit/?id=${commit.sha}`,
          source: 'cip-mirror',
        });
      }
    }
    return [...mirrorPatches, ...recordPatches];
  }

  /** True when one of the affected stable series has a matching CIP branch. */
  private affectsCipSeries(record: CveRecord): boolean {
    const ranges = record.affectedRanges ?? [];
    if (ranges.length === 0) return true; // unknown scope — still query
    return ranges.some((r) => this.branches.some((b) => b.startsWith(`linux-${r.series}.y`)));
  }

  /** Clone (once) or refresh (best-effort) the mirror, TTL-throttled via E4. */
  private async syncMirror(): Promise<void> {
    const sync = async (): Promise<{ syncedAt: string }> => {
      await this.ensureMirror();
      return { syncedAt: new Date().toISOString() };
    };
    if (this.cache) {
      await this.cache.wrap('cip-git-mirror', 'sync', sync);
    } else {
      await sync();
    }
  }

  private async ensureMirror(): Promise<void> {
    if (existsSync(join(this.mirrorDir, '.git'))) {
      // Best-effort refresh; on failure (air-gapped host) keep the existing
      // refs — answers still carry freshness via the cache stamp (R2).
      try {
        await this.run('git', ['-C', this.mirrorDir, 'fetch', '--quiet', 'origin']);
      } catch {
        /* offline: keep existing refs */
      }
      return;
    }
    // Metadata-only clone: commit graph + messages, no blobs, no worktree.
    mkdirSync(dirname(this.mirrorDir), { recursive: true });
    await this.run('git', [
      'clone',
      '--filter=blob:none',
      '--no-checkout',
      '--quiet',
      this.mirrorUrl,
      this.mirrorDir,
    ]);
  }

  /**
   * Search one CIP branch for backports of the given upstream fixing
   * commits. Multiple --grep patterns are OR-ed; `-F` matches fixed strings,
   * so the full 40-char upstream sha cannot collide with other messages.
   */
  private async findBackports(branch: string, upstreamShas: string[]): Promise<MirrorCommit[]> {
    const format = `%H${FIELD_SEP}%s${FIELD_SEP}%aD${FIELD_SEP}%b${RECORD_SEP}`;
    const args = ['-C', this.mirrorDir, 'log', '-F', `--format=${format}`, '-n', '20'];
    for (const sha of upstreamShas) args.push('--grep', sha);
    args.push(`origin/${branch}`);
    return parseGitLog(await this.run('git', args));
  }

  /**
   * First tagged CIP release containing the backport, e.g. 'v5.10.163-cip35'.
   * `git describe --contains` yields the nearest tag after the commit
   * ('v5.10.163-cip35~7'); commits not yet in any release yield undefined.
   */
  private async firstReleaseContaining(sha: string): Promise<string | undefined> {
    try {
      const out = (
        await this.run('git', ['-C', this.mirrorDir, 'describe', '--tags', '--contains', sha])
      ).trim();
      return out.split(/[~^]/)[0] || undefined;
    } catch {
      return undefined; // not yet part of any tagged CIP release
    }
  }
}

/** Parse git log output with \x1e record and \x1f field separators. */
export function parseGitLog(out: string): MirrorCommit[] {
  const commits: MirrorCommit[] = [];
  for (const raw of out.split(RECORD_SEP)) {
    const record = raw.trim();
    if (!record) continue;
    const [sha, subject, authoredAt, ...body] = record.split(FIELD_SEP);
    if (!sha || !subject) continue;
    commits.push({
      sha,
      subject,
      authoredAt: authoredAt ?? '',
      message: body.join(FIELD_SEP),
    });
  }
  return commits;
}

/**
 * Record-derived candidates (kernel.org CVE record only, no mirror).
 * When the fixing-commit count matches the range count, they are paired in
 * series order — the kernel.org record lists both in the same order.
 */
export function recordCandidates(record: CveRecord): PatchCandidate[] {
  const ranges = record.affectedRanges ?? [];
  if (ranges.length > 0) {
    const shas = record.fixingCommits.map((f) => f.sha);
    const paired = shas.length === ranges.length;
    return ranges.map((range, i) => ({
      upstreamSha: paired ? shas[i] : undefined,
      branch: range.branch,
      title:
        `Fix for ${record.id}` +
        (range.fixedIn ? ` (fixed in ${range.fixedIn})` : ' (no fix released yet)'),
      cve: record.id,
      fixedIn: range.fixedIn,
      source: 'cve-record' as const,
    }));
  }

  // Passthrough for records without range data.
  return record.fixingCommits.flatMap((fix) =>
    fix.branches.map((branch) => ({
      upstreamSha: fix.sha,
      branch,
      title: fix.description ?? `Fix for ${record.id}`,
      cve: record.id,
      source: 'cve-record' as const,
    })),
  );
}

/** Stable release fixing the same series, via the record's sha/range pairing. */
function stableFixedIn(record: CveRecord, upstreamSha?: string): string | undefined {
  if (!upstreamSha) return undefined;
  const shas = record.fixingCommits.map((f) => f.sha);
  const ranges = record.affectedRanges ?? [];
  if (shas.length === ranges.length) {
    const idx = shas.indexOf(upstreamSha);
    if (idx >= 0) return ranges[idx].fixedIn;
  }
  return undefined;
}
