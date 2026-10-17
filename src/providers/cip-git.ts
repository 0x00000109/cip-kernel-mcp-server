import type { CveRecord, PatchCandidate, PatchProvider } from '../engine/types.js';

/**
 * CIP git provider (Rules R1/R2/R4, module P2).
 * P0 scope: interface + branch catalogue + passthrough from CVE records.
 * TODO(P0+): live mirror queries against
 * https://git.kernel.org/pub/scm/linux/kernel/git/cip/linux-cip.git/ —
 * resolve Fixes: tags, `commit <sha> upstream` backport lines, and
 * linux-5.10.y-cip-rt (Rule R4). Mirrors are pinned and cached (modules E3/E4).
 */
export class CipGitProvider implements PatchProvider {
  readonly id = 'cip-git';

  /** CIP SLTS branches relevant to 5.10.x deployments. */
  static readonly BRANCHES = ['linux-5.10.y-cip', 'linux-5.10.y-cip-rt'] as const;

  constructor(
    private readonly loadCve: (cveId: string) => Promise<CveRecord | undefined>,
  ) {}

  async init(): Promise<void> {}

  async findPatches(cveId: string): Promise<PatchCandidate[]> {
    const record = await this.loadCve(cveId);
    if (!record) return [];
    return record.fixingCommits.flatMap((fix) =>
      fix.branches.map((branch) => ({
        upstreamSha: fix.sha,
        branch,
        title: fix.description ?? `Fix for ${record.id}`,
        cve: record.id,
      })),
    );
  }
}
