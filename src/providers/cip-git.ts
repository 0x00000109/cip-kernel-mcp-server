import type { CveRecord, PatchCandidate, PatchProvider } from '../engine/types.js';

/**
 * CIP git provider (Rules R1/R2/R4, module P2).
 * P0 scope: structured per-series patch candidates from CVE records, plus a
 * passthrough for records without ranges.
 * TODO(P1): live mirror queries against
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

    // Prefer structured per-series ranges from the kernel.org record (R3).
    if ((record.affectedRanges?.length ?? 0) > 0) {
      const shas = record.fixingCommits.map((f) => f.sha);
      // Heuristic: when the fixing-commit count matches the range count,
      // pair them by order (the kernel.org record lists both in the same
      // series order). TODO(P1): pair via mirror queries instead.
      const paired = shas.length === (record.affectedRanges?.length ?? 0);
      return (record.affectedRanges ?? []).map((range, i) => ({
        upstreamSha: paired ? shas[i] : undefined,
        branch: range.branch,
        title:
          `Fix for ${record.id}` +
          (range.fixedIn ? ` (fixed in ${range.fixedIn})` : ' (no fix released yet)'),
        cve: record.id,
        fixedIn: range.fixedIn,
      }));
    }

    // Fallback: passthrough for records without range data.
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
