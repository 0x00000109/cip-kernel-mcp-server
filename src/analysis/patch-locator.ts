import type { PatchCandidate, PatchProvider } from '../engine/types.js';

/**
 * Patch locator (Rules R1/R4, module A2).
 * Locates existing fixing commits along the provenance chain:
 * mainline -> stable -> CIP branches. The server never invents patches (R1).
 */
export class PatchLocator {
  constructor(private readonly git: PatchProvider) {}

  async findPatches(cveId: string): Promise<PatchCandidate[]> {
    return dedupe(await this.git.findPatches(cveId));
  }
}

function dedupe(patches: PatchCandidate[]): PatchCandidate[] {
  const seen = new Set<string>();
  return patches.filter((p) => {
    // A resolved backport commit is authoritative even when its upstream
    // sha is unknown, so key on the patch sha first.
    const key = `${p.patchSha ?? p.upstreamSha ?? ''}@${p.branch}`;
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  });
}
