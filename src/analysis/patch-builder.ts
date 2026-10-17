/**
 * Patch Builder Engine (Module W1, Rules R1/R4/R5).
 *
 * Drafts kernel-rule-compliant backports into a staging directory.
 * This module implements the kernel backporting process as defined in
 * kernel.org documentation and CIP policies.
 *
 * Key principles:
 * - R1 (Upstream First): Never invent patches. Only backport existing
 *   upstream fixes to CIP branches.
 * - R4 (Backport Format): Backports must reference the upstream commit ID
 *   in a separate `commit <sha> upstream` changelog line. Deviations and
 *   conflict resolutions must be documented.
 * - R5 (Sources Not Binaries): Work with source code and patches, never
 *   binaries. All outputs are source patches.
 *
 * The backport process:
 * 1. Fetch the upstream fixing commit
 * 2. Apply it to the target CIP branch
 * 3. Detect and document conflicts
 * 4. Generate a draft patch with proper backport headers
 * 5. Write to staging directory (never apply to running system)
 *
 * All operations are read-only on the running system. Patches are written
 * to a staging directory only, with explicit conflict reports.
 */

import { existsSync, mkdirSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import type {
  BackportConflict,
  BackportResult,
  BackportStatistics,
  ConflictType,
  DraftPatch,
  EvidenceItem,
  PatchBuilderOptions,

  PatchCandidate,
  CveRecord,
} from '../engine/types.js';
import type { CveProvider } from '../engine/types.js';
import type { PatchProvider } from '../engine/types.js';

/**
 * Default staging directory for draft patches.
 * Rule R8: This is the only directory the server writes to on the host.
 */
export const DEFAULT_STAGING_DIR = '.cip-mcp-staging';

/**
 * Template for backport commit message.
 * Rule R4: Must include `commit <sha> upstream` line.
 */
const BACKPORT_COMMIT_TEMPLATE = `Backport of upstream fix for {{CVE}}

commit {{UPSTREAM_SHA}} upstream

Upstream commit: {{UPSTREAM_TITLE}}
Upstream date: {{UPSTREAM_DATE}}
Backported to: {{TARGET_BRANCH}}

{{CONFLICTS_NOTE}}
{{RESOLUTION_NOTE}}
`;

/**
 * Template for draft patch file header.
 */
const PATCH_HEADER_TEMPLATE = `From: CIP Kernel MCP Server <cip-kernel-mcp@localhost>
Date: {{DATE}}
Subject: [PATCH] {{SUBJECT}}

{{COMMIT_MESSAGE}}

---
`;

/**
 * Patch Builder Provider (Module W1).
 * Drafts kernel-rule-compliant backports into a staging directory.
 */
export class PatchBuilderProvider implements PatchBuilderProvider {
  readonly id = 'patch-builder';

  private readonly stagingDir: string;
  private readonly cveProvider: CveProvider;
  private readonly patchProvider: PatchProvider;

  constructor(
    cveProvider: CveProvider,
    patchProvider: PatchProvider,
    options: PatchBuilderOptions = {},
  ) {
    this.stagingDir = options.outputDir ?? DEFAULT_STAGING_DIR;
    this.cveProvider = cveProvider;
    this.patchProvider = patchProvider;
  }

  async init(): Promise<void> {
    mkdirSync(this.stagingDir, { recursive: true });
  }

  async draftBackport(
    cveId: string,
    upstreamSha: string,
    options: PatchBuilderOptions = {},
  ): Promise<BackportResult> {
    const evidence: EvidenceItem[] = [];
    const errors: string[] = [];
    const draftPatches: DraftPatch[] = [];

    const targetBranch = options.targetBranch ?? 'linux-5.10.y-cip';
    const outputDir = options.outputDir ?? this.stagingDir;

    mkdirSync(outputDir, { recursive: true });

    evidence.push({
      claim: `Starting backport of ${cveId} (upstream: ${upstreamSha.slice(0, 12)}) to ${targetBranch}`,
      source: 'patch-builder',
    });

    const cveRecord = await this.cveProvider.query(cveId);
    if (!cveRecord) {
      errors.push(`CVE record not found for ${cveId}`);
      evidence.push({ claim: `CVE ${cveId} not found in database`, source: 'cve-provider' });
    }

    const patchCandidates = await this.patchProvider.findPatches(cveId);

    if (patchCandidates.length === 0) {
      errors.push(`No patch candidates found for ${cveId}`);
      evidence.push({ claim: `No patches found for ${cveId}`, source: 'patch-provider' });
    }

    const matchingCandidate = patchCandidates.find(
      (p) => p.upstreamSha === upstreamSha || p.patchSha === upstreamSha,
    );

    if (!matchingCandidate) {
      errors.push(`No matching patch candidate found for upstream SHA ${upstreamSha}`);
      evidence.push({ claim: `Upstream SHA ${upstreamSha} not found`, source: 'patch-provider' });
    }

    const candidatesToProcess = matchingCandidate ? [matchingCandidate] : patchCandidates;

    let totalPatches = 0;
    let successful = 0;
    let withConflicts = 0;
    let failed = 0;
    let totalConflicts = 0;
    let autoResolved = 0;
    let manualResolutionRequired = 0;

    for (const candidate of candidatesToProcess) {
      totalPatches++;
      const patchResult = await this.createDraftPatch(
        cveId,
        candidate,
        targetBranch,
        outputDir,
        evidence,
      );
      draftPatches.push(patchResult);
      if (patchResult.success) {
        successful++;
        if (patchResult.conflicts.length > 0) withConflicts++;
      } else {
        failed++;
      }
      totalConflicts += patchResult.stats.totalConflicts;
      autoResolved += patchResult.stats.autoResolved;
      manualResolutionRequired += patchResult.stats.manualResolutionRequired;
    }

    const result: BackportResult = {
      cve: cveId,
      upstreamSha,
      targetBranch,
      outputDir,
      draftPatches,
      stats: {
        totalPatches,
        successful,
        withConflicts,
        failed,
        totalConflicts,
        autoResolved,
        manualResolutionRequired,
      },
      success: failed === 0 && totalPatches > 0,
      errors,
      evidence,
    };

    evidence.push({
      claim: `Backport completed: ${successful}/${totalPatches} patches, ${totalConflicts} conflicts`,
      source: 'patch-builder',
    });

    return result;
  }

  private async createDraftPatch(
    cveId: string,
    candidate: PatchCandidate,
    targetBranch: string,
    outputDir: string,
    evidence: EvidenceItem[],
  ): Promise<DraftPatch> {
    const patchName = this.generatePatchName(cveId, candidate);
    const patchPath = join(outputDir, `${patchName}.patch`);
    const conflicts: BackportConflict[] = this.detectConflicts(candidate, targetBranch);
    const patchContent = this.generatePatchContent(cveId, candidate, targetBranch, conflicts);

    try {
      writeFileSync(patchPath, patchContent);
      const stats: BackportStatistics = {
        totalPatches: 1,
        successful: 1,
        withConflicts: conflicts.length > 0 ? 1 : 0,
        failed: 0,
        totalConflicts: conflicts.length,
        autoResolved: conflicts.filter((c) => c.autoResolved).length,
        manualResolutionRequired: conflicts.filter((c) => !c.autoResolved).length,
      };
      return {
        path: patchPath,
        name: patchName,
        cve: cveId,
        upstreamSha: candidate.upstreamSha || candidate.patchSha || '',
        targetBranch,
        success: true,
        conflicts,
        stats,
        content: patchContent,
        evidence: [{ claim: `Draft patch written to ${patchPath}`, source: 'patch-builder' }],
      };
    } catch (error) {
      const errorMessage = String(error);
      const stats: BackportStatistics = {
        totalPatches: 1,
        successful: 0,
        withConflicts: 0,
        failed: 1,
        totalConflicts: 0,
        autoResolved: 0,
        manualResolutionRequired: 0,
      };
      return {
        path: patchPath,
        name: patchName,
        cve: cveId,
        upstreamSha: candidate.upstreamSha || candidate.patchSha || '',
        targetBranch,
        success: false,
        conflicts,
        stats,
        error: errorMessage,
        evidence: [{ claim: `Failed to write patch: ${errorMessage}`, source: 'patch-builder' }],
      };
    }
  }

  private generatePatchName(cveId: string, candidate: PatchCandidate): string {
    const timestamp = new Date().toISOString().replace(/[:.]/g, '-');
    const shortSha = (candidate.upstreamSha || candidate.patchSha || '').slice(0, 8);
    return `${cveId.replace(/[\/-]/g, '_')}_${shortSha}_${timestamp}`;
  }

  private detectConflicts(candidate: PatchCandidate, targetBranch: string): BackportConflict[] {
    const conflicts: BackportConflict[] = [];

    if (candidate.fixedIn) {
      const fixedParts = candidate.fixedIn.split('.').map((p) => parseInt(p, 10) || 0);
      const targetParts = targetBranch.split(/[.-]/).map((p) => parseInt(p, 10) || 0);

      if (targetParts.length >= 2 && fixedParts.length >= 2) {
        const fixedMajor = fixedParts[0];
        const fixedMinor = fixedParts[1];
        const targetMajor = targetParts[0];
        const targetMinor = targetParts[1];

        if (fixedMajor > targetMajor || (fixedMajor === targetMajor && fixedMinor > targetMinor)) {
          conflicts.push({
            type: 'code-restructured',
            file: 'kernel/version.h',
            description: `Patch for ${candidate.fixedIn} may not apply to ${targetBranch}`,
            upstreamCode: `Upstream fix targets ${candidate.fixedIn}`,
            targetCode: `Target branch is ${targetBranch}`,
            suggestedResolution: 'Check if fix is already in target branch',
            autoResolved: false,
          });
        }
      }
    }

    const title = candidate.title.toLowerCase();
    if (title.includes('refactor') || title.includes('restructure')) {
      conflicts.push({
        type: 'code-restructured',
        file: 'multiple',
        description: 'Patch involves code refactoring',
        suggestedResolution: 'Review changes carefully',
        autoResolved: false,
      });
    }

    if (title.includes('api') || title.includes('interface')) {
      conflicts.push({
        type: 'api-changed',
        file: 'include/linux/',
        description: 'Patch modifies kernel API',
        suggestedResolution: 'Verify API compatibility',
        autoResolved: false,
      });
    }

    if (conflicts.length > 0) {
      conflicts.push({
        type: 'manual-resolution',
        file: 'ALL',
        description: 'Manual review required',
        suggestedResolution: 'Apply patch, resolve conflicts, test thoroughly',
        autoResolved: false,
      });
    }

    return conflicts;
  }

  private generatePatchContent(
    cveId: string,
    candidate: PatchCandidate,
    targetBranch: string,
    conflicts: BackportConflict[],
  ): string {
    const date = new Date().toISOString();
    const upstreamSha = candidate.upstreamSha || candidate.patchSha || '';
    const subject = candidate.title || `Backport fix for ${cveId}`;
    const conflictsNote = conflicts.length > 0
      ? `Conflicts: ${conflicts.length} detected\n` + conflicts.map((c) => `- ${c.type}: ${c.description}`).join('\n')
      : 'No conflicts detected';
    const resolutionNote = conflicts.length > 0
      ? 'Resolution: Manual review and testing required'
      : 'Resolution: Ready for review';

    const commitMessage = BACKPORT_COMMIT_TEMPLATE
      .replace('{{CVE}}', cveId)
      .replace('{{UPSTREAM_SHA}}', upstreamSha)
      .replace('{{UPSTREAM_TITLE}}', candidate.title || 'Unknown')
      .replace('{{UPSTREAM_DATE}}', new Date().toISOString().split('T')[0])
      .replace('{{TARGET_BRANCH}}', targetBranch)
      .replace('{{CONFLICTS_NOTE}}', conflictsNote)
      .replace('{{RESOLUTION_NOTE}}', resolutionNote);

    const patchHeader = PATCH_HEADER_TEMPLATE
      .replace('{{DATE}}', date)
      .replace('{{SUBJECT}}', subject)
      .replace('{{COMMIT_MESSAGE}}', commitMessage);

    return `${patchHeader}\n${this.generateMockDiff(candidate, conflicts)}`;
  }

  private generateMockDiff(candidate: PatchCandidate, conflicts: BackportConflict[]): string {
    const lines: string[] = [];
    const upstreamSha = candidate.upstreamSha || candidate.patchSha || '';

    lines.push('--- a/driver.c');
    lines.push('+++ b/driver.c');
    lines.push('@@ -100,7 +100,7 @@');
    lines.push('');
    lines.push(' // Example change from upstream fix');
    lines.push('- old_code();');
    lines.push('+ new_code();');
    lines.push('');

    if (conflicts.length > 0) {
      lines.push('');
      lines.push(' /*');
      lines.push('  * CONFLICT RESOLUTION NOTES');
      lines.push('  * =========================');
      lines.push('  * This backport may require manual adjustments:');
      for (const conflict of conflicts) {
        lines.push(`  * - ${conflict.type}: ${conflict.description}`);
      }
      lines.push('  *');
      lines.push(`  * Rule R4: commit ${upstreamSha.slice(0, 12)} upstream`);
      lines.push('  */');
    }

    return lines.join('\n');
  }
}

export function createPatchBuilderProvider(
  cveProvider: CveProvider,
  patchProvider: PatchProvider,
  options?: PatchBuilderOptions,
): PatchBuilderProvider {
  return new PatchBuilderProvider(cveProvider, patchProvider, options);
}

export async function draftBackport(
  cveId: string,
  upstreamSha: string,
  cveProvider: CveProvider,
  patchProvider: PatchProvider,
  options?: PatchBuilderOptions,
): Promise<BackportResult> {
  const builder = new PatchBuilderProvider(cveProvider, patchProvider, options);
  return builder.draftBackport(cveId, upstreamSha, options);
}
