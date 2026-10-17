import { describe, expect, it, beforeEach, afterEach } from 'vitest';
import { rmSync, existsSync, readFileSync } from 'node:fs';
import { join } from 'node:path';
import type { CveRecord, PatchCandidate } from '../src/engine/types.js';
import { PatchBuilderProvider, DEFAULT_STAGING_DIR } from '../src/analysis/patch-builder.js';

/**
 * Mock CVE provider
 */
class MockCveProvider {
  readonly id = 'mock-cve';
  private records: Map<string, CveRecord>;

  constructor(records: Map<string, CveRecord> = new Map()) {
    this.records = records;
  }

  async init(): Promise<void> {}

  async query(cveId: string): Promise<CveRecord | undefined> {
    return this.records.get(cveId);
  }

  addRecord(cveId: string, record: CveRecord): void {
    this.records.set(cveId, record);
  }
}

/**
 * Mock Patch provider
 */
class MockPatchProvider {
  readonly id = 'mock-patch';
  private patches: Map<string, PatchCandidate[]>;

  constructor(patches: Map<string, PatchCandidate[]> = new Map()) {
    this.patches = patches;
  }

  async init(): Promise<void> {}

  async findPatches(cveId: string): Promise<PatchCandidate[]> {
    return this.patches.get(cveId) || [];
  }

  addPatches(cveId: string, candidates: PatchCandidate[]): void {
    this.patches.set(cveId, candidates);
  }
}

/**
 * Create a test CVE record
 */
function createTestCveRecord(cveId: string = 'CVE-2024-9999'): CveRecord {
  return {
    id: cveId,
    description: 'Test CVE for patch builder',
    source: 'kernel.org-cve',
    affected: [{ file: 'net/netfilter/nf_tables_api.c' }],
    affectedRanges: [
      {
        series: '5.10',
        branch: 'linux-5.10.y',
        startIncluding: '5.10.157',
        fixedIn: '5.10.163',
      },
    ],
    fixingCommits: [
      { sha: 'a1b2c3d4e5f6789012345678901234567890abcd', branches: ['linux-5.10.y'] },
    ],
    fetchedAt: new Date().toISOString(),
  };
}

/**
 * Create a test patch candidate
 */
function createTestPatchCandidate(overrides: Partial<PatchCandidate> = {}): PatchCandidate {
  return {
    upstreamSha: 'a1b2c3d4e5f6789012345678901234567890abcd',
    patchSha: 'x1y2z3a4b5c6d7e8f901234567890abcdef',
    branch: 'linux-5.10.y-cip',
    title: 'netfilter: nf_tables: fix use-after-free',
    cve: 'CVE-2024-9999',
    fixedIn: '5.10.163',
    cipRelease: 'v5.10.163-cip35',
    url: 'https://git.kernel.org/pub/scm/linux/kernel/git/cip/linux-cip.git/commit/?id=x1y2z3...',
    source: 'cip-mirror',
    ...overrides,
  };
}

describe('PatchBuilderProvider', () => {
  let cveProvider: MockCveProvider;
  let patchProvider: MockPatchProvider;
  let builder: PatchBuilderProvider;
  let tempDir: string;

  beforeEach(() => {
    cveProvider = new MockCveProvider();
    patchProvider = new MockPatchProvider();
    tempDir = join(process.cwd(), 'test-staging');
    builder = new PatchBuilderProvider(cveProvider, patchProvider, { outputDir: tempDir });
  });

  afterEach(() => {
    // Clean up staging directory
    try {
      if (existsSync(tempDir)) {
        rmSync(tempDir, { recursive: true, force: true });
      }
      if (existsSync(DEFAULT_STAGING_DIR)) {
        rmSync(DEFAULT_STAGING_DIR, { recursive: true, force: true });
      }
    } catch {
      // Ignore cleanup errors
    }
  });

  describe('init', () => {
    it('should initialize without errors', async () => {
      await expect(builder.init()).resolves.toBeUndefined();
    });

    it('should create staging directory on init', async () => {
      await builder.init();
      expect(existsSync(tempDir)).toBe(true);
    });
  });

  describe('draftBackport', () => {
    const testCveId = 'CVE-2024-9999';
    const testUpstreamSha = 'a1b2c3d4e5f6789012345678901234567890abcd';

    beforeEach(() => {
      cveProvider.addRecord(testCveId, createTestCveRecord(testCveId));
      patchProvider.addPatches(testCveId, [createTestPatchCandidate()]);
    });

    it('should create a draft backport', async () => {
      const result = await builder.draftBackport(testCveId, testUpstreamSha);

      expect(result.cve).toBe(testCveId);
      expect(result.upstreamSha).toBe(testUpstreamSha);
      expect(result.targetBranch).toBe('linux-5.10.y-cip');
      expect(result.draftPatches.length).toBeGreaterThan(0);
      expect(result.success).toBe(true);
      expect(result.errors.length).toBe(0);
    });

    it('should create patch files in staging directory', async () => {
      const result = await builder.draftBackport(testCveId, testUpstreamSha);

      expect(result.draftPatches.length).toBeGreaterThan(0);
      
      for (const patch of result.draftPatches) {
        expect(existsSync(patch.path)).toBe(true);
        
        const content = readFileSync(patch.path, 'utf8');
        expect(content).toContain('Backport of upstream fix');
        expect(content).toContain(testCveId);
        expect(content).toContain(testUpstreamSha.slice(0, 12));
      }
    });

    it('should include proper backport headers with commit upstream line (Rule R4)', async () => {
      const result = await builder.draftBackport(testCveId, testUpstreamSha);
      const patch = result.draftPatches[0];
      const content = readFileSync(patch.path, 'utf8');

      // Check for Rule R4 compliance: commit <sha> upstream
      expect(content).toContain('commit ' + testUpstreamSha + ' upstream');
      expect(content).toContain('Subject:');
      expect(content).toContain('From:');
    });

    it('should detect conflicts for version mismatches', async () => {
      // Add a patch candidate with a newer fixedIn version
      patchProvider.addPatches(testCveId, [
        createTestPatchCandidate({ fixedIn: '6.1.100' }),
      ]);

      const result = await builder.draftBackport(testCveId, testUpstreamSha, {
        targetBranch: 'linux-5.10.y-cip',
      });

      expect(result.draftPatches.length).toBeGreaterThan(0);
      const patch = result.draftPatches[0];
      
      // Should have detected version conflict
      expect(patch.conflicts.length).toBeGreaterThan(0);
      expect(patch.conflicts.some((c) => c.type === 'code-restructured')).toBe(true);
    });

    it('should detect conflicts for refactoring patches', async () => {
      patchProvider.addPatches(testCveId, [
        createTestPatchCandidate({ title: 'netfilter: refactor packet processing' }),
      ]);

      const result = await builder.draftBackport(testCveId, testUpstreamSha);
      const patch = result.draftPatches[0];

      expect(patch.conflicts.length).toBeGreaterThan(0);
      expect(patch.conflicts.some((c) => c.type === 'code-restructured')).toBe(true);
    });

    it('should detect conflicts for API changes', async () => {
      patchProvider.addPatches(testCveId, [
        createTestPatchCandidate({ title: 'net: change socket API' }),
      ]);

      const result = await builder.draftBackport(testCveId, testUpstreamSha);
      const patch = result.draftPatches[0];

      expect(patch.conflicts.length).toBeGreaterThan(0);
      expect(patch.conflicts.some((c) => c.type === 'api-changed')).toBe(true);
    });

    it('should use custom output directory', async () => {
      const customDir = join(process.cwd(), 'custom-staging');
      const result = await builder.draftBackport(testCveId, testUpstreamSha, {
        outputDir: customDir,
      });

      expect(result.outputDir).toBe(customDir);
      expect(result.draftPatches[0].path).toContain(customDir);
      expect(existsSync(customDir)).toBe(true);
    });

    it('should use custom target branch', async () => {
      const result = await builder.draftBackport(testCveId, testUpstreamSha, {
        targetBranch: 'linux-5.10.y-cip-rt',
      });

      expect(result.targetBranch).toBe('linux-5.10.y-cip-rt');
      expect(result.draftPatches[0].targetBranch).toBe('linux-5.10.y-cip-rt');
    });

    it('should handle missing CVE record gracefully', async () => {
      // Don't add any CVE record or patches - should result in errors
      const result = await builder.draftBackport('CVE-NONEXISTENT', 'fake_sha');

      expect(result.errors.length).toBeGreaterThan(0);
      expect(result.errors.some((e) => e.includes('not found'))).toBe(true);
    });

    it('should handle missing patch candidates gracefully', async () => {
      // Add CVE record but no patches
      cveProvider.addRecord('CVE-NO-PATCHES', createTestCveRecord('CVE-NO-PATCHES'));
      // Don't add any patch candidates

      const result = await builder.draftBackport('CVE-NO-PATCHES', 'fake_sha');

      expect(result.errors.length).toBeGreaterThan(0);
      expect(result.errors.some((e) => e.includes('No patch candidates'))).toBe(true);
    });

    it('should handle non-matching upstream SHA gracefully', async () => {
      cveProvider.addRecord(testCveId, createTestCveRecord(testCveId));
      patchProvider.addPatches(testCveId, [
        createTestPatchCandidate({ upstreamSha: 'different_sha_1234567890' }),
      ]);

      const result = await builder.draftBackport(testCveId, testUpstreamSha);

      expect(result.errors.length).toBeGreaterThan(0);
      expect(result.errors.some((e) => e.includes('No matching patch candidate'))).toBe(true);
    });

    it('should include evidence chain in result', async () => {
      const result = await builder.draftBackport(testCveId, testUpstreamSha);

      expect(result.evidence.length).toBeGreaterThan(0);
      expect(result.evidence.some((e) => e.source === 'patch-builder')).toBe(true);
    });

    it('should include statistics in result', async () => {
      const result = await builder.draftBackport(testCveId, testUpstreamSha);

      expect(result.stats.totalPatches).toBeGreaterThan(0);
      expect(result.stats.successful).toBeGreaterThanOrEqual(0);
      expect(result.stats.failed).toBeGreaterThanOrEqual(0);
    });

    it('should create patch names with CVE and SHA', async () => {
      const result = await builder.draftBackport(testCveId, testUpstreamSha);
      const patch = result.draftPatches[0];

      expect(patch.name).toContain(testCveId.replace(/[\/-]/g, '_'));
      expect(patch.name).toContain(testUpstreamSha.slice(0, 8));
    });
  });

  describe('conflict detection', () => {
    it('should detect multiple types of conflicts', async () => {
      patchProvider.addPatches('CVE-2024-9999', [
        createTestPatchCandidate({
          title: 'refactor API and restructure code',
          fixedIn: '6.1.100',
        }),
      ]);

      const result = await builder.draftBackport('CVE-2024-9999', 'a1b2c3d4e5f6', {
        targetBranch: 'linux-5.10.y-cip',
      });

      const patch = result.draftPatches[0];
      expect(patch.conflicts.length).toBeGreaterThan(1);
      
      const conflictTypes = patch.conflicts.map((c) => c.type);
      expect(conflictTypes).toContain('code-restructured');
      expect(conflictTypes).toContain('api-changed');
    });

    it('should include suggested resolutions for conflicts', async () => {
      patchProvider.addPatches('CVE-2024-9999', [
        createTestPatchCandidate({ fixedIn: '6.1.100' }),
      ]);

      const result = await builder.draftBackport('CVE-2024-9999', 'a1b2c3d4e5f6', {
        targetBranch: 'linux-5.10.y-cip',
      });

      const patch = result.draftPatches[0];
      expect(patch.conflicts.length).toBeGreaterThan(0);
      
      for (const conflict of patch.conflicts) {
        expect(conflict.suggestedResolution).toBeDefined();
        expect(typeof conflict.suggestedResolution).toBe('string');
      }
    });

    it('should mark manual resolution as not auto-resolved', async () => {
      patchProvider.addPatches('CVE-2024-9999', [
        createTestPatchCandidate({ fixedIn: '6.1.100' }),
      ]);

      const result = await builder.draftBackport('CVE-2024-9999', 'a1b2c3d4e5f6', {
        targetBranch: 'linux-5.10.y-cip',
      });

      const patch = result.draftPatches[0];
      const manualConflicts = patch.conflicts.filter((c) => c.type === 'manual-resolution');
      expect(manualConflicts.length).toBeGreaterThan(0);
      
      for (const conflict of manualConflicts) {
        expect(conflict.autoResolved).toBe(false);
      }
    });
  });

  describe('Rule compliance', () => {
    const testCveId = 'CVE-2024-9999';
    const testUpstreamSha = 'a1b2c3d4e5f6789012345678901234567890abcd';

    beforeEach(() => {
      cveProvider.addRecord(testCveId, createTestCveRecord(testCveId));
      patchProvider.addPatches(testCveId, [createTestPatchCandidate()]);
    });

    it('should follow Rule R1: never invent patches', async () => {
      // Only backports existing upstream fixes
      cveProvider.addRecord(testCveId, createTestCveRecord(testCveId));
      patchProvider.addPatches(testCveId, [createTestPatchCandidate()]);

      const result = await builder.draftBackport(testCveId, testUpstreamSha);

      // Should only work with existing patches from providers
      expect(result.draftPatches.length).toBeGreaterThan(0);
      expect(result.draftPatches[0].upstreamSha).toBeDefined();
    });

    it('should follow Rule R4: include commit upstream line', async () => {
      cveProvider.addRecord(testCveId, createTestCveRecord(testCveId));
      patchProvider.addPatches(testCveId, [createTestPatchCandidate()]);

      const result = await builder.draftBackport(testCveId, testUpstreamSha);
      const patch = result.draftPatches[0];
      const content = readFileSync(patch.path, 'utf8');

      // Rule R4: Must include commit <sha> upstream
      expect(content).toContain('commit ' + testUpstreamSha + ' upstream');
    });

    it('should follow Rule R5: work with sources not binaries', async () => {
      cveProvider.addRecord(testCveId, createTestCveRecord(testCveId));
      patchProvider.addPatches(testCveId, [createTestPatchCandidate()]);

      const result = await builder.draftBackport(testCveId, testUpstreamSha);

      // Should create source patches, not binaries
      for (const patch of result.draftPatches) {
        expect(patch.path).toMatch(/\.patch$/);
        expect(patch.content).toBeDefined();
        expect(typeof patch.content).toBe('string');
        expect(patch.content).toContain('---');
        expect(patch.content).toContain('+++');
      }
    });
  });
});

describe('createPatchBuilderProvider', () => {
  it('should create a provider instance', () => {
    const cveProvider = new MockCveProvider();
    const patchProvider = new MockPatchProvider();
    const builder = new PatchBuilderProvider(cveProvider, patchProvider);

    expect(builder).toBeDefined();
    expect(builder.id).toBe('patch-builder');
  });
});

describe('draftBackport function', () => {
  it('should draft a backport directly', async () => {
    const cveProvider = new MockCveProvider();
    const patchProvider = new MockPatchProvider();
    const tempDir = join(process.cwd(), 'test-draft-staging');

    cveProvider.addRecord('CVE-2024-9999', createTestCveRecord());
    patchProvider.addPatches('CVE-2024-9999', [createTestPatchCandidate()]);

    const result = await import('../src/analysis/patch-builder.js');
    const draftResult = await result.draftBackport(
      'CVE-2024-9999',
      'a1b2c3d4e5f6789012345678901234567890abcd',
      cveProvider,
      patchProvider,
      { outputDir: tempDir },
    );

    expect(draftResult.cve).toBe('CVE-2024-9999');
    expect(draftResult.success).toBe(true);

    // Clean up
    try {
      if (existsSync(tempDir)) {
        rmSync(tempDir, { recursive: true, force: true });
      }
    } catch {
      // Ignore
    }
  });
});
