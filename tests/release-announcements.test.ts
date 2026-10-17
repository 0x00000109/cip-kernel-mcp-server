import { describe, expect, it, beforeEach, afterEach } from 'vitest';
import { rmSync, mkdirSync, existsSync } from 'node:fs';
import { join } from 'node:path';
import { CacheManager } from '../src/engine/cache.js';
import { ReleaseAnnouncementsProvider } from '../src/providers/release-announcements.js';
import type { CipRelease, ReleaseQueryResult } from '../src/engine/types.js';

/**
 * Test helper to create a temporary cache directory
 */
function createTempCacheDir(): string {
  const tempDir = join(process.cwd(), '.test-cache', `release-announcements-${Date.now()}`);
  mkdirSync(tempDir, { recursive: true });
  return tempDir;
}

/**
 * Test helper to clean up a temporary directory
 */
function cleanupTempDir(tempDir: string): void {
  if (existsSync(tempDir)) {
    rmSync(tempDir, { recursive: true, force: true });
  }
}

describe('ReleaseAnnouncementsProvider (Module P4, Rules R1/R3)', () => {
  let provider: ReleaseAnnouncementsProvider;
  let cacheDir: string;
  let cache: CacheManager;

  beforeEach(() => {
    cacheDir = createTempCacheDir();
    cache = new CacheManager(cacheDir, 1000);
    provider = new ReleaseAnnouncementsProvider(cache);
  });

  afterEach(() => {
    cleanupTempDir(cacheDir);
  });

  describe('init()', () => {
    it('should initialize without errors', async () => {
      await expect(provider.init()).resolves.not.toThrow();
    });

    it('should load seed data when offline', async () => {
      await provider.init();
      const result = await provider.queryReleases();
      expect(result.releases.length).toBeGreaterThan(0);
      expect(result.cipCount).toBeGreaterThan(0);
      expect(result.stableCount).toBeGreaterThan(0);
    });

    it('should set initialized flag', async () => {
      expect(provider['initialized']).toBe(false);
      await provider.init();
      expect(provider['initialized']).toBe(true);
    });

    it('should only initialize once', async () => {
      await provider.init();
      await provider.init();
      expect(provider['initialized']).toBe(true);
    });

    it('should sort releases by date, newest first', async () => {
      await provider.init();
      const result = await provider.queryReleases();
      expect(result.releases.length).toBeGreaterThan(1);

      for (let i = 1; i < result.releases.length; i++) {
        const prevDate = new Date(result.releases[i - 1].releasedAt).getTime();
        const currDate = new Date(result.releases[i].releasedAt).getTime();
        expect(prevDate).toBeGreaterThanOrEqual(currDate);
      }
    });
  });

  describe('queryReleases()', () => {
    beforeEach(async () => {
      await provider.init();
    });

    it('should return all releases when no filters are applied', async () => {
      const result = await provider.queryReleases();
      expect(result.releases.length).toBeGreaterThan(0);
      expect(result.total).toBe(result.releases.length);
      expect(result.evidence.length).toBeGreaterThan(0);
    });

    it('should filter by version pattern', async () => {
      const result = await provider.queryReleases({ version: '5.10.200' });
      expect(result.releases.length).toBeGreaterThan(0);
      expect(result.releases.every((rel) => 
        rel.version.includes('5.10.200') || rel.id.includes('5.10.200'))).toBe(true);
      expect(result.evidence.some((e) => e.claim.includes('version pattern'))).toBe(true);
    });

    it('should filter by source', async () => {
      const result = await provider.queryReleases({ source: 'cip' });
      expect(result.releases.length).toBeGreaterThan(0);
      expect(result.releases.every((rel) => rel.source === 'cip')).toBe(true);
      expect(result.evidence.some((e) => e.claim.includes('source'))).toBe(true);
    });

    it('should filter by series', async () => {
      const result = await provider.queryReleases({ series: '5.10' });
      expect(result.releases.length).toBeGreaterThan(0);
      expect(result.releases.every((rel) => rel.series === '5.10')).toBe(true);
      expect(result.evidence.some((e) => e.claim.includes('series'))).toBe(true);
    });

    it('should filter by branch', async () => {
      const result = await provider.queryReleases({ branch: 'linux-5.10.y-cip' });
      expect(result.releases.length).toBeGreaterThan(0);
      expect(result.releases.every((rel) => rel.branch === 'linux-5.10.y-cip')).toBe(true);
      expect(result.evidence.some((e) => e.claim.includes('branch'))).toBe(true);
    });

    it('should filter by date since', async () => {
      const result = await provider.queryReleases({ since: '2024-01-01T00:00:00Z' });
      expect(result.releases.length).toBeGreaterThan(0);
      expect(result.releases.every((rel) => 
        new Date(rel.releasedAt) >= new Date('2024-01-01T00:00:00Z'))).toBe(true);
      expect(result.evidence.some((e) => e.claim.includes('date since'))).toBe(true);
    });

    it('should filter by date until', async () => {
      const result = await provider.queryReleases({ until: '2024-03-01T00:00:00Z' });
      expect(result.releases.length).toBeGreaterThan(0);
      expect(result.releases.every((rel) => 
        new Date(rel.releasedAt) <= new Date('2024-03-01T00:00:00Z'))).toBe(true);
      expect(result.evidence.some((e) => e.claim.includes('date until'))).toBe(true);
    });

    it('should filter by CVE', async () => {
      const result = await provider.queryReleases({ cve: 'CVE-2024-26642' });
      expect(result.releases.length).toBeGreaterThan(0);
      expect(result.releases.every((rel) => rel.fixedCves.includes('CVE-2024-26642'))).toBe(true);
      expect(result.evidence.some((e) => e.claim.includes('CVE'))).toBe(true);
    });

    it('should filter to CIP releases only', async () => {
      const result = await provider.queryReleases({ cipOnly: true });
      expect(result.releases.length).toBeGreaterThan(0);
      expect(result.releases.every((rel) => rel.isCip)).toBe(true);
      expect(result.evidence.some((e) => e.claim.includes('CIP releases only'))).toBe(true);
    });

    it('should filter to stable releases only', async () => {
      const result = await provider.queryReleases({ stableOnly: true });
      expect(result.releases.length).toBeGreaterThan(0);
      expect(result.releases.every((rel) => rel.isStable)).toBe(true);
      expect(result.evidence.some((e) => e.claim.includes('stable releases only'))).toBe(true);
    });

    it('should apply limit', async () => {
      const result = await provider.queryReleases({ limit: 5 });
      expect(result.releases.length).toBeLessThanOrEqual(5);
      expect(result.evidence.some((e) => e.claim.includes('Limited to'))).toBe(true);
    });

    it('should apply multiple filters correctly', async () => {
      const result = await provider.queryReleases({
        source: 'cip',
        series: '5.10',
        limit: 3,
      });
      expect(result.releases.length).toBeLessThanOrEqual(3);
      expect(result.releases.every((rel) => 
        rel.source === 'cip' && rel.series === '5.10')).toBe(true);
    });

    it('should return correct counts', async () => {
      const result = await provider.queryReleases();
      expect(result.cipCount).toBe(result.releases.filter((r) => r.isCip).length);
      expect(result.stableCount).toBe(result.releases.filter((r) => r.isStable).length);
      expect(result.total).toBe(result.releases.length);
    });

    it('should return empty array for non-matching filters', async () => {
      const result = await provider.queryReleases({ version: 'nonexistent-version-xyz' });
      expect(result.releases.length).toBe(0);
      expect(result.total).toBe(0);
    });
  });

  describe('getRelease()', () => {
    beforeEach(async () => {
      await provider.init();
    });

    it('should find release by exact ID', async () => {
      const release = await provider.getRelease('v5.10.200-cip35');
      expect(release).toBeDefined();
      expect(release?.id).toBe('v5.10.200-cip35');
    });

    it('should find release by version', async () => {
      const release = await provider.getRelease('5.10.200-cip35');
      expect(release).toBeDefined();
      expect(release?.version).toBe('5.10.200-cip35');
    });

    it('should return undefined for non-existent release', async () => {
      const release = await provider.getRelease('nonexistent-release-xyz');
      expect(release).toBeUndefined();
    });

    it('should return release with all expected fields', async () => {
      const release = await provider.getRelease('v5.10.200-cip35');
      expect(release).toBeDefined();
      expect(release?.id).toBeDefined();
      expect(release?.version).toBeDefined();
      expect(release?.releasedAt).toBeDefined();
      expect(release?.source).toBeDefined();
      expect(release?.url).toBeDefined();
      expect(release?.title).toBeDefined();
      expect(release?.notes).toBeDefined();
      expect(release?.fixedCves).toBeDefined();
      expect(release?.fixingCommits).toBeDefined();
      expect(release?.series).toBeDefined();
      expect(release?.branch).toBeDefined();
      expect(release?.isStable).toBeDefined();
      expect(release?.isCip).toBeDefined();
    });
  });

  describe('getLatestRelease()', () => {
    beforeEach(async () => {
      await provider.init();
    });

    it('should return the latest release for a series', async () => {
      const release = await provider.getLatestRelease('5.10');
      expect(release).toBeDefined();
      expect(release?.series).toBe('5.10');
    });

    it('should return undefined for non-existent series', async () => {
      const release = await provider.getLatestRelease('nonexistent-series');
      expect(release).toBeUndefined();
    });

    it('should return the newest release by date', async () => {
      const release = await provider.getLatestRelease('5.10');
      expect(release).toBeDefined();

      // Verify it's the newest by comparing with all releases in the series
      const allReleases = await provider.queryReleases({ series: '5.10' });
      const latestDate = new Date(release!.releasedAt).getTime();
      for (const r of allReleases.releases) {
        const relDate = new Date(r.releasedAt).getTime();
        expect(latestDate).toBeGreaterThanOrEqual(relDate);
      }
    });
  });

  describe('refresh()', () => {
    it('should refresh release data without errors', async () => {
      await provider.init();
      await expect(provider.refresh()).resolves.not.toThrow();
    });

    it('should still work when refresh fails', async () => {
      await provider.init();
      await provider.refresh();
      const result = await provider.queryReleases();
      expect(result.releases.length).toBeGreaterThan(0);
    });

    it('should maintain sorting after refresh', async () => {
      await provider.init();
      await provider.refresh();
      const result = await provider.queryReleases();

      for (let i = 1; i < result.releases.length; i++) {
        const prevDate = new Date(result.releases[i - 1].releasedAt).getTime();
        const currDate = new Date(result.releases[i].releasedAt).getTime();
        expect(prevDate).toBeGreaterThanOrEqual(currDate);
      }
    });
  });

  describe('CipRelease interface compliance', () => {
    beforeEach(async () => {
      await provider.init();
    });

    it('should return releases with correct interface structure', async () => {
      const result = await provider.queryReleases();
      expect(result.releases.length).toBeGreaterThan(0);

      for (const release of result.releases) {
        expect(release).toHaveProperty('id');
        expect(typeof release.id).toBe('string');
        expect(release).toHaveProperty('version');
        expect(typeof release.version).toBe('string');
        expect(release).toHaveProperty('releasedAt');
        expect(typeof release.releasedAt).toBe('string');
        expect(release).toHaveProperty('source');
        expect(release).toHaveProperty('fixedCves');
        expect(Array.isArray(release.fixedCves)).toBe(true);
        expect(release).toHaveProperty('fixingCommits');
        expect(Array.isArray(release.fixingCommits)).toBe(true);
        expect(release).toHaveProperty('isStable');
        expect(typeof release.isStable).toBe('boolean');
        expect(release).toHaveProperty('isCip');
        expect(typeof release.isCip).toBe('boolean');
      }
    });

    it('should have valid source values', async () => {
      const result = await provider.queryReleases();
      const validSources = ['cip', 'kernel.org', 'debian', 'other'];

      for (const release of result.releases) {
        expect(validSources).toContain(release.source);
      }
    });

    it('should have valid series values', async () => {
      const result = await provider.queryReleases({ series: '5.10' });
      expect(result.releases.length).toBeGreaterThan(0);

      for (const release of result.releases) {
        expect(release.series).toBe('5.10');
      }
    });
  });

  describe('Rule R1 compliance (Upstream First)', () => {
    beforeEach(async () => {
      await provider.init();
    });

    it('should prioritize CIP and kernel.org sources', async () => {
      const result = await provider.queryReleases();
      expect(result.releases.length).toBeGreaterThan(0);

      const validSources = ['cip', 'kernel.org'];
      for (const release of result.releases) {
        expect(validSources).toContain(release.source);
      }
    });

    it('should include source information in evidence', async () => {
      const result = await provider.queryReleases();
      expect(result.evidence.length).toBeGreaterThan(0);
      expect(result.evidence[0].source).toBe('release-announcements');
    });
  });

  describe('Rule R3 compliance (Commit-Keyed)', () => {
    beforeEach(async () => {
      await provider.init();
    });

    it('should include fixing commits in releases', async () => {
      const result = await provider.queryReleases();
      expect(result.releases.length).toBeGreaterThan(0);

      for (const release of result.releases) {
        expect(Array.isArray(release.fixingCommits)).toBe(true);
        expect(release.fixingCommits.length).toBeGreaterThanOrEqual(0);
      }
    });

    it('should have non-empty fixing commits for releases with CVEs', async () => {
      const result = await provider.queryReleases({ cve: 'CVE-2024-26642' });
      expect(result.releases.length).toBeGreaterThan(0);

      for (const release of result.releases) {
        if (release.fixedCves.length > 0) {
          expect(release.fixingCommits.length).toBeGreaterThan(0);
        }
      }
    });

    it('should provide evidence chain for queries', async () => {
      const result = await provider.queryReleases();
      expect(result.evidence.length).toBeGreaterThan(0);

      for (const evidence of result.evidence) {
        expect(evidence).toHaveProperty('claim');
        expect(evidence).toHaveProperty('source');
      }
    });
  });

  describe('Offline-first behavior', () => {
    it('should work with seed data when initialization fails', async () => {
      const failingCache = {
        wrap: () => {
          throw new Error('Cache failed');
        },
      } as unknown as CacheManager;

      const offlineProvider = new ReleaseAnnouncementsProvider(failingCache);
      await offlineProvider.init();

      const result = await offlineProvider.queryReleases();
      expect(result.releases.length).toBeGreaterThan(0);
    });

    it('should return seed CIP releases', async () => {
      await provider.init();
      const result = await provider.queryReleases({ cipOnly: true });
      expect(result.cipCount).toBeGreaterThan(0);
    });

    it('should return seed kernel.org releases', async () => {
      await provider.init();
      const result = await provider.queryReleases({ source: 'kernel.org' });
      expect(result.releases.length).toBeGreaterThan(0);
    });
  });

  describe('Provider interface compliance', () => {
    it('should have correct id', () => {
      expect(provider.id).toBe('release-announcements');
    });

    it('should have init method', () => {
      expect(typeof provider.init).toBe('function');
    });

    it('should have queryReleases method', () => {
      expect(typeof provider.queryReleases).toBe('function');
    });

    it('should have getRelease method', () => {
      expect(typeof provider.getRelease).toBe('function');
    });

    it('should have getLatestRelease method', () => {
      expect(typeof provider.getLatestRelease).toBe('function');
    });

    it('should have refresh method', () => {
      expect(typeof provider.refresh).toBe('function');
    });
  });
});

describe('createReleaseAnnouncementsProvider', () => {
  let tempDir: string;

  beforeEach(() => {
    tempDir = createTempCacheDir();
  });

  afterEach(() => {
    cleanupTempDir(tempDir);
  });

  it('should create a provider with default cache directory', async () => {
    const { createReleaseAnnouncementsProvider } = await import('../src/providers/release-announcements.js');
    const provider = createReleaseAnnouncementsProvider(tempDir);
    expect(provider).toBeDefined();
    expect(provider.id).toBe('release-announcements');
  });

  it('should create a provider that can be initialized', async () => {
    const { createReleaseAnnouncementsProvider } = await import('../src/providers/release-announcements.js');
    const provider = createReleaseAnnouncementsProvider(tempDir);
    await expect(provider.init()).resolves.not.toThrow();
  });
});

describe('CipRelease type validation', () => {
  it('should have all required fields', () => {
    const release: CipRelease = {
      id: 'v5.10.200-cip35',
      version: '5.10.200-cip35',
      releasedAt: '2024-05-15T00:00:00Z',
      source: 'cip',
      fixedCves: [],
      fixingCommits: [],
      isStable: true,
      isCip: true,
    };

    expect(release).toHaveProperty('id');
    expect(release).toHaveProperty('version');
    expect(release).toHaveProperty('releasedAt');
    expect(release).toHaveProperty('source');
    expect(release).toHaveProperty('fixedCves');
    expect(release).toHaveProperty('fixingCommits');
    expect(release).toHaveProperty('isStable');
    expect(release).toHaveProperty('isCip');
  });

  it('should accept optional fields', () => {
    const release: CipRelease = {
      id: 'v5.10.200-cip35',
      version: '5.10.200-cip35',
      releasedAt: '2024-05-15T00:00:00Z',
      source: 'cip',
      url: 'https://www.cip-project.org/2024/05/15/cip-kernel-5-10-200-cip35-released/',
      title: 'CIP Kernel 5.10.200-cip35 Released',
      notes: 'CIP kernel 5.10.200-cip35 released with security fixes',
      fixedCves: ['CVE-2024-26642'],
      fixingCommits: ['a1b2c3d4e5f6789012345678901234567890abcd'],
      series: '5.10',
      branch: 'linux-5.10.y-cip',
      isStable: true,
      isCip: true,
    };

    expect(release.url).toBe('https://www.cip-project.org/2024/05/15/cip-kernel-5-10-200-cip35-released/');
    expect(release.title).toBe('CIP Kernel 5.10.200-cip35 Released');
    expect(release.notes).toBe('CIP kernel 5.10.200-cip35 released with security fixes');
    expect(release.fixedCves).toEqual(['CVE-2024-26642']);
    expect(release.fixingCommits).toEqual(['a1b2c3d4e5f6789012345678901234567890abcd']);
    expect(release.series).toBe('5.10');
    expect(release.branch).toBe('linux-5.10.y-cip');
  });
});

describe('ReleaseQueryResult type validation', () => {
  it('should have all required fields', () => {
    const result: ReleaseQueryResult = {
      releases: [],
      total: 0,
      cipCount: 0,
      stableCount: 0,
      evidence: [],
    };

    expect(result).toHaveProperty('releases');
    expect(result).toHaveProperty('total');
    expect(result).toHaveProperty('cipCount');
    expect(result).toHaveProperty('stableCount');
    expect(result).toHaveProperty('evidence');
  });

  it('should accept array values', () => {
    const release: CipRelease = {
      id: 'v5.10.200-cip35',
      version: '5.10.200-cip35',
      releasedAt: '2024-05-15T00:00:00Z',
      source: 'cip',
      fixedCves: ['CVE-2024-26642'],
      fixingCommits: ['a1b2c3d4'],
      isStable: true,
      isCip: true,
    };

    const result: ReleaseQueryResult = {
      releases: [release],
      total: 1,
      cipCount: 1,
      stableCount: 1,
      evidence: [{ claim: 'test', source: 'test' }],
    };

    expect(result.releases).toHaveLength(1);
    expect(result.total).toBe(1);
    expect(result.cipCount).toBe(1);
    expect(result.stableCount).toBe(1);
    expect(result.evidence).toHaveLength(1);
  });
});
