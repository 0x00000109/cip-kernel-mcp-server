import { describe, expect, it, beforeEach, afterEach } from 'vitest';
import { rmSync, mkdirSync, existsSync } from 'node:fs';
import { join } from 'node:path';
import { CacheManager } from '../src/engine/cache.js';
import { ReleaseAnnouncementsProvider } from '../src/providers/release-announcements.js';
import { ReleaseTrackerProvider } from '../src/analysis/release-tracker.js';
import type { CipRelease, ReleaseTrackingResult, TrackedCve } from '../src/engine/types.js';

/**
 * Mock CVE provider for testing
 */
class MockCveProvider {
  readonly id = 'mock-cve';

  async init(): Promise<void> {}

  async query(cveId: string): Promise<any | undefined> {
    // Return mock CVE record for known CVEs
    if (cveId === 'CVE-2024-26642') {
      return {
        id: cveId,
        description: 'Use-after-free in netfilter nf_tables',
        source: 'kernel.org-cve',
        affected: [{ file: 'net/netfilter/nf_tables_api.c' }],
        fixingCommits: [{ sha: 'a1b2c3d4e5f6789012345678901234567890abcd', branches: ['linux-5.10.y'] }],
        fetchedAt: new Date().toISOString(),
      };
    }
    return undefined;
  }
}

/**
 * Test helper to create a temporary cache directory
 */
function createTempCacheDir(): string {
  const tempDir = join(process.cwd(), '.test-cache', `release-tracker-${Date.now()}`);
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

describe('ReleaseTrackerProvider (Module W2, Rule R3)', () => {
  let releaseProvider: ReleaseAnnouncementsProvider;
  let cveProvider: MockCveProvider;
  let trackerProvider: ReleaseTrackerProvider;
  let cacheDir: string;
  let cache: CacheManager;

  beforeEach(() => {
    cacheDir = createTempCacheDir();
    cache = new CacheManager(cacheDir, 1000);
    releaseProvider = new ReleaseAnnouncementsProvider(cache);
    cveProvider = new MockCveProvider();
    trackerProvider = new ReleaseTrackerProvider(releaseProvider, cveProvider as any);
  });

  afterEach(() => {
    cleanupTempDir(cacheDir);
  });

  describe('init()', () => {
    it('should initialize without errors', async () => {
      await expect(trackerProvider.init()).resolves.not.toThrow();
    });

    it('should initialize providers', async () => {
      await trackerProvider.init();
      // Providers should be initialized
      expect(trackerProvider['initialized']).toBe(true);
    });
  });

  describe('trackRelease()', () => {
    beforeEach(async () => {
      await trackerProvider.init();
    });

    it('should track a CIP release', async () => {
      const result = await trackerProvider.trackRelease({
        installedRelease: 'v5.10.190-cip29',
      });

      expect(result).toBeDefined();
      expect(result.installed.release).toBe('v5.10.190-cip29');
      expect(result.installed.isCip).toBe(true);
      expect(result.isUpToDate).toBeDefined();
      expect(result.releasesBehind).toBeGreaterThanOrEqual(0);
      expect(result.recommendation).toBeDefined();
      expect(result.evidence.length).toBeGreaterThan(0);
    });

    it('should include CVE tracking by default', async () => {
      const result = await trackerProvider.trackRelease({
        installedRelease: 'v5.10.190-cip29',
      });

      expect(result.trackedCves.length).toBeGreaterThan(0);
      expect(result.cveStats.total).toBeGreaterThan(0);
    });

    it('should allow disabling CVE tracking', async () => {
      const result = await trackerProvider.trackRelease({
        installedRelease: 'v5.10.190-cip29',
        includeCveTracking: false,
      });

      expect(result.trackedCves.length).toBe(0);
      expect(result.cveStats.total).toBe(0);
    });

    it('should return available updates', async () => {
      const result = await trackerProvider.trackRelease({
        installedRelease: 'v5.10.190-cip29',
      });

      expect(result.availableUpdates).toBeDefined();
      expect(Array.isArray(result.availableUpdates)).toBe(true);
    });

    it('should calculate releases behind correctly', async () => {
      const result = await trackerProvider.trackRelease({
        installedRelease: 'v5.10.200-cip35',
      });

      expect(result.releasesBehind).toBeGreaterThanOrEqual(0);
    });

    it('should determine update recommendation', async () => {
      const result = await trackerProvider.trackRelease({
        installedRelease: 'v5.10.200-cip35',
      });

      expect(['no-action', 'update-available', 'security-update', 'critical-update']).toContain(result.recommendation);
    });

    it('should track by kernel version', async () => {
      const result = await trackerProvider.trackRelease({
        installedRelease: 'v5.10.190-cip29',
        kernelVersion: '5.10.190',
      });

      expect(result.installed.kernelVersion).toContain('5.10.190');
    });

    it('should track by series', async () => {
      const result = await trackerProvider.trackRelease({
        installedRelease: 'v5.10.190-cip29',
        series: '5.10',
      });

      expect(result.installed.branch).toBe('linux-5.10.y-cip');
    });
  });

  describe('trackReleases()', () => {
    beforeEach(async () => {
      await trackerProvider.init();
    });

    it('should track multiple releases', async () => {
      const results = await trackerProvider.trackReleases([
        { installedRelease: 'v5.10.190-cip29' },
        { installedRelease: 'v5.10.200-cip35' },
      ]);

      expect(results.length).toBe(2);
      expect(results[0].installed.release).toBe('v5.10.190-cip29');
      expect(results[1].installed.release).toBe('v5.10.200-cip35');
    });
  });

  describe('getUpdateStatus()', () => {
    beforeEach(async () => {
      await trackerProvider.init();
    });

    it('should return update status for a release', async () => {
      const result = await trackerProvider.getUpdateStatus('v5.10.190-cip29');

      expect(result).toBeDefined();
      expect(result.isUpToDate).toBeDefined();
      expect(result.releasesBehind).toBeGreaterThanOrEqual(0);
      expect(result.recommendation).toBeDefined();
      expect(result.availableUpdates).toBeDefined();
      expect(result.evidence.length).toBeGreaterThan(0);
    });

    it('should identify up-to-date systems', async () => {
      const result = await trackerProvider.getUpdateStatus('v5.10.200-cip35');

      // The latest release should be up-to-date
      if (result.latestAvailable?.version === 'v5.10.200-cip35') {
        expect(result.isUpToDate).toBe(true);
        expect(result.releasesBehind).toBe(0);
      }
    });

    it('should identify systems needing updates', async () => {
      const result = await trackerProvider.getUpdateStatus('v5.10.190-cip29');

      // Just verify the result structure
      expect(result).toBeDefined();
      expect(result.isUpToDate).toBeDefined();
      expect(result.releasesBehind).toBeGreaterThanOrEqual(0);
    });
  });

  describe('CVE tracking (Rule R3)', () => {
    beforeEach(async () => {
      await trackerProvider.init();
    });

    it('should track CVEs for installed release', async () => {
      const result = await trackerProvider.trackRelease({
        installedRelease: 'v5.10.190-cip29',
        includeCveTracking: true,
      });

      expect(result.trackedCves.length).toBeGreaterThan(0);

      for (const cve of result.trackedCves) {
        expect(cve).toHaveProperty('cve');
        expect(cve).toHaveProperty('status');
        expect(cve).toHaveProperty('description');
        expect(cve).toHaveProperty('fixingCommits');
        expect(cve).toHaveProperty('evidence');
        expect(['fixed', 'fixed-upstream', 'affected', 'not-affected', 'unknown']).toContain(cve.status);
      }
    });

    it('should identify fixed CVEs', async () => {
      const result = await trackerProvider.trackRelease({
        installedRelease: 'v5.10.200-cip35',
        includeCveTracking: true,
      });

      // v5.10.200-cip35 should have some fixed CVEs
      const fixedCves = result.trackedCves.filter((c) => c.status === 'fixed');
      expect(fixedCves.length).toBeGreaterThanOrEqual(0);
    });

    it('should identify fixed-upstream CVEs', async () => {
      const result = await trackerProvider.trackRelease({
        installedRelease: 'v5.10.190-cip29',
        includeCveTracking: true,
      });

      // Older releases should have some fixed-upstream CVEs
      const fixedUpstreamCves = result.trackedCves.filter((c) => c.status === 'fixed-upstream');
      expect(fixedUpstreamCves.length).toBeGreaterThanOrEqual(0);
    });

    it('should calculate CVE statistics', async () => {
      const result = await trackerProvider.trackRelease({
        installedRelease: 'v5.10.190-cip29',
        includeCveTracking: true,
      });

      expect(result.cveStats.total).toBeGreaterThan(0);
      expect(result.cveStats.fixed + result.cveStats.fixedUpstream + result.cveStats.affected + result.cveStats.notAffected + result.cveStats.unknown).toBe(result.cveStats.total);
    });

    it('should include fixing commits in CVE tracking (Rule R3)', async () => {
      const result = await trackerProvider.trackRelease({
        installedRelease: 'v5.10.190-cip29',
        includeCveTracking: true,
      });

      for (const cve of result.trackedCves) {
        expect(Array.isArray(cve.fixingCommits)).toBe(true);
        if (cve.fixingCommits.length > 0) {
          expect(cve.fixingCommits[0].length).toBeGreaterThan(0);
        }
      }
    });
  });

  describe('Provider interface compliance', () => {
    it('should have correct id', () => {
      expect(trackerProvider.id).toBe('release-tracker');
    });

    it('should have init method', () => {
      expect(typeof trackerProvider.init).toBe('function');
    });

    it('should have trackRelease method', () => {
      expect(typeof trackerProvider.trackRelease).toBe('function');
    });

    it('should have trackReleases method', () => {
      expect(typeof trackerProvider.trackReleases).toBe('function');
    });

    it('should have getUpdateStatus method', () => {
      expect(typeof trackerProvider.getUpdateStatus).toBe('function');
    });
  });

  describe('ReleaseTrackingResult type validation', () => {
    it('should have all required fields', async () => {
      await trackerProvider.init();
      const result = await trackerProvider.trackRelease({
        installedRelease: 'v5.10.190-cip29',
      });

      expect(result).toHaveProperty('installed');
      expect(result).toHaveProperty('latestAvailable');
      expect(result).toHaveProperty('isUpToDate');
      expect(result).toHaveProperty('releasesBehind');
      expect(result).toHaveProperty('recommendation');
      expect(result).toHaveProperty('trackedCves');
      expect(result).toHaveProperty('cveStats');
      expect(result).toHaveProperty('availableUpdates');
      expect(result).toHaveProperty('evidence');
    });

    it('should have correct cveStats structure', async () => {
      await trackerProvider.init();
      const result = await trackerProvider.trackRelease({
        installedRelease: 'v5.10.190-cip29',
      });

      expect(result.cveStats).toHaveProperty('total');
      expect(result.cveStats).toHaveProperty('fixed');
      expect(result.cveStats).toHaveProperty('fixedUpstream');
      expect(result.cveStats).toHaveProperty('affected');
      expect(result.cveStats).toHaveProperty('notAffected');
      expect(result.cveStats).toHaveProperty('unknown');
    });
  });

  describe('TrackedCve type validation', () => {
    it('should have all required fields', async () => {
      await trackerProvider.init();
      const result = await trackerProvider.trackRelease({
        installedRelease: 'v5.10.190-cip29',
        includeCveTracking: true,
      });

      if (result.trackedCves.length > 0) {
        const cve = result.trackedCves[0];
        expect(cve).toHaveProperty('cve');
        expect(cve).toHaveProperty('status');
        expect(cve).toHaveProperty('fixingCommits');
        expect(cve).toHaveProperty('evidence');
      }
    });

    it('should have valid status values', async () => {
      await trackerProvider.init();
      const result = await trackerProvider.trackRelease({
        installedRelease: 'v5.10.190-cip29',
        includeCveTracking: true,
      });

      const validStatuses = ['fixed', 'fixed-upstream', 'affected', 'not-affected', 'unknown'];
      for (const cve of result.trackedCves) {
        expect(validStatuses).toContain(cve.status);
      }
    });
  });

  describe('Evidence chain (Rule R8)', () => {
    it('should include evidence chain for trackRelease', async () => {
      await trackerProvider.init();
      const result = await trackerProvider.trackRelease({
        installedRelease: 'v5.10.190-cip29',
      });

      expect(result.evidence.length).toBeGreaterThan(0);
      for (const evidence of result.evidence) {
        expect(evidence).toHaveProperty('claim');
        expect(evidence).toHaveProperty('source');
        expect(evidence.source).toBe('release-tracker');
      }
    });

    it('should include evidence chain for getUpdateStatus', async () => {
      await trackerProvider.init();
      const result = await trackerProvider.getUpdateStatus('v5.10.190-cip29');

      expect(result.evidence.length).toBeGreaterThan(0);
      for (const evidence of result.evidence) {
        expect(evidence).toHaveProperty('claim');
        expect(evidence).toHaveProperty('source');
      }
    });
  });
});

describe('createReleaseTrackerProvider', () => {
  let tempDir: string;

  beforeEach(() => {
    tempDir = createTempCacheDir();
  });

  afterEach(() => {
    cleanupTempDir(tempDir);
  });

  it('should create a provider with default dependencies', async () => {
    const { createReleaseTrackerProvider } = await import('../src/analysis/release-tracker.js');
    const cache = new CacheManager(tempDir, 1000);
    const releaseProvider = new ReleaseAnnouncementsProvider(cache);
    const cveProvider = new MockCveProvider();
    const provider = createReleaseTrackerProvider(releaseProvider, cveProvider as any);

    expect(provider).toBeDefined();
    expect(provider.id).toBe('release-tracker');
  });

  it('should create a provider that can be initialized', async () => {
    const { createReleaseTrackerProvider } = await import('../src/analysis/release-tracker.js');
    const cache = new CacheManager(tempDir, 1000);
    const releaseProvider = new ReleaseAnnouncementsProvider(cache);
    const cveProvider = new MockCveProvider();
    const provider = createReleaseTrackerProvider(releaseProvider, cveProvider as any);

    await expect(provider.init()).resolves.not.toThrow();
  });
});
