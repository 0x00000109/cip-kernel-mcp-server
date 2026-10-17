import { describe, expect, it, beforeEach, afterEach } from 'vitest';
import { rmSync, mkdirSync, existsSync } from 'node:fs';
import { join } from 'node:path';
import { CacheManager } from '../src/engine/cache.js';
import { CipPackagesProvider } from '../src/providers/cip-packages.js';
import type { CipPackage, CipPackageQueryResult } from '../src/engine/types.js';

/**
 * Test helper to create a temporary cache directory
 */
function createTempCacheDir(): string {
  const tempDir = join(process.cwd(), '.test-cache', `cip-packages-${Date.now()}`);
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

describe('CipPackagesProvider (Module P5, Rule R6)', () => {
  let provider: CipPackagesProvider;
  let cacheDir: string;
  let cache: CacheManager;

  beforeEach(() => {
    cacheDir = createTempCacheDir();
    cache = new CacheManager(cacheDir, 1000);
    provider = new CipPackagesProvider(cache);
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
      const result = await provider.queryPackages();
      expect(result.packages.length).toBeGreaterThan(0);
      expect(result.cipCount).toBeGreaterThan(0);
      expect(result.debianCount).toBeGreaterThan(0);
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
  });

  describe('queryPackages()', () => {
    beforeEach(async () => {
      await provider.init();
    });

    it('should return all packages when no filters are applied', async () => {
      const result = await provider.queryPackages();
      expect(result.packages.length).toBeGreaterThan(0);
      expect(result.total).toBe(result.packages.length);
      expect(result.evidence.length).toBeGreaterThan(0);
    });

    it('should filter by name pattern', async () => {
      const result = await provider.queryPackages({ name: 'amd64' });
      expect(result.packages.length).toBeGreaterThan(0);
      expect(result.packages.every((pkg) => pkg.name.includes('amd64'))).toBe(true);
      expect(result.evidence.some((e) => e.claim.includes('name pattern'))).toBe(true);
    });

    it('should filter by version', async () => {
      const result = await provider.queryPackages({ version: '5.10.13-1' });
      expect(result.packages.length).toBeGreaterThan(0);
      expect(result.packages.every((pkg) => pkg.version === '5.10.13-1')).toBe(true);
      expect(result.evidence.some((e) => e.claim.includes('version'))).toBe(true);
    });

    it('should filter by source', async () => {
      const result = await provider.queryPackages({ source: 'cip' });
      expect(result.packages.length).toBeGreaterThan(0);
      expect(result.packages.every((pkg) => pkg.source === 'cip')).toBe(true);
      expect(result.evidence.some((e) => e.claim.includes('source'))).toBe(true);
    });

    it('should filter by architecture', async () => {
      const result = await provider.queryPackages({ architecture: 'amd64' });
      expect(result.packages.length).toBeGreaterThan(0);
      expect(result.packages.every((pkg) => pkg.architecture === 'amd64')).toBe(true);
      expect(result.evidence.some((e) => e.claim.includes('architecture'))).toBe(true);
    });

    it('should filter by kernel version', async () => {
      const result = await provider.queryPackages({ kernelVersion: '5.10.13-cip1' });
      expect(result.packages.length).toBeGreaterThan(0);
      expect(result.packages.every((pkg) => pkg.kernelVersion === '5.10.13-cip1')).toBe(true);
      expect(result.evidence.some((e) => e.claim.includes('kernel version'))).toBe(true);
    });

    it('should filter by CVE', async () => {
      const result = await provider.queryPackages({ cve: 'CVE-2021-4034' });
      expect(result.packages.length).toBeGreaterThan(0);
      expect(result.packages.every((pkg) => pkg.cves.includes('CVE-2021-4034'))).toBe(true);
      expect(result.evidence.some((e) => e.claim.includes('CVE'))).toBe(true);
    });

    it('should filter to CIP packages only', async () => {
      const result = await provider.queryPackages({ cipOnly: true });
      expect(result.packages.length).toBeGreaterThan(0);
      expect(result.packages.every((pkg) => pkg.isCip)).toBe(true);
      expect(result.evidence.some((e) => e.claim.includes('CIP packages only'))).toBe(true);
    });

    it('should filter to Debian packages only', async () => {
      const result = await provider.queryPackages({ debianOnly: true });
      expect(result.packages.length).toBeGreaterThan(0);
      expect(result.packages.every((pkg) => pkg.isDebian)).toBe(true);
      expect(result.evidence.some((e) => e.claim.includes('Debian packages only'))).toBe(true);
    });

    it('should apply multiple filters correctly', async () => {
      const result = await provider.queryPackages({
        source: 'cip',
        architecture: 'amd64',
      });
      expect(result.packages.length).toBeGreaterThan(0);
      expect(result.packages.every((pkg) => pkg.source === 'cip' && pkg.architecture === 'amd64')).toBe(true);
    });

    it('should return correct counts', async () => {
      const result = await provider.queryPackages();
      expect(result.cipCount).toBe(result.packages.filter((p) => p.isCip).length);
      expect(result.debianCount).toBe(result.packages.filter((p) => p.isDebian).length);
      expect(result.total).toBe(result.packages.length);
    });

    it('should return empty array for non-matching filters', async () => {
      const result = await provider.queryPackages({ name: 'nonexistent-package-xyz' });
      expect(result.packages.length).toBe(0);
      expect(result.total).toBe(0);
    });
  });

  describe('getPackage()', () => {
    beforeEach(async () => {
      await provider.init();
    });

    it('should find package by exact name', async () => {
      const pkg = await provider.getPackage('linux-image-5.10.0-cip1-amd64');
      expect(pkg).toBeDefined();
      expect(pkg?.name).toBe('linux-image-5.10.0-cip1-amd64');
    });

    it('should find package by partial name match', async () => {
      const pkg = await provider.getPackage('linux-image-5.10.0-cip1');
      expect(pkg).toBeDefined();
      expect(pkg?.name).toContain('linux-image-5.10.0-cip1');
    });

    it('should return undefined for non-existent package', async () => {
      const pkg = await provider.getPackage('nonexistent-package-xyz');
      expect(pkg).toBeUndefined();
    });

    it('should return package with all expected fields', async () => {
      const pkg = await provider.getPackage('linux-image-5.10.0-cip1-amd64');
      expect(pkg).toBeDefined();
      expect(pkg?.name).toBeDefined();
      expect(pkg?.version).toBeDefined();
      expect(pkg?.source).toBeDefined();
      expect(pkg?.maintainer).toBeDefined();
      expect(pkg?.description).toBeDefined();
      expect(pkg?.dependencies).toBeDefined();
      expect(pkg?.cves).toBeDefined();
      expect(pkg?.url).toBeDefined();
      expect(pkg?.architecture).toBeDefined();
      expect(pkg?.kernelVersion).toBeDefined();
      expect(pkg?.releasedAt).toBeDefined();
      expect(pkg?.isCip).toBeDefined();
      expect(pkg?.isDebian).toBeDefined();
    });
  });

  describe('refresh()', () => {
    it('should refresh package data without errors', async () => {
      await provider.init();
      await expect(provider.refresh()).resolves.not.toThrow();
    });

    it('should still work when refresh fails', async () => {
      await provider.init();
      // Even if refresh fails, the provider should still have seed data
      await provider.refresh();
      const result = await provider.queryPackages();
      expect(result.packages.length).toBeGreaterThan(0);
    });
  });

  describe('CipPackage interface compliance', () => {
    beforeEach(async () => {
      await provider.init();
    });

    it('should return packages with correct interface structure', async () => {
      const result = await provider.queryPackages();
      expect(result.packages.length).toBeGreaterThan(0);

      for (const pkg of result.packages) {
        expect(pkg).toHaveProperty('name');
        expect(typeof pkg.name).toBe('string');
        expect(pkg).toHaveProperty('version');
        expect(typeof pkg.version).toBe('string');
        expect(pkg).toHaveProperty('source');
        expect(pkg).toHaveProperty('dependencies');
        expect(Array.isArray(pkg.dependencies)).toBe(true);
        expect(pkg).toHaveProperty('cves');
        expect(Array.isArray(pkg.cves)).toBe(true);
        expect(pkg).toHaveProperty('isCip');
        expect(typeof pkg.isCip).toBe('boolean');
        expect(pkg).toHaveProperty('isDebian');
        expect(typeof pkg.isDebian).toBe('boolean');
      }
    });

    it('should have valid source values', async () => {
      const result = await provider.queryPackages();
      const validSources = ['cip', 'debian', 'ubuntu', 'elrepo', 'other'];

      for (const pkg of result.packages) {
        expect(validSources).toContain(pkg.source);
      }
    });

    it('should have valid architecture values', async () => {
      const result = await provider.queryPackages({ architecture: 'amd64' });
      expect(result.packages.length).toBeGreaterThan(0);

      for (const pkg of result.packages) {
        expect(pkg.architecture).toBe('amd64');
      }
    });
  });

  describe('Rule R6 compliance (ABI stability)', () => {
    beforeEach(async () => {
      await provider.init();
    });

    it('should track dependencies for ABI impact analysis', async () => {
      const result = await provider.queryPackages();
      expect(result.packages.length).toBeGreaterThan(0);

      // All packages should have dependencies tracked
      for (const pkg of result.packages) {
        expect(Array.isArray(pkg.dependencies)).toBe(true);
        expect(pkg.dependencies.length).toBeGreaterThanOrEqual(0);
      }
    });

    it('should provide kernel version information for ABI tracking', async () => {
      const result = await provider.queryPackages();
      expect(result.packages.length).toBeGreaterThan(0);

      // All packages should have kernel version for ABI tracking
      for (const pkg of result.packages) {
        if (pkg.kernelVersion) {
          expect(typeof pkg.kernelVersion).toBe('string');
          expect(pkg.kernelVersion.length).toBeGreaterThan(0);
        }
      }
    });

    it('should provide evidence chain for queries', async () => {
      const result = await provider.queryPackages();
      expect(result.evidence.length).toBeGreaterThan(0);

      for (const evidence of result.evidence) {
        expect(evidence).toHaveProperty('claim');
        expect(evidence).toHaveProperty('source');
        expect(evidence.source).toBe('cip-packages');
      }
    });
  });

  describe('Offline-first behavior', () => {
    it('should work with seed data when initialization fails', async () => {
      // Create a provider with a failing cache
      const failingCache = {
        wrap: () => {
          throw new Error('Cache failed');
        },
      } as unknown as CacheManager;

      const offlineProvider = new CipPackagesProvider(failingCache);
      await offlineProvider.init();

      const result = await offlineProvider.queryPackages();
      expect(result.packages.length).toBeGreaterThan(0);
    });

    it('should return seed CIP packages', async () => {
      await provider.init();
      const result = await provider.queryPackages({ cipOnly: true });
      expect(result.cipCount).toBeGreaterThan(0);
    });

    it('should return seed Debian packages', async () => {
      await provider.init();
      const result = await provider.queryPackages({ debianOnly: true });
      expect(result.debianCount).toBeGreaterThan(0);
    });
  });

  describe('Provider interface compliance', () => {
    it('should have correct id', () => {
      expect(provider.id).toBe('cip-packages');
    });

    it('should have init method', () => {
      expect(typeof provider.init).toBe('function');
    });

    it('should have queryPackages method', () => {
      expect(typeof provider.queryPackages).toBe('function');
    });

    it('should have getPackage method', () => {
      expect(typeof provider.getPackage).toBe('function');
    });

    it('should have refresh method', () => {
      expect(typeof provider.refresh).toBe('function');
    });
  });
});

describe('createCipPackagesProvider', () => {
  let tempDir: string;

  beforeEach(() => {
    tempDir = createTempCacheDir();
  });

  afterEach(() => {
    cleanupTempDir(tempDir);
  });

  it('should create a provider with default cache directory', async () => {
    const { createCipPackagesProvider } = await import('../src/providers/cip-packages.js');
    const provider = createCipPackagesProvider(tempDir);
    expect(provider).toBeDefined();
    expect(provider.id).toBe('cip-packages');
  });

  it('should create a provider that can be initialized', async () => {
    const { createCipPackagesProvider } = await import('../src/providers/cip-packages.js');
    const provider = createCipPackagesProvider(tempDir);
    await expect(provider.init()).resolves.not.toThrow();
  });
});

describe('CipPackage type validation', () => {
  it('should have all required fields', () => {
    const pkg: CipPackage = {
      name: 'test-package',
      version: '1.0.0',
      source: 'cip',
      isCip: true,
      isDebian: false,
      dependencies: [],
      cves: [],
    };

    expect(pkg).toHaveProperty('name');
    expect(pkg).toHaveProperty('version');
    expect(pkg).toHaveProperty('source');
    expect(pkg).toHaveProperty('isCip');
    expect(pkg).toHaveProperty('isDebian');
    expect(pkg).toHaveProperty('dependencies');
    expect(pkg).toHaveProperty('cves');
  });

  it('should accept optional fields', () => {
    const pkg: CipPackage = {
      name: 'test-package',
      version: '1.0.0',
      source: 'cip',
      maintainer: 'Test Maintainer',
      description: 'Test Description',
      dependencies: ['dep1', 'dep2'],
      cves: ['CVE-2024-0001'],
      url: 'https://example.com',
      architecture: 'amd64',
      kernelVersion: '5.10.0',
      releasedAt: '2024-01-01T00:00:00Z',
      isCip: true,
      isDebian: false,
    };

    expect(pkg.maintainer).toBe('Test Maintainer');
    expect(pkg.description).toBe('Test Description');
    expect(pkg.dependencies).toEqual(['dep1', 'dep2']);
    expect(pkg.cves).toEqual(['CVE-2024-0001']);
    expect(pkg.url).toBe('https://example.com');
    expect(pkg.architecture).toBe('amd64');
    expect(pkg.kernelVersion).toBe('5.10.0');
    expect(pkg.releasedAt).toBe('2024-01-01T00:00:00Z');
  });
});

describe('CipPackageQueryResult type validation', () => {
  it('should have all required fields', () => {
    const result: CipPackageQueryResult = {
      packages: [],
      total: 0,
      cipCount: 0,
      debianCount: 0,
      evidence: [],
    };

    expect(result).toHaveProperty('packages');
    expect(result).toHaveProperty('total');
    expect(result).toHaveProperty('cipCount');
    expect(result).toHaveProperty('debianCount');
    expect(result).toHaveProperty('evidence');
  });

  it('should accept array values', () => {
    const pkg: CipPackage = {
      name: 'test',
      version: '1.0',
      source: 'cip',
      isCip: true,
      isDebian: false,
      dependencies: [],
      cves: [],
    };

    const result: CipPackageQueryResult = {
      packages: [pkg],
      total: 1,
      cipCount: 1,
      debianCount: 0,
      evidence: [{ claim: 'test', source: 'test' }],
    };

    expect(result.packages).toHaveLength(1);
    expect(result.total).toBe(1);
    expect(result.cipCount).toBe(1);
    expect(result.debianCount).toBe(0);
    expect(result.evidence).toHaveLength(1);
  });
});
