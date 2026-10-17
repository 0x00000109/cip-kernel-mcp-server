import type {
  CipRelease,
  InstalledRelease,
  ReleaseTrackingOptions,
  ReleaseTrackingResult,
  ReleaseTrackerProvider as ReleaseTrackerProviderType,
  TrackedCve,
  CveStatus,
  UpdateRecommendation,
  EvidenceItem,
} from '../engine/types.js';
import type { ReleaseAnnouncementsProvider } from '../providers/release-announcements.js';
import type { CveProvider } from '../providers/cve-service.js';

/**
 * Seed CVE data for offline-first operation.
 * These are example CVEs that might affect CIP 5.10.x kernels.
 * Rule R3: Commit-keyed - CVEs are tracked by their fixing commits.
 */
const SEED_CVE_DATA: Map<string, { description: string; fixingCommits: string[]; severity?: string }> = new Map([
  ['CVE-2024-26642', { description: 'Use-after-free in netfilter nf_tables', fixingCommits: ['a1b2c3d4e5f6789012345678901234567890abcd'], severity: 'high' }],
  ['CVE-2024-26884', { description: 'Race condition in AF_VSOCK', fixingCommits: ['112233445566778899aabbccddeeff0011223344'], severity: 'medium' }],
  ['CVE-2024-26885', { description: 'Memory leak in netfilter', fixingCommits: ['aabbccddeeff00112233445566778899aabbccdd'], severity: 'medium' }],
  ['CVE-2024-26641', { description: 'Buffer overflow in Bluetooth subsystem', fixingCommits: ['ffaabbccdd11223344556677889900aabbcc'], severity: 'high' }],
  ['CVE-2024-26640', { description: 'Privilege escalation in filesystem layer', fixingCommits: ['eeaabbccdd223344556677889900aabbcc'], severity: 'critical' }],
  ['CVE-2024-26639', { description: 'Denial of service in network stack', fixingCommits: ['ddaabbcc11223344556677889900aabbcc'], severity: 'medium' }],
  ['CVE-2023-4881', { description: 'Use-after-free in filesystem notification', fixingCommits: ['bbaabbcc11223344556677889900aabbcc'], severity: 'high' }],
  ['CVE-2023-52428', { description: 'Memory corruption in KSM', fixingCommits: ['ccaabbcc11223344556677889900aabbcc'], severity: 'high' }],
]);

/**
 * Mapping of fixing commits to the releases that contain them.
 * Rule R3: Commit-keyed - tracking by commit SHAs.
 */
const COMMIT_TO_RELEASE_MAP: Map<string, string> = new Map([
  ['a1b2c3d4e5f6789012345678901234567890abcd', 'v5.10.200-cip35'],
  ['112233445566778899aabbccddeeff0011223344', 'v5.10.200-cip35'],
  ['aabbccddeeff00112233445566778899aabbccdd', 'v5.10.200-cip35'],
  ['ffaabbccdd11223344556677889900aabbcc', 'v5.10.199-cip34'],
  ['eeaabbccdd223344556677889900aabbcc', 'v5.10.198-cip33'],
  ['ddaabbcc11223344556677889900aabbcc', 'v5.10.197-cip32'],
  ['bbaabbcc11223344556677889900aabbcc', 'v5.10.195-cip30'],
  ['ccaabbcc11223344556677889900aabbcc', 'v5.10.195-cip30'],
]);

/**
 * Release tracker provider (Module W2, Rule R3).
 * Tracks installed CIP releases and their CVE status.
 * Provides update recommendations based on available releases.
 * Rule R3: Commit-keyed - tracks CVEs by their fixing commits.
 */
export class ReleaseTrackerProvider implements ReleaseTrackerProviderType {
  readonly id = 'release-tracker';

  private readonly releaseProvider: ReleaseAnnouncementsProvider;
  private readonly cveProvider: CveProvider;
  private initialized = false;

  constructor(releaseProvider: ReleaseAnnouncementsProvider, cveProvider: CveProvider) {
    this.releaseProvider = releaseProvider;
    this.cveProvider = cveProvider;
  }

  async init(): Promise<void> {
    if (this.initialized) return;
    await this.releaseProvider.init();
    await this.cveProvider.init();
    this.initialized = true;
  }

  async trackRelease(options: ReleaseTrackingOptions): Promise<ReleaseTrackingResult> {
    await this.ensureInitialized();

    const evidence: EvidenceItem[] = [{
      claim: `Tracking release: ${options.installedRelease}`,
      source: this.id,
    }];

    const installed: InstalledRelease = this.parseInstalledRelease(options);
    evidence.push({ claim: `Parsed installed release: ${installed.release} (${installed.kernelVersion})`, source: this.id });

    const series = options.series ?? installed.kernelVersion.split('.').slice(0, 2).join('.');
    const allReleases = await this.releaseProvider.queryReleases({ series });
    evidence.push({ claim: `Found ${allReleases.total} releases for series ${series}`, source: this.id });

    const foundInstalledRel = allReleases.releases.find(
      (r) => r.version === installed.release || r.id === installed.release,
    );
    const latestAvailable = await this.releaseProvider.getLatestRelease(series);
    evidence.push({ claim: latestAvailable ? `Latest available: ${latestAvailable.version}` : `No latest release found for series ${series}`, source: this.id });

    const releasesBehind = this.calculateReleasesBehind(foundInstalledRel, latestAvailable, allReleases.releases);
    evidence.push({ claim: `System is ${releasesBehind} releases behind`, source: this.id });

    const recommendation = this.determineRecommendation(foundInstalledRel, latestAvailable, releasesBehind);
    evidence.push({ claim: `Update recommendation: ${recommendation}`, source: this.id });

    const trackedCves: TrackedCve[] = options.includeCveTracking !== false
      ? await this.trackCves(installed, foundInstalledRel, allReleases.releases, evidence)
      : [];

    const cveStats = this.calculateCveStats(trackedCves);
    const availableUpdates = this.getAvailableUpdates(foundInstalledRel, allReleases.releases);

    return {
      installed,
      latestAvailable,
      isUpToDate: releasesBehind === 0,
      releasesBehind,
      recommendation,
      trackedCves,
      cveStats,
      availableUpdates,
      evidence,
    };
  }

  async trackReleases(options: ReleaseTrackingOptions[]): Promise<ReleaseTrackingResult[]> {
    await this.ensureInitialized();
    const results: ReleaseTrackingResult[] = [];
    for (const opt of options) {
      results.push(await this.trackRelease(opt));
    }
    return results;
  }

  async getUpdateStatus(releaseVersion: string): Promise<{
    isUpToDate: boolean;
    latestAvailable?: CipRelease;
    releasesBehind: number;
    recommendation: UpdateRecommendation;
    availableUpdates: CipRelease[];
    evidence: EvidenceItem[];
  }> {
    await this.ensureInitialized();

    const evidence: EvidenceItem[] = [{ claim: `Getting update status for: ${releaseVersion}`, source: this.id }];

    const installed: InstalledRelease = this.parseInstalledRelease({ installedRelease: releaseVersion });
    const series = installed.kernelVersion.split('.').slice(0, 2).join('.');
    const allReleases = await this.releaseProvider.queryReleases({ series });

    const foundRel = allReleases.releases.find(
      (r) => r.version === installed.release || r.id === installed.release,
    );
    const latestAvailable = await this.releaseProvider.getLatestRelease(series);
    const releasesBehind = this.calculateReleasesBehind(foundRel, latestAvailable, allReleases.releases);
    const recommendation = this.determineRecommendation(foundRel, latestAvailable, releasesBehind);
    const availableUpdates = this.getAvailableUpdates(foundRel, allReleases.releases);

    return {
      isUpToDate: releasesBehind === 0,
      latestAvailable,
      releasesBehind,
      recommendation,
      availableUpdates,
      evidence,
    };
  }

  private async ensureInitialized(): Promise<void> {
    if (!this.initialized) {
      await this.init();
    }
  }

  private parseInstalledRelease(options: ReleaseTrackingOptions): InstalledRelease {
    let release = options.installedRelease;
    let kernelVersion = options.kernelVersion ?? options.installedRelease;
    const versionMatch = /(v?\d+\.\d+\.\d+)(?:-cip(\d+))?/.exec(release);
    if (versionMatch) {
      kernelVersion = versionMatch[1];
      release = versionMatch[0];
    }
    const isCip = release.includes('cip') || options.installedRelease.includes('cip');
    const branch = isCip ? 'linux-5.10.y-cip' : 'linux-5.10.y';
    return { release: options.installedRelease, kernelVersion, installedAt: new Date().toISOString(), isCip, branch };
  }

  private calculateReleasesBehind(
    foundRel: CipRelease | undefined,
    latestAvailable: CipRelease | undefined,
    allReleases: CipRelease[],
  ): number {
    if (!foundRel || !latestAvailable) return 0;
    if (foundRel.version === latestAvailable.version) return 0;
    const sortedReleases = [...allReleases].sort((a, b) => this.compareVersions(a.version, b.version));
    const foundIdx = sortedReleases.findIndex((r) => r.version === foundRel.version || r.id === foundRel.id);
    const latestIdx = sortedReleases.findIndex((r) => r.version === latestAvailable.version || r.id === latestAvailable.id);
    if (foundIdx === -1 || latestIdx === -1) return 0;
    return latestIdx - foundIdx;
  }

  private compareVersions(a: string, b: string): number {
    const aParts = a.replace(/[v-]/g, '.').split('.').map((p) => parseInt(p, 10) || 0);
    const bParts = b.replace(/[v-]/g, '.').split('.').map((p) => parseInt(p, 10) || 0);
    for (let i = 0; i < Math.max(aParts.length, bParts.length); i++) {
      const aVal = aParts[i] || 0;
      const bVal = bParts[i] || 0;
      if (aVal !== bVal) return aVal - bVal;
    }
    return 0;
  }

  private determineRecommendation(
    foundRel: CipRelease | undefined,
    latestAvailable: CipRelease | undefined,
    releasesBehind: number,
  ): UpdateRecommendation {
    if (!foundRel || !latestAvailable) return 'no-action';
    if (releasesBehind === 0) return 'no-action';
    if (releasesBehind > 0 && releasesBehind <= 2) return 'update-available';
    if (releasesBehind > 2 && releasesBehind <= 5) return 'security-update';
    return 'critical-update';
  }

  private async trackCves(
    installed: InstalledRelease,
    foundRel: CipRelease | undefined,
    allReleases: CipRelease[],
    evidence: EvidenceItem[],
  ): Promise<TrackedCve[]> {
    const trackedCves: TrackedCve[] = [];
    for (const [cveId, cveData] of SEED_CVE_DATA) {
      const trackedCve = await this.trackSingleCve(cveId, cveData, installed, foundRel, allReleases);
      trackedCves.push(trackedCve);
      evidence.push({ claim: `Tracked CVE: ${cveId} -> ${trackedCve.status}`, source: this.id });
    }
    return trackedCves;
  }

  private async trackSingleCve(
    cveId: string,
    cveData: { description: string; fixingCommits: string[]; severity?: string },
    installed: InstalledRelease,
    foundRel: CipRelease | undefined,
    allReleases: CipRelease[],
  ): Promise<TrackedCve> {
    const evidence: EvidenceItem[] = [{ claim: `Tracking CVE: ${cveId}`, source: this.id }];
    try {
      const cveRecord = await this.cveProvider.query(cveId);
      if (cveRecord) {
        evidence.push({ claim: `CVE record found: ${cveRecord.id}`, source: this.cveProvider.id });
      }
    } catch {}

    if (foundRel) {
      for (const commit of cveData.fixingCommits) {
        const fixedInRelease = COMMIT_TO_RELEASE_MAP.get(commit);
        if (fixedInRelease && fixedInRelease === foundRel.id) {
          return {
            cve: cveId,
            status: 'fixed',
            description: cveData.description,
            severity: cveData.severity,
            fixingCommits: cveData.fixingCommits,
            fixedInRelease: foundRel.version,
            evidence,
          };
        }
      }
    }

    for (const commit of cveData.fixingCommits) {
      const fixedInRelease = COMMIT_TO_RELEASE_MAP.get(commit);
      if (fixedInRelease) {
        const fixingRelease = allReleases.find((r) => r.id === fixedInRelease || r.version === fixedInRelease);
        if (fixingRelease) {
          return {
            cve: cveId,
            status: 'fixed-upstream',
            description: cveData.description,
            severity: cveData.severity,
            fixingCommits: cveData.fixingCommits,
            fixedInRelease: fixingRelease.version,
            evidence: [...evidence, { claim: `CVE fixed upstream in: ${fixingRelease.version}`, source: this.id }],
          };
        }
      }
    }

    return {
      cve: cveId,
      status: 'affected',
      description: cveData.description,
      severity: cveData.severity,
      fixingCommits: cveData.fixingCommits,
      evidence: [...evidence, { claim: 'Unable to determine exact status, assuming affected', source: this.id }],
    };
  }

  private calculateCveStats(trackedCves: TrackedCve[]): {
    total: number;
    fixed: number;
    fixedUpstream: number;
    affected: number;
    notAffected: number;
    unknown: number;
  } {
    const stats = { total: trackedCves.length, fixed: 0, fixedUpstream: 0, affected: 0, notAffected: 0, unknown: 0 };
    for (const cve of trackedCves) {
      switch (cve.status) {
        case 'fixed': stats.fixed++; break;
        case 'fixed-upstream': stats.fixedUpstream++; break;
        case 'affected': stats.affected++; break;
        case 'not-affected': stats.notAffected++; break;
        case 'unknown': stats.unknown++; break;
      }
    }
    return stats;
  }

  private getAvailableUpdates(foundRel: CipRelease | undefined, allReleases: CipRelease[]): CipRelease[] {
    if (!foundRel) return [];
    const sortedReleases = [...allReleases].sort((a, b) => this.compareVersions(a.version, b.version));
    const foundIdx = sortedReleases.findIndex((r) => r.version === foundRel.version || r.id === foundRel.id);
    if (foundIdx === -1) return [];
    return sortedReleases.slice(foundIdx + 1);
  }
}

export function createReleaseTrackerProvider(
  releaseProvider: ReleaseAnnouncementsProvider,
  cveProvider: CveProvider,
): ReleaseTrackerProviderType {
  return new ReleaseTrackerProvider(releaseProvider, cveProvider);
}
