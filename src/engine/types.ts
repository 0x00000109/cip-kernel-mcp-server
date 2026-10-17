/**
 * Core domain types shared across engine, providers and analysis modules.
 * See docs/ARCHITECTURE.md for module IDs and the rules (R1-R8) each serves.
 */

export interface DistroInfo {
  id?: string;
  name?: string;
  version?: string;
}

export interface ModuleInfo {
  name: string;
  sizeKb: number;
  usedBy: string[];
}

/** Result of the system-inventory provider (module P1). */
export interface KernelInventory {
  kernelVersion: string;
  arch: string;
  /** CONFIG_X => 'y' | 'm' | 'n' (value strings kept as found in /proc/config.gz). */
  config: Record<string, string>;
  modules: ModuleInfo[];
  distro: DistroInfo;
  packages: string[];
  collectedAt: string;
}

export interface AffectedEntry {
  /** Path inside the kernel tree, e.g. 'fs/ext4/inode.c'. */
  file: string;
}

export interface FixingCommit {
  sha: string;
  branches: string[];
  description?: string;
}

export type CveSource = 'kernel.org-cve' | 'nvd' | 'debian-security-tracker';

/**
 * Normalized CVE record. Rule R3: kernel CVEs are commit-tracked, so fixing
 * commits are the primary key for provenance, not the CVE id alone.
 */
export interface CveRecord {
  id: string;
  description: string;
  source: CveSource;
  affected: AffectedEntry[];
  fixingCommits: FixingCommit[];
  fetchedAt: string;
}

export type ApplicabilityVerdict = 'applicable' | 'not-applicable' | 'unknown';

/** Rule R3/R8: every verdict must carry an auditable evidence chain. */
export interface EvidenceItem {
  claim: string;
  source: string;
}

export interface ApplicabilityResult {
  cve: string;
  verdict: ApplicabilityVerdict;
  confidence: 'high' | 'medium' | 'low';
  evidence: EvidenceItem[];
  rationale: string;
}

export interface PatchCandidate {
  upstreamSha: string;
  branch: string;
  title: string;
  cve?: string;
}

export interface Provider {
  readonly id: string;
  init(): Promise<void>;
}

export interface InventoryProvider extends Provider {
  collect(): Promise<KernelInventory>;
}

export interface CveProvider extends Provider {
  query(cveId: string): Promise<CveRecord | undefined>;
}

export interface PatchProvider extends Provider {
  findPatches(cveId: string): Promise<PatchCandidate[]>;
}
