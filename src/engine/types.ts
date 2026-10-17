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

/**
 * How the running kernel's config was resolved (module P1): procfs when
 * CONFIG_IKCONFIG_PROC is set, the distro-shipped /boot config, the IKCONFIG
 * blob extracted from the kernel image, or 'none' when unavailable.
 */
export type ConfigSource = 'proc-config-gz' | 'boot-config' | 'ikconfig' | 'none';

/** Result of the system-inventory provider (module P1). */
export interface KernelInventory {
  kernelVersion: string;
  arch: string;
  /** CONFIG_X => 'y' | 'm' | 'n' (value strings kept as found in the config). */
  config: Record<string, string>;
  /** Where the config was resolved from (fallback chain, module P1). */
  configSource?: ConfigSource;
  modules: ModuleInfo[];
  distro: DistroInfo;
  packages: string[];
  collectedAt: string;
}

export interface AffectedEntry {
  /** Path inside the kernel tree, e.g. 'fs/ext4/inode.c'. */
  file: string;
}

/**
 * Affected version range for one stable series, derived from the kernel.org
 * CVE record (cpeApplicability). `fixedIn` is versionEndExcluding; a range
 * without `fixedIn` is an open, unfixed range for that branch (Rule R3).
 */
export interface AffectedRange {
  /** Stable series, e.g. '5.10'. */
  series: string;
  /** Stable branch label, e.g. 'linux-5.10.y'. */
  branch: string;
  startIncluding?: string;
  fixedIn?: string;
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
  affectedRanges?: AffectedRange[];
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
  /** Upstream fixing commit, when known (may be unresolved at record level). */
  upstreamSha?: string;
  /** Backport commit on a CIP branch, resolved via the linux-cip mirror (R4). */
  patchSha?: string;
  branch: string;
  title: string;
  cve?: string;
  /** Stable release that contains the fix, e.g. '5.10.163'. */
  fixedIn?: string;
  /** First tagged CIP release containing the backport, e.g. 'v5.10.163-cip35'. */
  cipRelease?: string;
  /** Browsable commit URL (kernel.org cgit for the linux-cip mirror). */
  url?: string;
  /** How the candidate was resolved. */
  source?: 'cip-mirror' | 'cve-record';
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

// =============================================================================
// Dependency Graph Types (Module A3, Rule R6)
// =============================================================================

/**
 * Node types in the dependency graph.
 * Symbols: kernel symbols (EXPORT_SYMBOL)
 * Modules: kernel modules (from /proc/modules or modinfo)
 * Drivers: device drivers (often built as modules)
 * Packages: distro packages (dpkg, rpm)
 * Subsystems: kernel subsystems (e.g., NET, USB, DRM)
 * Files: source files in the kernel tree
 */
export type DependencyNodeType = 'symbol' | 'module' | 'driver' | 'package' | 'subsystem' | 'file';

/** A node in the dependency graph. */
export interface DependencyNode {
  id: string;
  type: DependencyNodeType;
  name: string;
  /** For symbols: the module that exports it. For modules: the file path. */
  source?: string;
  /** For modules: loaded status. For packages: installed version. */
  status?: string;
}

/** An edge between two nodes in the dependency graph. */
export interface DependencyEdge {
  from: string; // node id
  to: string;   // node id
  type: 'depends-on' | 'requires' | 'uses' | 'built-from' | 'part-of';
  /** Evidence for this edge (e.g., 'CONFIG_X=y', 'modinfo deps', 'symbol table'). */
  evidence?: string;
}

/** The dependency graph structure. */
export interface DependencyGraph {
  nodes: DependencyNode[];
  edges: DependencyEdge[];
  /** Timestamp when the graph was built. */
  builtAt: string;
  /** Source of the graph (e.g., 'system-inventory', 'cve-record'). */
  source: string;
}

/** Query types for the dependency graph. */
export type DependencyQueryType = 
  | 'impact-analysis'    // What depends on this node?
  | 'dependency-chain'  // What does this node depend on?
  | 'subgraph'          // Subgraph containing these nodes
  | 'path'              // Find paths between nodes
  ;

/** Parameters for graph queries. */
export interface DependencyQuery {
  queryType: DependencyQueryType;
  /** Node IDs to start from (for impact-analysis, dependency-chain, subgraph). */
  nodeIds?: string[];
  /** For path queries: start and end node IDs. */
  startId?: string;
  endId?: string;
  /** Maximum depth for traversal. */
  maxDepth?: number;
}

/** Result of a dependency graph query. */
export interface DependencyQueryResult {
  query: DependencyQuery;
  nodes: DependencyNode[];
  edges: DependencyEdge[];
  /** For impact-analysis: nodes that depend on the query nodes. */
  impactedNodes?: string[];
  /** For dependency-chain: nodes that the query nodes depend on. */
  dependencyNodes?: string[];
  /** For path queries: list of paths from start to end. */
  paths?: string[][];
  /** Evidence chain for the query result. */
  evidence: EvidenceItem[];
}

/** Provider for dependency graph data. */
export interface DependencyProvider extends Provider {
  /** Build a dependency graph from the given inventory. */
  buildGraph(inventory: KernelInventory): Promise<DependencyGraph>;
  /** Query the dependency graph. */
  queryGraph(query: DependencyQuery, graph?: DependencyGraph): Promise<DependencyQueryResult>;
}
