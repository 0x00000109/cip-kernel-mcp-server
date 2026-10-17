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

// =============================================================================
// Patch Builder Types (Module W1, Rules R1/R4/R5)
// =============================================================================

/**
 * Patch builder options for creating backports.
 * Rule R4: Backports must reference the upstream commit ID in a separate
 * `commit <sha> upstream` changelog line; deviations and conflict resolutions
 * must be documented.
 * Rule R5: Sources not binaries - we work with source patches only.
 */
export interface PatchBuilderOptions {
  /** Output directory for draft patches (default: staging directory). */
  outputDir?: string;
  /** Base kernel version for the backport (e.g., '5.10.209-cip50'). */
  baseVersion?: string;
  /** Target CIP branch (e.g., 'linux-5.10.y-cip'). */
  targetBranch?: string;
  /** Whether to include conflict resolution markers. */
  includeConflictMarkers?: boolean;
}

/** Conflict type in a backport. */
export type ConflictType = 
  | 'context-change'      // Context around the change is different
  | 'symbol-renamed'      // Symbol or function was renamed
  | 'file-moved'          // File was moved to a different location
  | 'code-restructured'   // Code structure changed significantly
  | 'dependency-added'    // New dependencies were added
  | 'api-changed'         // API changed between versions
  | 'manual-resolution'   // Required manual resolution
  ;

/** A single conflict found during backporting. */
export interface BackportConflict {
  /** Type of conflict. */
  type: ConflictType;
  /** File where the conflict was found. */
  file: string;
  /** Line number (if applicable). */
  line?: number;
  /** Description of the conflict. */
  description: string;
  /** The conflicting code from the upstream patch. */
  upstreamCode?: string;
  /** The conflicting code from the target branch. */
  targetCode?: string;
  /** Suggested resolution (if available). */
  suggestedResolution?: string;
  /** Whether this conflict was auto-resolved. */
  autoResolved?: boolean;
}

/** Resolution strategy for conflicts. */
export type ConflictResolutionStrategy = 
  | 'skip'              // Skip this patch entirely
  | 'manual'            // Require manual resolution
  | 'auto-merge'        // Attempt automatic merge
  | 'use-upstream'      // Use upstream version
  | 'use-target'        // Use target version
  ;

/** Statistics for a backport operation. */
export interface BackportStatistics {
  /** Total number of patches processed. */
  totalPatches: number;
  /** Number of patches successfully backported. */
  successful: number;
  /** Number of patches with conflicts. */
  withConflicts: number;
  /** Number of patches that failed. */
  failed: number;
  /** Total number of conflicts found. */
  totalConflicts: number;
  /** Number of conflicts auto-resolved. */
  autoResolved: number;
  /** Number of conflicts requiring manual resolution. */
  manualResolutionRequired: number;
}

/** A draft backport patch file. */
export interface DraftPatch {
  /** Path to the draft patch file. */
  path: string;
  /** Name of the patch. */
  name: string;
  /** CVE ID this patch addresses (if applicable). */
  cve?: string;
  /** Upstream commit SHA this patch is based on. */
  upstreamSha: string;
  /** Target branch for the backport. */
  targetBranch: string;
  /** Whether the patch was successfully created. */
  success: boolean;
  /** Conflicts found during backporting. */
  conflicts: BackportConflict[];
  /** Statistics for this patch. */
  stats: BackportStatistics;
  /** The generated patch content (if success). */
  content?: string;
  /** Error message (if failed). */
  error?: string;
  /** Evidence chain for the backport. */
  evidence: EvidenceItem[];
}

/** Result of a backport operation. */
export interface BackportResult {
  /** CVE ID this backport is for. */
  cve: string;
  /** Upstream commit SHA being backported. */
  upstreamSha: string;
  /** Target branch. */
  targetBranch: string;
  /** Output directory where patches were created. */
  outputDir: string;
  /** List of draft patches created. */
  draftPatches: DraftPatch[];
  /** Overall statistics. */
  stats: BackportStatistics;
  /** Overall success status. */
  success: boolean;
  /** Any errors encountered. */
  errors: string[];
  /** Evidence chain for the entire operation. */
  evidence: EvidenceItem[];
}

/** Provider for backport/patch building operations. */
export interface PatchBuilderProvider extends Provider {
  /**
   * Draft a backport for a given CVE and upstream commit.
   * Rule R1: Never invent patches - only backport existing upstream fixes.
   * Rule R4: Backports must follow kernel backport format with commit <sha> upstream.
   * Rule R5: Work with sources, not binaries.
   */
  draftBackport(
    cveId: string,
    upstreamSha: string,
    options?: PatchBuilderOptions,
  ): Promise<BackportResult>;
}

