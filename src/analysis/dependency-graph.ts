/**
 * Dependency Graph Engine (Module A3, Rules R1/R6).
 *
 * Builds and queries a dependency graph for kernel symbols, modules, drivers,
 * packages, and subsystems. This enables impact analysis and dependency
 * chain discovery for CVE triage and patch planning.
 *
 * Key principles:
 * - R1 (Upstream First): All data is derived from official sources (kernel
 *   config, /proc/modules, known subsystem mappings).
 * - R6 (ABI Stability): Tracks dependencies to ensure userspace ABI impact
 *   analysis is possible.
 * - Evidence-backed: Every edge in the graph carries evidence of how it was
 *   derived (config settings, module dependencies, symbol exports).
 *
 * The graph is built from:
 * 1. Kernel config: CONFIG_X symbols and their values (y/m/n)
 * 2. Loaded modules: from /proc/modules with their dependencies
 * 3. File-to-subsystem mappings: known mappings of kernel source paths to
 *    subsystems (e.g., fs/ext4 -> EXT4_FS)
 * 4. Symbol-to-module mappings: inferred from CONFIG symbols
 */

import type {
  DependencyEdge,
  DependencyGraph,
  DependencyNode,
  DependencyNodeType,
  DependencyProvider,
  DependencyQuery,
  DependencyQueryResult,
  EvidenceItem,
  KernelInventory,
  ModuleInfo,
} from '../engine/types.js';

/**
 * Mapping of kernel source file prefixes to subsystem CONFIG symbols.
 * This is a seed mapping; in production this would be data-driven from
 * Kconfig/Makefile analysis of the kernel tree.
 *
 * Rule R1: These mappings are derived from upstream kernel organization.
 */
const FILE_PREFIX_TO_SUBSYSTEM: Array<[prefix: string, configSymbol: string]> = [
  // Filesystems
  ['fs/ext4/', 'CONFIG_EXT4_FS'],
  ['fs/btrfs/', 'CONFIG_BTRFS_FS'],
  ['fs/xfs/', 'CONFIG_XFS_FS'],
  ['fs/f2fs/', 'CONFIG_F2FS_FS'],
  ['fs/nfs/', 'CONFIG_NFS_FS'],
  ['fs/cifs/', 'CONFIG_CIFS'],
  ['fs/overlayfs/', 'CONFIG_OVERLAY_FS'],
  
  // Networking
  ['net/core/', 'CONFIG_NET'],
  ['net/sched/', 'CONFIG_NET_SCHED'],
  ['net/ipv4/', 'CONFIG_INET'],
  ['net/ipv6/', 'CONFIG_IPV6'],
  ['net/netfilter/', 'CONFIG_NETFILTER'],
  ['net/wireless/', 'CONFIG_WIRELESS'],
  ['net/bluetooth/', 'CONFIG_BT'],
  ['net/8021q/', 'CONFIG_VLAN_8021Q'],
  
  // Device Drivers
  ['drivers/net/', 'CONFIG_NETDEVICES'],
  ['drivers/net/wireless/', 'CONFIG_WLAN'],
  ['drivers/net/ethernet/', 'CONFIG_ETHERNET'],
  ['drivers/usb/', 'CONFIG_USB'],
  ['drivers/pci/', 'CONFIG_PCI'],
  ['drivers/gpu/drm/', 'CONFIG_DRM'],
  ['drivers/input/', 'CONFIG_INPUT'],
  ['drivers/tty/', 'CONFIG_TTY'],
  ['drivers/block/', 'CONFIG_BLOCK'],
  ['drivers/scsi/', 'CONFIG_SCSI'],
  ['drivers/iommu/', 'CONFIG_IOMMU_SUPPORT'],
  ['drivers/md/', 'CONFIG_MD'],
  ['drivers/nvme/', 'CONFIG_NVME_CORE'],
  
  // Storage
  ['block/', 'CONFIG_BLOCK'],
  ['fs/block_dev/', 'CONFIG_BLK_DEV'],
  
  // Security
  ['security/', 'CONFIG_SECURITY'],
  ['security/apparmor/', 'CONFIG_SECURITY_APPARMOR'],
  ['security/selinux/', 'CONFIG_SECURITY_SELINUX'],
  
  // Memory Management
  ['mm/', 'CONFIG_MMU'],
  ['mm/slab/', 'CONFIG_SLAB'],
  
  // Virtualization
  ['virt/', 'CONFIG_VIRTUALIZATION'],
  ['arch/x86/kvm/', 'CONFIG_KVM'],
  
  // Crypto
  ['crypto/', 'CONFIG_CRYPTO'],
  
  // BPF
  ['kernel/bpf/', 'CONFIG_BPF_SYSCALL'],
  
  // Tracing
  ['kernel/trace/', 'CONFIG_TRACING'],
];

/**
 * Mapping of subsystem CONFIG symbols to their parent subsystems.
 * Used to build hierarchy in the graph.
 */
const SUBSYSTEM_HIERARCHY: Record<string, string[]> = {
  CONFIG_EXT4_FS: ['CONFIG_FS'],
  CONFIG_BTRFS_FS: ['CONFIG_FS'],
  CONFIG_XFS_FS: ['CONFIG_FS'],
  CONFIG_F2FS_FS: ['CONFIG_FS'],
  CONFIG_NFS_FS: ['CONFIG_FS', 'CONFIG_NET'],
  CONFIG_CIFS: ['CONFIG_FS', 'CONFIG_NET'],
  CONFIG_OVERLAY_FS: ['CONFIG_FS'],
  CONFIG_NETFILTER: ['CONFIG_NET'],
  CONFIG_NET_SCHED: ['CONFIG_NET'],
  CONFIG_INET: ['CONFIG_NET'],
  CONFIG_IPV6: ['CONFIG_NET'],
  CONFIG_WIRELESS: ['CONFIG_NET'],
  CONFIG_BT: ['CONFIG_NET'],
  CONFIG_VLAN_8021Q: ['CONFIG_NET'],
  CONFIG_NETDEVICES: ['CONFIG_NET'],
  CONFIG_WLAN: ['CONFIG_NETDEVICES'],
  CONFIG_ETHERNET: ['CONFIG_NETDEVICES'],
  CONFIG_USB: [],
  CONFIG_PCI: [],
  CONFIG_DRM: ['CONFIG_GRAPHICS'],
  CONFIG_INPUT: [],
  CONFIG_TTY: [],
  CONFIG_BLOCK: [],
  CONFIG_SCSI: ['CONFIG_BLOCK'],
  CONFIG_IOMMU_SUPPORT: [],
  CONFIG_MD: ['CONFIG_BLOCK'],
  CONFIG_NVME_CORE: ['CONFIG_BLOCK'],
  CONFIG_SECURITY: [],
  CONFIG_SECURITY_APPARMOR: ['CONFIG_SECURITY'],
  CONFIG_SECURITY_SELINUX: ['CONFIG_SECURITY'],
  CONFIG_MMU: [],
  CONFIG_SLAB: ['CONFIG_MMU'],
  CONFIG_VIRTUALIZATION: [],
  CONFIG_KVM: ['CONFIG_VIRTUALIZATION'],
  CONFIG_CRYPTO: [],
  CONFIG_BPF_SYSCALL: [],
  CONFIG_TRACING: [],
};

/**
 * Known kernel symbols and their exporting modules.
 * In production, this would be populated from:
 * - /proc/kallsyms (for loaded symbols)
 * - Module symbol tables (modinfo)
 * - vmlinux symbol table
 *
 * For now, we use a conservative mapping based on subsystem configs.
 */
const SYMBOL_TO_MODULE: Record<string, string> = {
  // Example symbols - in practice these would be extracted from the system
  'ext4_file_operations': 'ext4',
  'btrfs_file_operations': 'btrfs',
  'usb_submit_urb': 'usbcore',
  'nvme_submit_cmd': 'nvme',
};

/**
 * Dependency Graph Provider (Module A3).
 * Builds and queries dependency graphs from kernel inventory data.
 */
export class DependencyGraphProvider implements DependencyProvider {
  readonly id = 'dependency-graph';

  async init(): Promise<void> {
    // No initialization needed
  }

  /**
   * Build a dependency graph from the given kernel inventory.
   * 
   * Nodes include:
   * - Subsystems (from CONFIG symbols)
   * - Modules (from /proc/modules)
   * - Drivers (inferred from module names and config)
   * - Symbols (inferred from config and known mappings)
   * 
   * Edges represent:
   * - depends-on: module dependencies
   * - requires: config dependencies (CONFIG_A requires CONFIG_B)
   * - uses: symbol usage
   * - built-from: source file to module
   * - part-of: subsystem hierarchy
   */
  async buildGraph(inventory: KernelInventory): Promise<DependencyGraph> {
    const nodes: DependencyNode[] = [];
    const edges: DependencyEdge[] = [];
    const evidence: EvidenceItem[] = [];

    // Track node IDs to avoid duplicates
    const nodeIdMap = new Map<string, DependencyNode>();

    // Helper to add a node
    const addNode = (node: DependencyNode): string => {
      if (!nodeIdMap.has(node.id)) {
        nodeIdMap.set(node.id, node);
        nodes.push(node);
      }
      return node.id;
    };

    // Helper to add an edge
    const addEdge = (from: string, to: string, type: DependencyEdge['type'], evidenceStr?: string): void => {
      edges.push({ from, to, type, evidence: evidenceStr });
      evidence.push({
        claim: `${type.replace('-', ' ')}: ${from} -> ${to}`,
        source: evidenceStr || 'dependency-graph',
      });
    };

    // 1. Add subsystem nodes from kernel config
    evidence.push({
      claim: `Building dependency graph from kernel config (${Object.keys(inventory.config).length} symbols)`,
      source: inventory.configSource || 'kernel-config',
    });

    for (const [configSymbol, value] of Object.entries(inventory.config)) {
      // Only consider enabled or modular subsystems
      if (value === 'n') continue;

      const nodeId = configSymbol;
      const node: DependencyNode = {
        id: nodeId,
        type: 'subsystem',
        name: configSymbol.replace(/^CONFIG_/, ''),
        status: value,
      };
      addNode(node);

      // Add hierarchy edges (part-of)
      const parents = SUBSYSTEM_HIERARCHY[configSymbol] || [];
      for (const parent of parents) {
        if (inventory.config[parent] !== undefined) {
          const parentId = parent;
          const parentNode: DependencyNode = {
            id: parentId,
            type: 'subsystem',
            name: parent.replace(/^CONFIG_/, ''),
            status: inventory.config[parent],
          };
          addNode(parentNode);
          addEdge(nodeId, parentId, 'part-of', `Hierarchy: ${configSymbol} is part of ${parent}`);
        }
      }
    }

    // 2. Add module nodes from /proc/modules
    evidence.push({
      claim: `Adding ${inventory.modules.length} loaded modules`,
      source: '/proc/modules',
    });

    for (const module of inventory.modules) {
      const nodeId = `module:${module.name}`;
      const node: DependencyNode = {
        id: nodeId,
        type: 'module',
        name: module.name,
        status: 'loaded',
        source: '/proc/modules',
      };
      const moduleId = addNode(node);

      // Add dependencies from module's usedBy
      for (const usedBy of module.usedBy) {
        if (usedBy && usedBy !== '0') {
          const usedById = `module:${usedBy}`;
          const usedByNode: DependencyNode = {
            id: usedById,
            type: 'module',
            name: usedBy,
            status: 'referenced',
            source: '/proc/modules',
          };
          addNode(usedByNode);
          addEdge(moduleId, usedById, 'depends-on', `Module ${module.name} used by ${usedBy}`);
        }
      }

      // Map module to subsystem based on name patterns
      const subsystem = mapModuleToSubsystem(module.name, inventory.config);
      if (subsystem) {
        addEdge(moduleId, subsystem, 'part-of', `Module ${module.name} belongs to subsystem ${subsystem}`);
      }
    }

    // 3. Add driver nodes (modules that are drivers)
    for (const module of inventory.modules) {
      if (isDriverModule(module.name)) {
        const driverId = `driver:${module.name}`;
        const node: DependencyNode = {
          id: driverId,
          type: 'driver',
          name: module.name,
          status: 'loaded',
          source: '/proc/modules',
        };
        const driverNodeId = addNode(node);
        const moduleId = `module:${module.name}`;
        addEdge(driverNodeId, moduleId, 'built-from', `Driver ${module.name} built as module`);
      }
    }

    // 4. Add symbol nodes and their relationships
    // For each enabled config, add a symbol node
    for (const [configSymbol, value] of Object.entries(inventory.config)) {
      if (value === 'n') continue;

      const symbolId = `symbol:${configSymbol}`;
      const node: DependencyNode = {
        id: symbolId,
        type: 'symbol',
        name: configSymbol,
        status: value,
        source: inventory.configSource,
      };
      const symbolNodeId = addNode(node);

      // Connect symbol to subsystem
      addEdge(symbolNodeId, configSymbol, 'part-of', `Symbol ${configSymbol} belongs to subsystem`);
    }

    // 5. Add file nodes from affected files (if available in context)
    // This would be populated when building graph for a specific CVE
    // For now, we add known kernel file paths based on subsystems
    for (const [prefix, configSymbol] of FILE_PREFIX_TO_SUBSYSTEM) {
      if (inventory.config[configSymbol] !== undefined && inventory.config[configSymbol] !== 'n') {
        const fileId = `file:${prefix}`;
        const node: DependencyNode = {
          id: fileId,
          type: 'file',
          name: prefix,
          source: 'file-to-subsystem-mapping',
        };
        const fileNodeId = addNode(node);
        addEdge(fileNodeId, configSymbol, 'part-of', `File ${prefix} belongs to ${configSymbol}`);
      }
    }

    return {
      nodes,
      edges,
      builtAt: new Date().toISOString(),
      source: 'system-inventory',
    };
  }

  /**
   * Query the dependency graph.
   */
  async queryGraph(query: DependencyQuery, graph?: DependencyGraph): Promise<DependencyQueryResult> {
    const effectiveGraph = graph || (await this.buildGraphFromEmpty());
    const evidence: EvidenceItem[] = [];

    switch (query.queryType) {
      case 'impact-analysis':
        return this.queryImpactAnalysis(query, effectiveGraph, evidence);
      case 'dependency-chain':
        return this.queryDependencyChain(query, effectiveGraph, evidence);
      case 'subgraph':
        return this.querySubgraph(query, effectiveGraph, evidence);
      case 'path':
        return this.queryPath(query, effectiveGraph, evidence);
      default:
        throw new Error(`Unknown query type: ${(query as DependencyQuery).queryType}`);
    }
  }

  /**
   * Query: What depends on these nodes? (Impact analysis)
   */
  private queryImpactAnalysis(
    query: DependencyQuery,
    graph: DependencyGraph,
    evidence: EvidenceItem[],
  ): DependencyQueryResult {
    if (!query.nodeIds || query.nodeIds.length === 0) {
      throw new Error('impact-analysis requires nodeIds');
    }

    const impacted = new Set<string>();
    const visited = new Set<string>();
    const queue = [...query.nodeIds];

    // BFS: find all nodes that have edges TO our query nodes (reverse traversal)
    while (queue.length > 0) {
      const nodeId = queue.shift()!;
      if (visited.has(nodeId)) continue;
      visited.add(nodeId);

      // Find all edges where 'to' is our node (i.e., someone depends on it)
      for (const edge of graph.edges) {
        if (edge.to === nodeId && !visited.has(edge.from)) {
          impacted.add(edge.from);
          queue.push(edge.from);
        }
      }
    }

    // Build subgraph of impacted nodes
    const impactedNodes = graph.nodes.filter((n) => impacted.has(n.id));
    const relevantEdges = graph.edges.filter(
      (e) => impacted.has(e.from) || impacted.has(e.to),
    );

    evidence.push({
      claim: `Impact analysis: ${impacted.size} nodes depend on ${query.nodeIds.join(', ')}`,
      source: 'dependency-graph-query',
    });

    return {
      query,
      nodes: impactedNodes,
      edges: relevantEdges,
      impactedNodes: Array.from(impacted),
      evidence,
    };
  }

  /**
   * Query: What do these nodes depend on? (Dependency chain)
   */
  private queryDependencyChain(
    query: DependencyQuery,
    graph: DependencyGraph,
    evidence: EvidenceItem[],
  ): DependencyQueryResult {
    if (!query.nodeIds || query.nodeIds.length === 0) {
      throw new Error('dependency-chain requires nodeIds');
    }

    const dependencies = new Set<string>();
    const visited = new Set<string>();
    const queue = [...query.nodeIds];
    const maxDepth = query.maxDepth ?? 10;

    // BFS: find all nodes that our query nodes depend on
    let currentDepth = 0;
    while (queue.length > 0 && currentDepth < maxDepth) {
      const levelSize = queue.length;
      for (let i = 0; i < levelSize; i++) {
        const nodeId = queue.shift()!;
        if (visited.has(nodeId)) continue;
        visited.add(nodeId);

        // Find all edges where 'from' is our node (i.e., our node depends on something)
        for (const edge of graph.edges) {
          if (edge.from === nodeId && !visited.has(edge.to)) {
            dependencies.add(edge.to);
            queue.push(edge.to);
          }
        }
      }
      currentDepth++;
    }

    // Build subgraph of dependency nodes
    const dependencyNodes = graph.nodes.filter((n) => dependencies.has(n.id));
    const relevantEdges = graph.edges.filter(
      (e) => dependencies.has(e.from) || dependencies.has(e.to),
    );

    evidence.push({
      claim: `Dependency chain: ${dependencies.size} nodes are dependencies of ${query.nodeIds.join(', ')}`,
      source: 'dependency-graph-query',
    });

    return {
      query,
      nodes: dependencyNodes,
      edges: relevantEdges,
      dependencyNodes: Array.from(dependencies),
      evidence,
    };
  }

  /**
   * Query: Get subgraph containing these nodes
   */
  private querySubgraph(
    query: DependencyQuery,
    graph: DependencyGraph,
    evidence: EvidenceItem[],
  ): DependencyQueryResult {
    if (!query.nodeIds || query.nodeIds.length === 0) {
      throw new Error('subgraph requires nodeIds');
    }

    const subgraphNodes = new Set<string>();
    const subgraphEdges = new Set<DependencyEdge>();

    // Add query nodes
    for (const nodeId of query.nodeIds) {
      subgraphNodes.add(nodeId);
    }

    // Add all edges between subgraph nodes
    for (const edge of graph.edges) {
      if (subgraphNodes.has(edge.from) || subgraphNodes.has(edge.to)) {
        subgraphEdges.add(edge);
        subgraphNodes.add(edge.from);
        subgraphNodes.add(edge.to);
      }
    }

    // Get the actual node objects
    const resultNodes = graph.nodes.filter((n) => subgraphNodes.has(n.id));

    evidence.push({
      claim: `Subgraph: ${resultNodes.length} nodes, ${subgraphEdges.size} edges`,
      source: 'dependency-graph-query',
    });

    return {
      query,
      nodes: resultNodes,
      edges: Array.from(subgraphEdges),
      evidence,
    };
  }

  /**
   * Query: Find paths between nodes
   */
  private queryPath(
    query: DependencyQuery,
    graph: DependencyGraph,
    evidence: EvidenceItem[],
  ): DependencyQueryResult {
    if (!query.startId || !query.endId) {
      throw new Error('path query requires startId and endId');
    }

    const paths: string[][] = [];
    const visited = new Set<string>();
    const maxDepth = query.maxDepth ?? 10;

    // DFS to find all paths from start to end
    const dfs = (current: string, path: string[], depth: number): void => {
      if (depth > maxDepth) return;
      if (current === query.endId!) {
        paths.push([...path, current]);
        return;
      }
      if (visited.has(current)) return;
      visited.add(current);

      // Follow edges from current node
      for (const edge of graph.edges) {
        if (edge.from === current) {
          path.push(current);
          dfs(edge.to, path, depth + 1);
          path.pop();
        }
      }
      visited.delete(current);
    };

    dfs(query.startId, [], 0);

    // Build subgraph of nodes in paths
    const pathNodes = new Set<string>();
    for (const path of paths) {
      for (const nodeId of path) {
        pathNodes.add(nodeId);
      }
    }

    const resultNodes = graph.nodes.filter((n) => pathNodes.has(n.id));
    const relevantEdges = graph.edges.filter(
      (e) => pathNodes.has(e.from) && pathNodes.has(e.to),
    );

    evidence.push({
      claim: `Found ${paths.length} path(s) from ${query.startId} to ${query.endId}`,
      source: 'dependency-graph-query',
    });

    return {
      query,
      nodes: resultNodes,
      edges: relevantEdges,
      paths,
      evidence,
    };
  }

  /**
   * Build an empty graph (for when no inventory is available)
   */
  private async buildGraphFromEmpty(): Promise<DependencyGraph> {
    return {
      nodes: [],
      edges: [],
      builtAt: new Date().toISOString(),
      source: 'empty',
    };
  }
}

/**
 * Map a module name to its subsystem based on known patterns.
 */
function mapModuleToSubsystem(moduleName: string, config: Record<string, string>): string | null {
  // Try exact matches first
  for (const [, configSymbol] of FILE_PREFIX_TO_SUBSYSTEM) {
    const baseName = configSymbol.replace(/^CONFIG_/, '');
    if (moduleName.toLowerCase().includes(baseName.toLowerCase())) {
      return configSymbol;
    }
  }

  // Try prefix matches
  for (const [prefix, configSymbol] of FILE_PREFIX_TO_SUBSYSTEM) {
    const prefixParts = prefix.replace(/\/$/, '').split('/');
    const moduleParts = moduleName.split('_');
    
    // Check if any prefix part matches any module part
    for (const prefixPart of prefixParts) {
      for (const modulePart of moduleParts) {
        if (modulePart.toLowerCase().includes(prefixPart.toLowerCase())) {
          return configSymbol;
        }
      }
    }
  }

  return null;
}

/**
 * Check if a module name suggests it's a driver.
 */
function isDriverModule(moduleName: string): boolean {
  const driverPatterns = [
    'usb', 'pci', 'sata', 'ahci', 'nvme', 'scsi', 'ata',
    'eth', 'net', 'wifi', 'bluetooth', 'bt', 'serial',
    'gpu', 'drm', 'video', 'input', 'keyboard', 'mouse',
    'storage', 'block', 'md', 'raid',
    'i2c', 'spi', 'gpio', 'hwmon',
  ];
  
  const lowerName = moduleName.toLowerCase();
  return driverPatterns.some((pattern) => lowerName.includes(pattern));
}

/**
 * Build a dependency graph from a kernel inventory.
 * This is a convenience function for direct use without the provider.
 */
export function buildDependencyGraph(inventory: KernelInventory): Promise<DependencyGraph> {
  const provider = new DependencyGraphProvider();
  return provider.buildGraph(inventory);
}

/**
 * Query a dependency graph.
 * This is a convenience function for direct use without the provider.
 */
export function queryDependencyGraph(
  query: DependencyQuery,
  graph: DependencyGraph,
): Promise<DependencyQueryResult> {
  const provider = new DependencyGraphProvider();
  return provider.queryGraph(query, graph);
}
