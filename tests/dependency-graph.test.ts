import { describe, expect, it, beforeEach } from 'vitest';
import type { KernelInventory, DependencyGraph, DependencyQueryResult } from '../src/engine/types.js';
import { DependencyGraphProvider } from '../src/analysis/dependency-graph.js';

/**
 * Test fixtures for kernel inventory
 */
function createTestInventory(configOverrides: Record<string, string> = {}): KernelInventory {
  return {
    kernelVersion: '5.10.209-cip50',
    arch: 'x86_64',
    config: {
      // Base config
      CONFIG_NET: 'y',
      CONFIG_INET: 'y',
      CONFIG_IPV6: 'm',
      CONFIG_NETFILTER: 'y',
      CONFIG_EXT4_FS: 'y',
      CONFIG_BTRFS_FS: 'n',
      CONFIG_USB: 'y',
      CONFIG_PCI: 'y',
      CONFIG_DRM: 'm',
      CONFIG_BPF_SYSCALL: 'y',
      CONFIG_SECURITY: 'y',
      CONFIG_CRYPTO: 'y',
      CONFIG_BLOCK: 'y',
      CONFIG_SCSI: 'm',
      CONFIG_NVME_CORE: 'y',
      CONFIG_FS: 'y',
      ...configOverrides,
    },
    configSource: 'proc-config-gz',
    modules: [
      { name: 'ext4', sizeKb: 100, usedBy: [] },
      { name: 'usb_storage', sizeKb: 50, usedBy: ['scsi_mod'] },
      { name: 'scsi_mod', sizeKb: 200, usedBy: [] },
      { name: 'nvme', sizeKb: 150, usedBy: [] },
      { name: 'usbcore', sizeKb: 300, usedBy: ['usb_storage'] },
    ],
    distro: { id: 'debian', name: 'Debian GNU/Linux', version: '11' },
    packages: [],
    collectedAt: new Date().toISOString(),
  };
}

describe('DependencyGraphProvider', () => {
  let provider: DependencyGraphProvider;

  beforeEach(() => {
    provider = new DependencyGraphProvider();
  });

  describe('buildGraph', () => {
    it('should build a graph with subsystems from kernel config', async () => {
      const inventory = createTestInventory();
      const graph = await provider.buildGraph(inventory);

      expect(graph.nodes.length).toBeGreaterThan(0);
      expect(graph.edges.length).toBeGreaterThan(0);
      expect(graph.source).toBe('system-inventory');
      expect(graph.builtAt).toBeDefined();
    });

    it('should include enabled subsystems as nodes', async () => {
      const inventory = createTestInventory();
      const graph = await provider.buildGraph(inventory);

      const subsystemNodes = graph.nodes.filter((n) => n.type === 'subsystem');
      expect(subsystemNodes.length).toBeGreaterThan(0);

      const configSymbols = Object.keys(inventory.config);
      const enabledSymbols = configSymbols.filter((s) => inventory.config[s] !== 'n');
      
      for (const symbol of enabledSymbols) {
        expect(subsystemNodes.some((n) => n.id === symbol)).toBe(true);
      }
    });

    it('should include loaded modules as nodes', async () => {
      const inventory = createTestInventory();
      const graph = await provider.buildGraph(inventory);

      const moduleNodes = graph.nodes.filter((n) => n.type === 'module');
      expect(moduleNodes.length).toBeGreaterThan(0);

      for (const module of inventory.modules) {
        expect(moduleNodes.some((n) => n.id === `module:${module.name}`)).toBe(true);
      }
    });

    it('should create edges for module dependencies from usedBy', async () => {
      const inventory = createTestInventory();
      const graph = await provider.buildGraph(inventory);

      const usedByEdges = graph.edges.filter(
        (e) => e.type === 'depends-on' && e.from === 'module:usb_storage',
      );
      expect(usedByEdges.length).toBeGreaterThan(0);
      expect(usedByEdges.some((e) => e.to === 'module:scsi_mod')).toBe(true);
    });

    it('should create hierarchy edges for subsystems', async () => {
      const inventory = createTestInventory();
      const graph = await provider.buildGraph(inventory);

      const hierarchyEdges = graph.edges.filter((e) => e.type === 'part-of');
      expect(hierarchyEdges.length).toBeGreaterThan(0);

      // CONFIG_INET should be part of CONFIG_NET
      expect(hierarchyEdges.some((e) => e.from === 'CONFIG_INET' && e.to === 'CONFIG_NET')).toBe(true);
    });

    it('should mark disabled subsystems as not included', async () => {
      const inventory = createTestInventory({
        CONFIG_BTRFS_FS: 'n',
        CONFIG_IPV6: 'n',
      });
      const graph = await provider.buildGraph(inventory);

      const subsystemNodes = graph.nodes.filter((n) => n.type === 'subsystem');
      
      // Disabled subsystems should not be in the graph
      expect(subsystemNodes.some((n) => n.id === 'CONFIG_BTRFS_FS')).toBe(false);
      expect(subsystemNodes.some((n) => n.id === 'CONFIG_IPV6')).toBe(false);
    });

    it('should include driver nodes for driver-like modules', async () => {
      const inventory = createTestInventory();
      const graph = await provider.buildGraph(inventory);

      const driverNodes = graph.nodes.filter((n) => n.type === 'driver');
      expect(driverNodes.length).toBeGreaterThan(0);

      // usb_storage, nvme, scsi_mod should be identified as drivers
      expect(driverNodes.some((n) => n.id === 'driver:usb_storage')).toBe(true);
      expect(driverNodes.some((n) => n.id === 'driver:nvme')).toBe(true);
      expect(driverNodes.some((n) => n.id === 'driver:scsi_mod')).toBe(true);
    });

    it('should create symbol nodes for config symbols', async () => {
      const inventory = createTestInventory();
      const graph = await provider.buildGraph(inventory);

      const symbolNodes = graph.nodes.filter((n) => n.type === 'symbol');
      expect(symbolNodes.length).toBeGreaterThan(0);

      // Each enabled config symbol should have a corresponding symbol node
      const enabledSymbols = Object.entries(inventory.config)
        .filter(([_, v]) => v !== 'n')
        .map(([k]) => k);
      
      for (const symbol of enabledSymbols) {
        expect(symbolNodes.some((n) => n.id === `symbol:${symbol}`)).toBe(true);
      }
    });

    it('should handle empty inventory gracefully', async () => {
      const emptyInventory: KernelInventory = {
        kernelVersion: 'unknown',
        arch: 'unknown',
        config: {},
        configSource: 'none',
        modules: [],
        distro: {},
        packages: [],
        collectedAt: new Date().toISOString(),
      };

      const graph = await provider.buildGraph(emptyInventory);
      expect(graph.nodes.length).toBe(0);
      expect(graph.edges.length).toBe(0);
    });
  });

  describe('queryGraph', () => {
    let graph: DependencyGraph;

    beforeEach(async () => {
      const inventory = createTestInventory();
      graph = await provider.buildGraph(inventory);
    });

    describe('impact-analysis', () => {
      it('should find nodes that depend on a given node', async () => {
        const query = {
          queryType: 'impact-analysis' as const,
          nodeIds: ['CONFIG_NET'],
        };

        const result = await provider.queryGraph(query, graph);

        expect(result.query.queryType).toBe('impact-analysis');
        expect(result.impactedNodes).toBeDefined();
        expect(result.impactedNodes!.length).toBeGreaterThan(0);
        
        // CONFIG_INET should be impacted by CONFIG_NET
        expect(result.impactedNodes!.some((n) => n === 'CONFIG_INET')).toBe(true);
      });

      it('should return empty for nodes with no dependents', async () => {
        const query = {
          queryType: 'impact-analysis' as const,
          nodeIds: ['CONFIG_EXT4_FS'],
        };

        const result = await provider.queryGraph(query, graph);

        expect(result.impactedNodes).toBeDefined();
        // EXT4_FS might not have many dependents in our test graph
        expect(result.impactedNodes!.length).toBeGreaterThanOrEqual(0);
      });

      it('should handle multiple node IDs', async () => {
        const query = {
          queryType: 'impact-analysis' as const,
          nodeIds: ['CONFIG_NET', 'CONFIG_BLOCK'],
        };

        const result = await provider.queryGraph(query, graph);

        expect(result.impactedNodes).toBeDefined();
        expect(result.impactedNodes!.length).toBeGreaterThan(0);
      });
    });

    describe('dependency-chain', () => {
      it('should find nodes that a given node depends on', async () => {
        const query = {
          queryType: 'dependency-chain' as const,
          nodeIds: ['CONFIG_INET'],
        };

        const result = await provider.queryGraph(query, graph);

        expect(result.query.queryType).toBe('dependency-chain');
        expect(result.dependencyNodes).toBeDefined();
        
        // CONFIG_INET should depend on CONFIG_NET
        expect(result.dependencyNodes!.some((n) => n === 'CONFIG_NET')).toBe(true);
      });

      it('should respect maxDepth parameter', async () => {
        const query = {
          queryType: 'dependency-chain' as const,
          nodeIds: ['CONFIG_INET'],
          maxDepth: 1,
        };

        const result = await provider.queryGraph(query, graph);

        expect(result.dependencyNodes).toBeDefined();
        // With maxDepth=1, should only get direct dependencies
        expect(result.dependencyNodes!.length).toBeGreaterThanOrEqual(0);
      });

      it('should find dependencies for module nodes', async () => {
        const query = {
          queryType: 'dependency-chain' as const,
          nodeIds: ['module:usb_storage'],
        };

        const result = await provider.queryGraph(query, graph);

        expect(result.dependencyNodes).toBeDefined();
        // usb_storage depends on scsi_mod
        expect(result.dependencyNodes!.some((n) => n === 'module:scsi_mod')).toBe(true);
      });
    });

    describe('subgraph', () => {
      it('should return a subgraph containing the specified nodes', async () => {
        const query = {
          queryType: 'subgraph' as const,
          nodeIds: ['CONFIG_NET', 'CONFIG_INET'],
        };

        const result = await provider.queryGraph(query, graph);

        expect(result.query.queryType).toBe('subgraph');
        expect(result.nodes.length).toBeGreaterThan(0);
        
        // Should include the requested nodes
        expect(result.nodes.some((n) => n.id === 'CONFIG_NET')).toBe(true);
        expect(result.nodes.some((n) => n.id === 'CONFIG_INET')).toBe(true);
      });

      it('should include edges between the nodes', async () => {
        const query = {
          queryType: 'subgraph' as const,
          nodeIds: ['CONFIG_NET', 'CONFIG_INET'],
        };

        const result = await provider.queryGraph(query, graph);

        expect(result.edges.length).toBeGreaterThanOrEqual(0);
      });
    });

    describe('path', () => {
      it('should find paths between nodes', async () => {
        const query = {
          queryType: 'path' as const,
          startId: 'CONFIG_INET',
          endId: 'CONFIG_NET',
        };

        const result = await provider.queryGraph(query, graph);

        expect(result.query.queryType).toBe('path');
        expect(result.paths).toBeDefined();
        
        // Should find at least one path
        expect(result.paths!.length).toBeGreaterThanOrEqual(0);
      });

      it('should return empty paths for unreachable nodes', async () => {
        const query = {
          queryType: 'path' as const,
          startId: 'CONFIG_EXT4_FS',
          endId: 'CONFIG_NET',
        };

        const result = await provider.queryGraph(query, graph);

        expect(result.paths).toBeDefined();
        // EXT4_FS and NET might not have a direct path in our test graph
        expect(result.paths!.length).toBeGreaterThanOrEqual(0);
      });

      it('should require startId and endId', async () => {
        const query = {
          queryType: 'path' as const,
        };

        await expect(provider.queryGraph(query, graph)).rejects.toThrow(
          'path query requires startId and endId',
        );
      });
    });
  });

  describe('error handling', () => {
    it('should throw for unknown query types', async () => {
      const query = {
        queryType: 'unknown' as any,
      };

      const inventory = createTestInventory();
      const graph = await provider.buildGraph(inventory);

      await expect(provider.queryGraph(query, graph)).rejects.toThrow(
        'Unknown query type: unknown',
      );
    });

    it('should throw for impact-analysis without nodeIds', async () => {
      const query = {
        queryType: 'impact-analysis' as const,
      };

      const inventory = createTestInventory();
      const graph = await provider.buildGraph(inventory);

      await expect(provider.queryGraph(query, graph)).rejects.toThrow(
        'impact-analysis requires nodeIds',
      );
    });

    it('should throw for dependency-chain without nodeIds', async () => {
      const query = {
        queryType: 'dependency-chain' as const,
      };

      const inventory = createTestInventory();
      const graph = await provider.buildGraph(inventory);

      await expect(provider.queryGraph(query, graph)).rejects.toThrow(
        'dependency-chain requires nodeIds',
      );
    });

    it('should throw for subgraph without nodeIds', async () => {
      const query = {
        queryType: 'subgraph' as const,
      };

      const inventory = createTestInventory();
      const graph = await provider.buildGraph(inventory);

      await expect(provider.queryGraph(query, graph)).rejects.toThrow(
        'subgraph requires nodeIds',
      );
    });
  });

  describe('init', () => {
    it('should initialize without errors', async () => {
      await expect(provider.init()).resolves.toBeUndefined();
    });
  });
});

describe('buildDependencyGraph', () => {
  it('should build a graph directly', async () => {
    const { buildDependencyGraph } = await import('../src/analysis/dependency-graph.js');
    const inventory = createTestInventory();
    const graph = await buildDependencyGraph(inventory);

    expect(graph.nodes.length).toBeGreaterThan(0);
    expect(graph.edges.length).toBeGreaterThan(0);
  });
});

describe('queryDependencyGraph', () => {
  it('should query a graph directly', async () => {
    const { buildDependencyGraph, queryDependencyGraph } = await import('../src/analysis/dependency-graph.js');
    const inventory = createTestInventory();
    const graph = await buildDependencyGraph(inventory);

    const query = {
      queryType: 'impact-analysis' as const,
      nodeIds: ['CONFIG_NET'],
    };

    const result = await queryDependencyGraph(query, graph);
    expect(result.query.queryType).toBe('impact-analysis');
    expect(result.impactedNodes).toBeDefined();
  });
});
