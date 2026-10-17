import { describe, expect, it } from 'vitest';
import { ToolRegistry } from '../src/engine/tool-registry';

describe('ToolRegistry (module E1)', () => {
  it('registers and calls a tool', async () => {
    const registry = new ToolRegistry();
    registry.register({
      name: 'echo',
      description: 'echoes args',
      handler: async (args) => args,
    });
    const result = await registry.call('echo', { value: 42 });
    expect(result).toEqual({ value: 42 });
  });

  it('rejects duplicate registration', () => {
    const registry = new ToolRegistry();
    registry.register({
      name: 'echo',
      description: 'echoes args',
      handler: async () => ({}),
    });
    expect(() =>
      registry.register({ name: 'echo', description: '', handler: async () => ({}) }),
    ).toThrow(/already registered/);
  });

  it('throws for unknown tools', async () => {
    const registry = new ToolRegistry();
    await expect(registry.call('missing')).rejects.toThrow(/Unknown tool/);
  });

  it('throws when a required argument is missing', async () => {
    const registry = new ToolRegistry();
    registry.register({
      name: 'needs_cve',
      description: '',
      requiredArgs: ['cveId'],
      handler: async () => ({}),
    });
    await expect(registry.call('needs_cve', {})).rejects.toThrow(/Missing required argument/);
  });
});
