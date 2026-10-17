export interface ToolDefinition {
  name: string;
  description: string;
  requiredArgs?: string[];
  handler: (args: Record<string, unknown>) => Promise<unknown>;
}

/**
 * Tool registry for engine-internal composition and testing (module E1).
 * The MCP surface in src/tools/ is a thin adapter over this registry, so the
 * engine stays testable without a live MCP client.
 */
export class ToolRegistry {
  private readonly tools = new Map<string, ToolDefinition>();

  register(def: ToolDefinition): void {
    if (this.tools.has(def.name)) {
      throw new Error(`Tool already registered: ${def.name}`);
    }
    this.tools.set(def.name, def);
  }

  list(): ToolDefinition[] {
    return [...this.tools.values()];
  }

  async call(name: string, args: Record<string, unknown> = {}): Promise<unknown> {
    const tool = this.tools.get(name);
    if (!tool) {
      throw new Error(`Unknown tool: ${name}`);
    }
    for (const required of tool.requiredArgs ?? []) {
      if (args[required] === undefined) {
        throw new Error(`Missing required argument: ${required}`);
      }
    }
    return tool.handler(args);
  }
}
