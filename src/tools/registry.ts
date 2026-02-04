// Tool Registration System - Plugin-style architecture for MCP tools

export interface ToolDefinition {
  name: string;
  description: string;
  inputSchema: {
    type: 'object';
    properties: Record<string, unknown>;
    required?: string[];
  };
  handler: (args: Record<string, unknown>) => Promise<unknown>;
  icon?: string; // MCP 2025-11-25 feature
}

export interface ToolResult {
  content: Array<{ type: 'text'; text: string }>;
  isError?: boolean;
}

class ToolRegistry {
  private tools: Map<string, ToolDefinition> = new Map();

  register(tool: ToolDefinition): void {
    if (this.tools.has(tool.name)) {
      console.warn(`[registry] Tool ${tool.name} already registered, overwriting`);
    }
    this.tools.set(tool.name, tool);
  }

  registerAll(tools: ToolDefinition[]): void {
    tools.forEach(t => this.register(t));
  }

  get(name: string): ToolDefinition | undefined {
    return this.tools.get(name);
  }

  getAll(): ToolDefinition[] {
    return Array.from(this.tools.values());
  }

  has(name: string): boolean {
    return this.tools.has(name);
  }

  getNames(): string[] {
    return Array.from(this.tools.keys());
  }

  async execute(name: string, args: Record<string, unknown>): Promise<unknown> {
    const tool = this.tools.get(name);
    if (!tool) {
      throw new Error(`Unknown tool: ${name}. Available: ${this.getNames().join(', ')}`);
    }
    return tool.handler(args);
  }

  // Execute and format for MCP response
  async executeForMcp(name: string, args: Record<string, unknown>): Promise<ToolResult> {
    try {
      const result = await this.execute(name, args);
      return {
        content: [{ type: 'text', text: JSON.stringify(result, null, 2) }],
      };
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error);
      return {
        content: [{ type: 'text', text: JSON.stringify({ error: true, message }) }],
        isError: true,
      };
    }
  }

  // Format for MCP ListToolsRequest
  toMcpTools(): Array<{ name: string; description: string; inputSchema: object }> {
    return this.getAll().map(t => ({
      name: t.name,
      description: t.description,
      inputSchema: t.inputSchema,
    }));
  }

  count(): number {
    return this.tools.size;
  }

  unregister(name: string): boolean {
    return this.tools.delete(name);
  }

  clear(): void {
    this.tools.clear();
  }
}

// Singleton instance
export const toolRegistry = new ToolRegistry();

// Helper to define a tool with type safety
export function defineTool(definition: ToolDefinition): ToolDefinition {
  return definition;
}

// Helper to register a tool inline
export function registerTool(definition: ToolDefinition): ToolDefinition {
  toolRegistry.register(definition);
  return definition;
}
