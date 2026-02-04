// Tool request handler - uses the tool registry
import { toolRegistry } from '../tools/index.js';

export interface ToolCallResult {
  content: Array<{ type: 'text'; text: string }>;
  isError?: boolean;
}

export async function handleToolCall(name: string, args: Record<string, unknown>): Promise<ToolCallResult> {
  return toolRegistry.executeForMcp(name, args);
}

export function listTools() {
  return { tools: toolRegistry.toMcpTools() };
}
