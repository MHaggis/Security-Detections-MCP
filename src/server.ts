// MCP Server setup and configuration
import { Server } from '@modelcontextprotocol/sdk/server/index.js';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import {
  CallToolRequestSchema,
  ListToolsRequestSchema,
  ListPromptsRequestSchema,
  GetPromptRequestSchema,
  ListResourcesRequestSchema,
  ReadResourceRequestSchema,
  CompleteRequestSchema,
  SubscribeRequestSchema,
  UnsubscribeRequestSchema,
} from '@modelcontextprotocol/sdk/types.js';

import { handleToolCall, listTools } from './handlers/tools.js';
import { listPrompts, getPrompt } from './handlers/prompts.js';
import { listResources, listResourceTemplates, readResource } from './handlers/resources.js';
import { getDistinctTechniqueIds, getDistinctCves, getDistinctProcessNames } from './db/detections.js';

// Version from package.json would be ideal, but keeping simple for now
const SERVER_VERSION = '2.1.0';

const SERVER_INSTRUCTIONS = `# Security Detections MCP v2.0 - Usage Guide

## Tool Categories

### Detection Search & Filters (30+ tools)
- search, get_by_id, list_all, list_by_source, list_by_mitre, list_by_severity, etc.

### Coverage Analysis
- analyze_coverage, identify_gaps, suggest_detections, smart_compare

### Knowledge Graph (Tribal Knowledge)
- create_entity, create_relation, log_decision, add_learning
- search_knowledge, get_relevant_decisions, get_learnings

### Dynamic Tables (LLM-Created Storage)
- create_table, insert_row, query_table, list_tables

### Query Templates (Shortcuts)
- save_template, run_template, list_templates

### Autonomous Analysis
- auto_analyze_coverage, auto_gap_report, auto_compare_sources
- These tools run comprehensive analysis and store findings automatically

## Key Features
- Tribal knowledge: log_decision captures WHY you made analytical decisions
- Knowledge graph: create_entity and create_relation with reasoning build persistent understanding
- Dynamic tables: Store analysis results for faster future retrieval
- Templates: Save common queries for quick reuse
- Elicitation: Server can request user confirmation for destructive operations
- Resource subscriptions: Subscribe to live resource updates

## Quick Start
1. get_stats() - See detection inventory
2. analyze_coverage() - Get tactic coverage
3. identify_gaps("ransomware") - Find gaps
4. log_decision() - Record your analysis reasoning`;

// Global server instance for tools that need elicitation/sampling
let serverInstance: Server | null = null;

export function getServerInstance(): Server | null {
  return serverInstance;
}

// Helper to wrap handlers with error handling
function wrapHandler<T, R>(
  handlerName: string,
  handler: (request: T) => Promise<R>
): (request: T) => Promise<R> {
  return async (request: T): Promise<R> => {
    try {
      return await handler(request);
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error);
      console.error(`[security-detections-mcp] Error in ${handlerName}: ${message}`);
      throw error; // Re-throw to let MCP SDK handle it
    }
  };
}

export function createServer(): Server {
  const server = new Server(
    {
      name: 'security-detections-mcp',
      version: SERVER_VERSION,
    },
    {
      capabilities: {
        tools: {},
        prompts: { listChanged: true },
        resources: { subscribe: true, listChanged: true },
        completions: {},
      },
      instructions: SERVER_INSTRUCTIONS,
    }
  );

  // Store for tools that need it
  serverInstance = server;

  // List tools handler
  server.setRequestHandler(ListToolsRequestSchema, wrapHandler('listTools', async () => listTools()));

  // Call tool handler - validated return type
  server.setRequestHandler(CallToolRequestSchema, wrapHandler('callTool', async (request) => {
    const { name, arguments: args = {} } = request.params;
    const result = await handleToolCall(name, args as Record<string, unknown>);
    
    // Ensure proper response structure
    if (result && typeof result === 'object' && 'content' in result) {
      return result as { content: Array<{ type: 'text'; text: string }>; isError?: boolean };
    }
    
    // Wrap unexpected result format
    return {
      content: [{ type: 'text' as const, text: JSON.stringify(result) }],
    };
  }));

  // List prompts handler
  server.setRequestHandler(ListPromptsRequestSchema, wrapHandler('listPrompts', async () => listPrompts()));

  // Get prompt handler
  server.setRequestHandler(GetPromptRequestSchema, wrapHandler('getPrompt', async (request) => {
    const { name, arguments: args = {} } = request.params;
    return getPrompt(name, args as Record<string, string>);
  }));

  // List resources handler
  server.setRequestHandler(ListResourcesRequestSchema, wrapHandler('listResources', async () => {
    const { resources } = listResources();
    const { resourceTemplates } = listResourceTemplates();
    return { resources, resourceTemplates };
  }));

  // Read resource handler
  server.setRequestHandler(ReadResourceRequestSchema, wrapHandler('readResource', async (request) => {
    return readResource(request.params.uri);
  }));

  // Completions handler for autocomplete
  server.setRequestHandler(CompleteRequestSchema, wrapHandler('complete', async (request) => {
    const { argument } = request.params;
    
    if (!argument) {
      return { completion: { values: [], hasMore: false } };
    }

    const argName = argument.name;
    const prefix = argument.value || '';
    
    let values: string[] = [];
    
    switch (argName) {
      case 'technique_id':
      case 'technique':
        values = getDistinctTechniqueIds(prefix, 10);
        break;
      case 'cve_id':
      case 'cve':
        values = getDistinctCves(prefix, 10);
        break;
      case 'process_name':
        values = getDistinctProcessNames(prefix, 10);
        break;
      case 'source_type':
      case 'source':
        values = ['sigma', 'splunk_escu', 'elastic', 'kql'].filter(s => 
          s.toLowerCase().startsWith(prefix.toLowerCase())
        );
        break;
      case 'threat_profile':
      case 'profile':
        values = ['ransomware', 'apt', 'initial-access', 'persistence', 'credential-access', 'defense-evasion']
          .filter(p => p.toLowerCase().startsWith(prefix.toLowerCase()));
        break;
      case 'tactic':
        values = [
          'reconnaissance', 'resource-development', 'initial-access', 'execution',
          'persistence', 'privilege-escalation', 'defense-evasion', 'credential-access',
          'discovery', 'lateral-movement', 'collection', 'command-and-control',
          'exfiltration', 'impact'
        ].filter(t => t.toLowerCase().startsWith(prefix.toLowerCase()));
        break;
    }
    
    return { completion: { values, hasMore: false } };
  }));

  // Resource subscription handler
  server.setRequestHandler(SubscribeRequestSchema, wrapHandler('subscribe', async (request) => {
    const { uri } = request.params;
    
    const subscriptions = resourceSubscriptions.get(uri) ?? new Set<string>();
    const subscriptionId = `sub_${Date.now()}_${Math.random().toString(36).substring(2, 11)}`;
    subscriptions.add(subscriptionId);
    resourceSubscriptions.set(uri, subscriptions);
    
    console.error(`[security-detections-mcp] Subscription created for ${uri}: ${subscriptionId}`);
    
    return {};
  }));

  // Resource unsubscription handler
  server.setRequestHandler(UnsubscribeRequestSchema, wrapHandler('unsubscribe', async (request) => {
    const { uri } = request.params;
    
    if (resourceSubscriptions.has(uri)) {
      resourceSubscriptions.delete(uri);
      console.error(`[security-detections-mcp] Unsubscribed from ${uri}`);
    }
    
    return {};
  }));

  return server;
}

// Track active resource subscriptions
const resourceSubscriptions = new Map<string, Set<string>>();

/**
 * Notify subscribers when a resource changes
 */
export async function notifyResourceChange(uri: string): Promise<void> {
  if (!serverInstance) return;
  
  const subscriptions = resourceSubscriptions.get(uri);
  if (!subscriptions || subscriptions.size === 0) return;
  
  try {
    await serverInstance.notification({
      method: 'notifications/resources/updated',
      params: { uri },
    });
    console.error(`[security-detections-mcp] Notified ${subscriptions.size} subscriber(s) of change to ${uri}`);
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    console.error(`[security-detections-mcp] Failed to notify subscribers of ${uri}: ${message}`);
  }
}

/**
 * Clear all subscriptions (call on shutdown)
 */
export function clearSubscriptions(): void {
  const count = resourceSubscriptions.size;
  resourceSubscriptions.clear();
  if (count > 0) {
    console.error(`[security-detections-mcp] Cleared ${count} resource subscription(s)`);
  }
}

/**
 * Get subscription stats for debugging
 */
export function getSubscriptionStats(): { total: number; byUri: Record<string, number> } {
  const byUri: Record<string, number> = {};
  let total = 0;
  
  for (const [uri, subs] of resourceSubscriptions.entries()) {
    byUri[uri] = subs.size;
    total += subs.size;
  }
  
  return { total, byUri };
}

export async function startServer(server: Server): Promise<void> {
  const transport = new StdioServerTransport();
  
  // Handle process termination gracefully
  const cleanup = () => {
    console.error('[security-detections-mcp] Shutting down...');
    clearSubscriptions();
    serverInstance = null;
  };
  
  process.on('SIGINT', cleanup);
  process.on('SIGTERM', cleanup);
  
  await server.connect(transport);
  console.error(`[security-detections-mcp] Server started (v${SERVER_VERSION} - Advanced MCP Features)`);
}
