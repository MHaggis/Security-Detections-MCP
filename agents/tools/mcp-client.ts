/**
 * MCP Client for calling MCP server tools
 * 
 * Routes calls to the right MCP server:
 * - security-detections MCP (detections database) – direct DB when available
 * - splunk-mcp (Splunk queries) – via env-gated MCP protocol
 * - mitre-attack MCP (ATT&CK data) – via MCP protocol
 * 
 * When the real MCP transport isn't wired yet the client returns a
 * structured "pending" payload so callers know what *would* have been called.
 */

import { getConfig } from '../config.js';
import { existsSync } from 'node:fs';

interface MCPToolCall {
  server: string;
  tool: string;
  arguments: Record<string, unknown>;
}

interface MCPToolResult {
  success: boolean;
  result?: unknown;
  error?: string;
}

// Dynamic db module reference (loaded at runtime)
let dbModule: any = null;

/**
 * Load the db module dynamically at runtime
 */
async function loadDbModule(): Promise<any> {
  if (dbModule) return dbModule;
  
  try {
    // Source lives in agents/tools; compiled output lives in agents/dist/tools.
    // Locate the agents package first so both entry points reach the sibling
    // MCP server build, independently of the process working directory.
    const parent = new URL('../', import.meta.url);
    const packageRoot = existsSync(new URL('package.json', parent))
      ? parent
      : new URL('../', parent);
    const moduleUrl = new URL('../dist/db/index.js', packageRoot);
    dbModule = await import(moduleUrl.href);
    return dbModule;
  } catch (error) {
    console.log('[MCP Client] Could not load db module directly, will use MCP protocol');
    return null;
  }
}

export class MCPClient {
  /**
   * Call an MCP tool
   * 
   * Routes to the appropriate MCP server based on the server name.
   */
  async callTool(call: MCPToolCall): Promise<MCPToolResult> {
    console.log(`[MCP Client] Calling ${call.server}/${call.tool}`);
    
    try {
      switch (call.server) {
        case 'security-detections':
        case 'user-security-detections':
          return this.callDetectionsMCP(call.tool, call.arguments);
          
        case 'splunk-mcp':
        case 'user-splunk-mcp':
          return this.callSplunkMCP(call.tool, call.arguments);
          
        case 'mitre-attack':
        case 'user-mitre-attack':
          return this.callMitreMCP(call.tool, call.arguments);
          
        default:
          return { success: false, error: `Unknown MCP server: ${call.server}` };
      }
    } catch (error) {
      return { 
        success: false, 
        error: error instanceof Error ? error.message : 'Unknown error' 
      };
    }
  }

  /**
   * Security Detections MCP - detection database queries
   * 
   * Attempts to call db functions directly if available,
   * otherwise returns a pending MCP call structure.
   */
  private async callDetectionsMCP(tool: string, args: Record<string, unknown>): Promise<MCPToolResult> {
    console.log(`[Security Detections MCP] Tool: ${tool}`);
    console.log(`[Security Detections MCP] Args: ${JSON.stringify(args)}`);
    
    // Try to load and use the db module directly
    const db = await loadDbModule();
    
    if (db) {
      try {
        // Initialize db if needed
        if (db.dbExists && !db.dbExists()) {
          console.log('[Security Detections MCP] Database not found, returning pending');
        } else {
          if (db.initDb) {
            db.initDb();
          }
          
          switch (tool) {
            case 'search': {
              const query = args.query as string;
              const limit = (args.limit as number) || 50;
              if (db.searchDetections) {
                const results = db.searchDetections(query, limit);
                return { success: true, result: results };
              }
              break;
            }
            
            case 'list_by_mitre': {
              const techniqueId = args.technique_id as string;
              const limit = (args.limit as number) || 100;
              const offset = (args.offset as number) || 0;
              if (db.listByMitre) {
                const results = db.listByMitre(techniqueId, limit, offset);
                return { success: true, result: results };
              }
              break;
            }
            
            case 'analyze_coverage': {
              const sourceType = args.source_type as string | undefined;
              if (db.analyzeCoverage) {
                const results = db.analyzeCoverage(sourceType);
                return { success: true, result: results };
              }
              break;
            }
            
            case 'identify_gaps': {
              const threatProfile = args.threat_profile as string;
              const sourceType = args.source_type as string | undefined;
              if (db.identifyGaps) {
                const results = db.identifyGaps(threatProfile, sourceType);
                return { success: true, result: results };
              }
              break;
            }
            
            case 'suggest_detections': {
              const techniqueId = args.technique_id as string;
              const sourceType = args.source_type as string | undefined;
              if (db.suggestDetections) {
                const results = db.suggestDetections(techniqueId, sourceType);
                return { success: true, result: results };
              }
              break;
            }
            
            case 'get_stats': {
              if (db.getStats) {
                const results = db.getStats();
                return { success: true, result: results };
              }
              break;
            }

            case 'generate_navigator_layer': {
              const name = (args.name as string) || 'Coverage Layer';
              if (db.generateNavigatorLayer) {
                const results = db.generateNavigatorLayer({
                  name,
                  description: args.description as string | undefined,
                  source_type: args.source_type as string | undefined,
                  tactic: args.tactic as string | undefined,
                  severity: args.severity as string | undefined,
                });
                return { success: true, result: results };
              }
              break;
            }
          }
        }
      } catch (error) {
        console.log(`[Security Detections MCP] Error calling db: ${error}`);
      }
    }
    
    // Fallback: return MCP call structure for external handling
    return {
      success: true,
      result: {
        _mcp_pending: true,
        _server: 'security-detections',
        _tool: tool,
        _args: args,
        _message: 'Call prepared - wire to actual MCP for execution',
      },
    };
  }

  /**
   * Splunk MCP - Splunk API queries
   */
  private async callSplunkMCP(tool: string, args: Record<string, unknown>): Promise<MCPToolResult> {
    console.log(`[Splunk MCP] Tool: ${tool}`);
    console.log(`[Splunk MCP] Args: ${JSON.stringify(args)}`);
    
    const canCallMCP = process.env.SPLUNK_MCP_ENABLED === 'true';
    
    if (!canCallMCP) {
      console.log(`[Splunk MCP] MCP not enabled - returning call structure`);
      
      return {
        success: true,
        result: {
          _mcp_pending: true,
          _server: 'splunk-mcp',
          _tool: tool,
          _args: args,
          _message: 'Splunk MCP call prepared - wire to actual MCP for execution',
        },
      };
    }
    
    try {
      const result = await this.executeMCPCall('splunk-mcp', tool, args);
      return { success: true, result };
    } catch (error) {
      return { 
        success: false, 
        error: error instanceof Error ? error.message : 'Splunk MCP call failed' 
      };
    }
  }

  /**
   * MITRE ATT&CK MCP - technique lookup
   */
  private async callMitreMCP(tool: string, args: Record<string, unknown>): Promise<MCPToolResult> {
    console.log(`[MITRE MCP] Tool: ${tool}, Args: ${JSON.stringify(args)}`);
    
    return {
      success: true,
      result: {
        _mcp_pending: true,
        _server: 'mitre-attack',
        _tool: tool,
        _args: args,
      },
    };
  }

  /**
   * Execute an actual MCP call via the MCP SDK transport.
   *
   * Right now this is a best-effort wrapper: if @modelcontextprotocol/sdk
   * is installed and the server URL is configured we'll use it, otherwise
   * we fall back to the pending-call structure.
   */
  private async executeMCPCall(server: string, tool: string, args: Record<string, unknown>): Promise<unknown> {
    const cfg = getConfig();

    // In dry-run mode never hit a real server
    if (cfg.dryRun) {
      return { _dry_run: true, _server: server, _tool: tool, _args: args };
    }

    // Attempt to use the SDK if available
    try {
      const { Client } = await import('@modelcontextprotocol/sdk/client/index.js');
      const { StdioClientTransport } = await import('@modelcontextprotocol/sdk/client/stdio.js');

      const transport = new StdioClientTransport({ command: 'npx', args: [server] });
      const client = new Client({ name: 'detection-agents', version: '3.0.0' });
      await client.connect(transport);

      const result = await client.callTool({ name: tool, arguments: args });
      await client.close();
      return result;
    } catch {
      // SDK not installed or connection failed – return pending structure
      return {
        _mcp_pending: true,
        _server: server,
        _tool: tool,
        _args: args,
        _message: `MCP SDK not available for ${server}/${tool} – install @modelcontextprotocol/sdk to enable`,
      };
    }
  }
}

// Singleton instance
let client: MCPClient | null = null;

export function getMCPClient(): MCPClient {
  if (!client) {
    client = new MCPClient();
  }
  return client;
}

/**
 * Convenience function to call Splunk MCP search
 */
export async function splunkSearch(spl: string): Promise<MCPToolResult> {
  const client = getMCPClient();
  return client.callTool({
    server: 'splunk-mcp',
    tool: 'search',
    arguments: { search: spl },
  });
}

/**
 * Convenience function to run a detection via Splunk MCP
 */
export async function splunkRunDetection(detectionPath: string): Promise<MCPToolResult> {
  const client = getMCPClient();
  return client.callTool({
    server: 'splunk-mcp',
    tool: 'run_detection',
    arguments: { detection_path: detectionPath, auto_prefix: true },
  });
}

/**
 * Convenience function to export attack data via Splunk MCP
 */
export async function splunkExportDump(
  search: string,
  outputPath: string,
  earliest?: string,
  latest?: string
): Promise<MCPToolResult> {
  const client = getMCPClient();
  return client.callTool({
    server: 'splunk-mcp',
    tool: 'export_dump',
    arguments: { 
      search, 
      output_path: outputPath,
      earliest: earliest || '-2h',
      latest: latest || 'now',
      output_format: 'jsonl',
    },
  });
}
