#!/usr/bin/env node
/**
 * Security Detections MCP v2.0
 * 
 * Modular architecture with:
 * - 61+ tools across 6 modules (detections, stories, cache, knowledge, dynamic, meta)
 * - Knowledge graph with tribal knowledge (decisions, learnings, reasoning)
 * - Dynamic LLM-created tables for persistent storage
 * - Query templates for reusable shortcuts
 * 
 * This file is intentionally minimal - all logic lives in modules.
 */

import { createServer, startServer } from './server.js';
import { registerAllTools, getToolsSummary } from './tools/index.js';
import { initDb } from './db/connection.js';
import { indexDetections, needsIndexing } from './indexer.js';
import { initPatternsSchema, getPatternStats } from './db/patterns.js';

// Parse comma-separated paths from env var
function parsePaths(envVar: string | undefined): string[] {
  if (!envVar) return [];
  return envVar.split(',').map(p => p.trim()).filter(p => p.length > 0);
}

// Get configured paths from environment
const SIGMA_PATHS = parsePaths(process.env.SIGMA_PATHS);
const SPLUNK_PATHS = parsePaths(process.env.SPLUNK_PATHS);
const ELASTIC_PATHS = parsePaths(process.env.ELASTIC_PATHS);
const STORY_PATHS = parsePaths(process.env.STORY_PATHS);
const KQL_PATHS = parsePaths(process.env.KQL_PATHS);

// Auto-index on startup if paths are configured and DB is empty
function autoIndex(): void {
  if (SIGMA_PATHS.length === 0 && SPLUNK_PATHS.length === 0 && ELASTIC_PATHS.length === 0 && KQL_PATHS.length === 0) {
    return;
  }
  
  initDb();
  
  if (needsIndexing()) {
    console.error('[security-detections-mcp] Auto-indexing detections...');
    const result = indexDetections(SIGMA_PATHS, SPLUNK_PATHS, STORY_PATHS, ELASTIC_PATHS, KQL_PATHS);
    let msg = `[security-detections-mcp] Indexed ${result.total} detections`;
    msg += ` (${result.sigma_indexed} Sigma, ${result.splunk_indexed} Splunk, ${result.elastic_indexed} Elastic, ${result.kql_indexed} KQL)`;
    if (result.stories_indexed > 0) {
      msg += `, ${result.stories_indexed} stories`;
    }
    console.error(msg);
  }
}

async function main() {
  // Initialize database
  initDb();
  
  // Auto-index if configured
  autoIndex();
  
  // Initialize patterns schema (Detection Engineering Intelligence)
  initPatternsSchema();
  const patternStats = getPatternStats();
  if (patternStats.total_patterns > 0) {
    console.error(`[security-detections-mcp] Patterns: ${patternStats.total_patterns} patterns, ${patternStats.fields_indexed} fields, ${patternStats.conventions_stored} conventions`);
  }
  
  // Register all tools from modules
  registerAllTools();
  
  // Log tool summary
  const summary = getToolsSummary();
  console.error(`[security-detections-mcp] ${summary.total} tools registered`);
  console.error(`[security-detections-mcp] Modules: ${Object.entries(summary.byModule).map(([k, v]) => `${k}(${v})`).join(', ')}`);
  
  // Create and start server
  const server = createServer();
  await startServer(server);
}

main().catch((error) => {
  console.error('[security-detections-mcp] Fatal error:', error);
  process.exit(1);
});
