// Tool aggregation and registration entry point
export { toolRegistry, defineTool, registerTool } from './registry.js';
export type { ToolDefinition, ToolResult } from './registry.js';

// Tool module imports
import { detectionTools, detectionToolCounts } from './detections/index.js';
import { storyTools } from './stories/index.js';
import { cacheTools } from './cache/index.js';
import { metaTools } from './meta/index.js';
import { dynamicTools } from './dynamic/index.js';
import { knowledgeTools, knowledgeToolCount } from './knowledge/index.js';
import { autonomousTools, autonomousToolCount } from './autonomous/index.js';
import { engineeringTools, engineeringToolCount } from './engineering/index.js';

import { toolRegistry } from './registry.js';

// Re-export detection tools for direct access
export { detectionTools, detectionToolCounts } from './detections/index.js';
export { searchTools } from './detections/search.js';
export { filterTools } from './detections/filters.js';
export { analysisTools } from './detections/analysis.js';
export { comparisonTools } from './detections/comparison.js';
export { storyTools } from './stories/index.js';
export { cacheTools } from './cache/index.js';
export { metaTools } from './meta/index.js';
export { dynamicTools } from './dynamic/index.js';
export { knowledgeTools, knowledgeToolCount } from './knowledge/index.js';
export { autonomousTools, autonomousToolCount } from './autonomous/index.js';
export { engineeringTools, engineeringToolCount } from './engineering/index.js';

export function registerAllTools(): void {
  // Register all tool modules
  toolRegistry.registerAll(detectionTools);
  toolRegistry.registerAll(storyTools);
  toolRegistry.registerAll(cacheTools);
  toolRegistry.registerAll(metaTools);
  toolRegistry.registerAll(dynamicTools);
  toolRegistry.registerAll(knowledgeTools);
  toolRegistry.registerAll(autonomousTools);
  toolRegistry.registerAll(engineeringTools);
  
  console.error(`[tools] Registry initialized with ${toolRegistry.count()} tools`);
  console.error(`[tools] - Detections: ${detectionToolCounts.total}`);
  console.error(`[tools] - Stories: ${storyTools.length}`);
  console.error(`[tools] - Cache: ${cacheTools.length}`);
  console.error(`[tools] - Meta: ${metaTools.length}`);
  console.error(`[tools] - Dynamic: ${dynamicTools.length}`);
  console.error(`[tools] - Knowledge: ${knowledgeToolCount}`);
  console.error(`[tools] - Autonomous: ${autonomousToolCount}`);
  console.error(`[tools] - Engineering: ${engineeringToolCount}`);
}

export function getToolsSummary(): { total: number; names: string[]; byModule: Record<string, number> } {
  return {
    total: toolRegistry.count(),
    names: toolRegistry.getNames(),
    byModule: {
      detections: detectionToolCounts.total,
      stories: storyTools.length,
      cache: cacheTools.length,
      meta: metaTools.length,
      dynamic: dynamicTools.length,
      knowledge: knowledgeToolCount,
      autonomous: autonomousToolCount,
      engineering: engineeringToolCount,
    },
  };
}
