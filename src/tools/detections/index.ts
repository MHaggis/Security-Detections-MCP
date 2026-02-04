// Detection tools aggregation and export
import { searchTools } from './search.js';
import { filterTools } from './filters.js';
import { analysisTools } from './analysis.js';
import { comparisonTools } from './comparison.js';

// Re-export individual tool arrays for granular imports
export { searchTools } from './search.js';
export { filterTools } from './filters.js';
export { analysisTools } from './analysis.js';
export { comparisonTools } from './comparison.js';

// Combined export of all detection tools
export const detectionTools = [
  ...searchTools,
  ...filterTools,
  ...analysisTools,
  ...comparisonTools,
];

// Tool counts for debugging/stats
export const detectionToolCounts = {
  search: searchTools.length,
  filters: filterTools.length,
  analysis: analysisTools.length,
  comparison: comparisonTools.length,
  total: searchTools.length + filterTools.length + analysisTools.length + comparisonTools.length,
};
