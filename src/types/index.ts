/**
 * Security Detections MCP - Type Definitions
 * 
 * This module exports all type definitions used throughout the MCP server.
 * Types are organized into logical modules:
 * 
 * - detection: Core detection types (Sigma, Splunk, Elastic, KQL)
 * - story: Analytic story and campaign grouping types
 * - stats: Statistics, comparisons, and cached query types
 * - knowledge: Knowledge graph types for agent memory
 * - dynamic: Dynamic table types for runtime schema extension
 * - meta: Meta-tool types for custom tools and workflows
 */

// Detection types
export type {
  Detection,
  DetectionSummary,
  SigmaRule,
  SplunkDetection,
  ElasticRule,
  ElasticThreat,
  ElasticTechnique,
} from './detection.js';

// Story types
export type {
  AnalyticStory,
  SplunkStoryYaml,
} from './story.js';

// Statistics types
export type {
  IndexStats,
  SourceComparison,
  SavedQuery,
} from './stats.js';

// Knowledge graph types
export type {
  KnowledgeEntity,
  KnowledgeRelation,
  KnowledgeObservation,
  KnowledgeDecision,
  KnowledgeLearning,
  KnowledgeQueryOptions,
} from './knowledge.js';

// Dynamic table types
export type {
  DynamicColumnSchema,
  DynamicTableDefinition,
  DynamicIndexDefinition,
  DynamicTable,
  DynamicRow,
  DynamicQueryResult,
  DynamicQueryOptions,
  DynamicInsertOptions,
} from './dynamic.js';

// Meta-tool types
export type {
  CustomTool,
  CustomToolInputSchema,
  CustomToolParameter,
  QueryTemplate,
  QueryTemplateParameter,
  CustomToolResult,
  RegisterToolOptions,
  Workflow,
  WorkflowStep,
} from './meta.js';
