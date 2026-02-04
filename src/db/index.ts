/**
 * Database Module - Main Entry Point
 * 
 * Re-exports all database functionality for easy imports.
 * Existing code can continue to import from './db' or './db/index'.
 */

// =============================================================================
// CONNECTION
// =============================================================================

export {
  getDbPath,
  getCacheDir,
  initDb,
  getDb,
  clearDb,
  recreateDb,
  dbExists,
  closeDb,
} from './connection.js';

// =============================================================================
// SCHEMA
// =============================================================================

export {
  createSchema,
  createSavedQueriesTable,
} from './schema.js';

// =============================================================================
// DETECTIONS
// =============================================================================

export {
  // Types
  type ValidationResult,
  type TechniqueIdFilters,
  type CoverageReport,
  type GapAnalysis,
  type DetectionSuggestion,
  type NavigatorLayerOptions,
  type DetectionListItem,
  type SourceComparisonResult,
  
  // CRUD
  insertDetection,
  getDetectionById,
  getRawYaml,
  getDetectionCount,
  
  // Search and List
  searchDetections,
  listDetections,
  listBySource,
  listByMitre,
  listByLogsource,
  listBySeverity,
  listByCve,
  listByAnalyticStory,
  listByProcessName,
  listByDetectionType,
  listByDataSource,
  listByKqlCategory,
  listByKqlTag,
  listByKqlDatasource,
  listByMitreTactic,
  
  // Statistics
  getStats,
  
  // Completion Helpers
  getDistinctTechniqueIds,
  getDistinctCves,
  getDistinctProcessNames,
  
  // Validation
  validateTechniqueId,
  
  // Coverage Analysis
  getTechniqueIds,
  analyzeCoverage,
  identifyGaps,
  suggestDetections,
  generateNavigatorLayer,
  
  // Lightweight Lists
  searchDetectionList,
  listDetectionsBySourceLight,
  compareDetectionsBySource,
  getDetectionNamesByPattern,
  countDetectionsBySource,
} from './detections.js';

// =============================================================================
// STORIES
// =============================================================================

export {
  insertStory,
  getStoryByName,
  getStoryById,
  getStoryCount,
  searchStories,
  listStories,
  listStoriesByCategory,
} from './stories.js';

// =============================================================================
// CACHE
// =============================================================================

export {
  initSavedQueriesTable,
  saveQueryResult,
  getSavedQuery,
  listSavedQueries,
  deleteSavedQuery,
  cleanupExpiredQueries,
  getSavedQueryById,
} from './cache.js';

// =============================================================================
// DYNAMIC TABLES
// =============================================================================

export {
  initDynamicSchema,
  createDynamicTable,
  getTableMetadata,
  listDynamicTables,
  dropDynamicTable,
  insertDynamicRow,
  insertDynamicRows,
  queryDynamicTable,
  deleteDynamicRows,
  getDynamicRow,
  PREBUILT_TABLES,
} from './dynamic.js';

// =============================================================================
// PATTERNS (Detection Engineering Intelligence)
// =============================================================================

export {
  // Types
  type PatternData,
  type FieldReference,
  type StyleConvention,
  type TechniquePatterns,
  type ExtractionResult,
  
  // Schema
  initPatternsSchema,
  
  // Storage
  storePattern,
  storeFieldReference,
  storeStyleConvention,
  
  // Retrieval
  getPatternsByTechnique,
  getFieldReference,
  getStyleConventions,
  getMacroReference,
  
  // Extraction
  extractSPLPatterns,
  extractSigmaPatterns,
  extractKQLPatterns,
  extractElasticPatterns,
  extractFieldUsage,
  extractMacroUsage,
  extractNamingConventions,
  extractAllPatterns,
  
  // Stats
  getPatternStats,
} from './patterns.js';
