/**
 * Detection Pattern Extraction and Storage
 * 
 * Extracts patterns from indexed detections to enable:
 * - Query pattern learning by technique
 * - Field usage reference by data model
 * - Style/convention learning
 * - Template generation based on learned patterns
 */

import { getDb } from './connection.js';
import { listBySource, listDetections, listByMitre } from './detections.js';
import { addLearning } from './knowledge.js';
import type { Detection } from '../types/detection.js';

// =============================================================================
// SCHEMA
// =============================================================================

export function initPatternsSchema(): void {
  const db = getDb();
  
  // Detection patterns by technique/data source
  db.exec(`
    CREATE TABLE IF NOT EXISTS detection_patterns (
      id TEXT PRIMARY KEY,
      pattern_type TEXT NOT NULL,
      technique_id TEXT,
      data_model TEXT,
      source_type TEXT,
      pattern_content TEXT NOT NULL,
      example_detection_id TEXT,
      usage_count INTEGER DEFAULT 1,
      confidence REAL DEFAULT 1.0,
      created_at TEXT DEFAULT CURRENT_TIMESTAMP
    )
  `);
  
  db.exec(`CREATE INDEX IF NOT EXISTS idx_patterns_technique ON detection_patterns(technique_id)`);
  db.exec(`CREATE INDEX IF NOT EXISTS idx_patterns_type ON detection_patterns(pattern_type)`);
  db.exec(`CREATE INDEX IF NOT EXISTS idx_patterns_source ON detection_patterns(source_type)`);
  
  // Field reference by data model
  db.exec(`
    CREATE TABLE IF NOT EXISTS field_reference (
      id TEXT PRIMARY KEY,
      data_model TEXT NOT NULL,
      field_name TEXT NOT NULL,
      field_type TEXT,
      common_values TEXT,
      usage_examples TEXT,
      description TEXT,
      usage_count INTEGER DEFAULT 1,
      UNIQUE(data_model, field_name)
    )
  `);
  
  db.exec(`CREATE INDEX IF NOT EXISTS idx_fields_model ON field_reference(data_model)`);
  
  // Style conventions
  db.exec(`
    CREATE TABLE IF NOT EXISTS style_conventions (
      id TEXT PRIMARY KEY,
      convention_type TEXT NOT NULL,
      convention_key TEXT NOT NULL,
      convention_value TEXT NOT NULL,
      source TEXT DEFAULT 'extracted',
      confidence REAL DEFAULT 1.0,
      created_at TEXT DEFAULT CURRENT_TIMESTAMP,
      UNIQUE(convention_type, convention_key)
    )
  `);
  
  db.exec(`CREATE INDEX IF NOT EXISTS idx_conventions_type ON style_conventions(convention_type)`);
}

// =============================================================================
// TYPES
// =============================================================================

export interface PatternData {
  uses_tstats: boolean;
  uses_datamodel: string | null;
  macros_used: string[];
  fields_used: string[];
  aggregations: string[];
  where_patterns: string[];
  join_patterns: string[];
}

export interface FieldReference {
  data_model: string;
  field_name: string;
  field_type: string | null;
  common_values: string[];
  usage_examples: string[];
  description: string | null;
  usage_count: number;
}

export interface StyleConvention {
  convention_type: string;
  convention_key: string;
  convention_value: string;
  source: string;
  confidence: number;
}

export interface TechniquePatterns {
  technique_id: string;
  count: number;
  spl_structure: PatternData[];
  data_models: string[];
  macros: string[];
  fields: string[];
  most_common_data_model: string | null;
}

// =============================================================================
// PATTERN EXTRACTION HELPERS
// =============================================================================

function extractFieldsFromQuery(query: string): string[] {
  const fields = new Set<string>();
  
  // Match Processes.field_name or Filesystem.field_name patterns
  const dmFields = query.match(/(?:Processes|Filesystem|Registry|Network_Traffic|Authentication)\.(\w+)/g) || [];
  for (const match of dmFields) {
    const field = match.split('.')[1];
    if (field) fields.add(field);
  }
  
  // Match "by" clause fields
  const byMatch = query.match(/by\s+([^\|]+)/i);
  if (byMatch) {
    const byFields = byMatch[1].split(/\s+/).filter(f => f && !f.startsWith('`'));
    for (const f of byFields) {
      const clean = f.replace(/[,()]/g, '').trim();
      if (clean && !clean.includes('=')) {
        fields.add(clean.split('.').pop() || clean);
      }
    }
  }
  
  return Array.from(fields);
}

function extractMacrosFromQuery(query: string): string[] {
  const macros = query.match(/`([^`]+)`/g) || [];
  return macros.map(m => m.replace(/`/g, ''));
}

function extractAggregationsFromQuery(query: string): string[] {
  const aggs = new Set<string>();
  const aggPatterns = ['count', 'sum', 'avg', 'min', 'max', 'values', 'dc', 'earliest', 'latest', 'stats', 'eventstats'];
  
  for (const agg of aggPatterns) {
    if (query.toLowerCase().includes(agg + '(') || query.toLowerCase().includes(agg + ' ')) {
      aggs.add(agg);
    }
  }
  
  return Array.from(aggs);
}

function extractWherePatterns(query: string): string[] {
  const patterns = new Set<string>();
  
  // Extract WHERE clause patterns
  const whereMatch = query.match(/where\s+([^\|]+)/gi) || [];
  for (const match of whereMatch) {
    // Look for common patterns
    if (match.includes(' IN (')) patterns.add('IN_LIST');
    if (match.includes(' LIKE ')) patterns.add('LIKE');
    if (match.includes('=')) patterns.add('EQUALS');
    if (match.includes('!=') || match.includes('<>')) patterns.add('NOT_EQUALS');
    if (match.includes('*')) patterns.add('WILDCARD');
    if (match.includes(' AND ')) patterns.add('AND');
    if (match.includes(' OR ')) patterns.add('OR');
    if (match.includes(' NOT ')) patterns.add('NOT');
  }
  
  return Array.from(patterns);
}

function generatePatternId(): string {
  return `pat_${Date.now()}_${Math.random().toString(36).slice(2, 8)}`;
}

// Normalize Splunk data model names to full format (DataModel.Object)
function normalizeDataModel(dm: string | null): string | null {
  if (!dm) return null;
  
  // Already in correct format
  if (dm.includes('.')) return dm;
  
  // Known single-name data models that need their object name appended
  const dataModelObjects: Record<string, string> = {
    'Authentication': 'Authentication.Authentication',
    'Change': 'Change.All_Changes',
    'Email': 'Email.All_Email',
    'Network_Resolution': 'Network_Resolution.DNS',
    'Network_Sessions': 'Network_Sessions.All_Sessions',
    'Network_Traffic': 'Network_Traffic.All_Traffic',
    'Updates': 'Updates.Published_Updates',
    'Web': 'Web.Web',
    'Risk': 'Risk.All_Risk',
    'Alerts': 'Alerts.Alerts',
    'Certificates': 'Certificates.All_Certificates',
    'Intrusion_Detection': 'Intrusion_Detection.IDS_Attacks',
  };
  
  // Return normalized version or original if not in known list
  return dataModelObjects[dm] || dm;
}

// =============================================================================
// PATTERN STORAGE
// =============================================================================

export function storePattern(
  patternType: string,
  techniqueId: string | null,
  dataModel: string | null,
  sourceType: string,
  patternContent: PatternData,
  exampleDetectionId: string
): string {
  const db = getDb();
  initPatternsSchema();
  
  // Check if pattern exists for this technique/source combination
  const existing = db.prepare(`
    SELECT id, usage_count, pattern_content, data_model FROM detection_patterns
    WHERE pattern_type = ? AND technique_id = ? AND source_type = ?
    LIMIT 1
  `).get(patternType, techniqueId, sourceType) as { 
    id: string; 
    usage_count: number; 
    pattern_content: string;
    data_model: string | null;
  } | undefined;
  
  if (existing) {
    // Aggregate pattern data from new detection into existing pattern
    const existingContent = JSON.parse(existing.pattern_content) as PatternData;
    
    // Merge macros (union of both sets)
    const allMacros = new Set([...(existingContent.macros_used || []), ...(patternContent.macros_used || [])]);
    
    // Merge fields (union of both sets)
    const allFields = new Set([...(existingContent.fields_used || []), ...(patternContent.fields_used || [])]);
    
    // Merge aggregations
    const allAggs = new Set([...(existingContent.aggregations || []), ...(patternContent.aggregations || [])]);
    
    // Merge where patterns
    const allWherePatterns = new Set([...(existingContent.where_patterns || []), ...(patternContent.where_patterns || [])]);
    
    // Prefer tstats=true if any detection uses it
    const usesTstats = existingContent.uses_tstats || patternContent.uses_tstats;
    
    // Track data models - prefer non-null, use most recently seen
    let bestDataModel = existing.data_model;
    if (dataModel) {
      // Update data_model if this pattern has one
      bestDataModel = dataModel;
    }
    
    const mergedContent: PatternData = {
      uses_tstats: usesTstats,
      uses_datamodel: patternContent.uses_datamodel || existingContent.uses_datamodel,
      macros_used: Array.from(allMacros),
      fields_used: Array.from(allFields),
      aggregations: Array.from(allAggs),
      where_patterns: Array.from(allWherePatterns),
      join_patterns: [...new Set([...(existingContent.join_patterns || []), ...(patternContent.join_patterns || [])])],
    };
    
    // Update with merged content
    db.prepare(`
      UPDATE detection_patterns 
      SET usage_count = usage_count + 1,
          pattern_content = ?,
          data_model = COALESCE(?, data_model)
      WHERE id = ?
    `).run(JSON.stringify(mergedContent), bestDataModel, existing.id);
    
    return existing.id;
  }
  
  // Insert new pattern
  const id = generatePatternId();
  db.prepare(`
    INSERT INTO detection_patterns (id, pattern_type, technique_id, data_model, source_type, pattern_content, example_detection_id)
    VALUES (?, ?, ?, ?, ?, ?, ?)
  `).run(id, patternType, techniqueId, dataModel, sourceType, JSON.stringify(patternContent), exampleDetectionId);
  
  return id;
}

export function storeFieldReference(
  dataModel: string,
  fieldName: string,
  fieldType: string | null,
  commonValues: string[],
  usageExamples: string[],
  description: string | null
): void {
  const db = getDb();
  initPatternsSchema();
  
  const id = `field_${dataModel}_${fieldName}`.replace(/\./g, '_');
  
  db.prepare(`
    INSERT INTO field_reference (id, data_model, field_name, field_type, common_values, usage_examples, description)
    VALUES (?, ?, ?, ?, ?, ?, ?)
    ON CONFLICT(data_model, field_name) DO UPDATE SET
      usage_count = usage_count + 1,
      common_values = ?,
      usage_examples = ?
  `).run(
    id, dataModel, fieldName, fieldType,
    JSON.stringify(commonValues), JSON.stringify(usageExamples), description,
    JSON.stringify(commonValues), JSON.stringify(usageExamples)
  );
}

export function storeStyleConvention(
  conventionType: string,
  conventionKey: string,
  conventionValue: string,
  source: string = 'extracted',
  confidence: number = 1.0
): void {
  const db = getDb();
  initPatternsSchema();
  
  // Use a hash-like approach to ensure unique ID
  const idBase = `${conventionType}_${conventionKey}`;
  const id = `conv_${Buffer.from(idBase).toString('base64').replace(/[^a-zA-Z0-9]/g, '').substring(0, 32)}`;
  
  // Use INSERT OR REPLACE to handle both id conflicts and unique constraint conflicts
  db.prepare(`
    INSERT OR REPLACE INTO style_conventions (id, convention_type, convention_key, convention_value, source, confidence, created_at)
    VALUES (?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
  `).run(id, conventionType, conventionKey, conventionValue, source, confidence);
}

// =============================================================================
// PATTERN RETRIEVAL
// =============================================================================

export function getPatternsByTechnique(techniqueId: string, sourceType?: string): TechniquePatterns {
  const db = getDb();
  initPatternsSchema();
  
  let sql = 'SELECT * FROM detection_patterns WHERE technique_id = ?';
  const params: string[] = [techniqueId];
  
  if (sourceType) {
    sql += ' AND source_type = ?';
    params.push(sourceType);
  }
  
  const rows = db.prepare(sql).all(...params) as Array<{
    id: string;
    pattern_type: string;
    data_model: string;
    source_type: string;
    pattern_content: string;
    usage_count: number;
  }>;
  
  const patterns: PatternData[] = [];
  const dataModels = new Set<string>();
  const macros = new Set<string>();
  const fields = new Set<string>();
  
  for (const row of rows) {
    const content = JSON.parse(row.pattern_content) as PatternData;
    patterns.push(content);
    
    if (row.data_model) dataModels.add(row.data_model);
    for (const macro of content.macros_used || []) macros.add(macro);
    for (const field of content.fields_used || []) fields.add(field);
  }
  
  // Find most common data model
  const dataModelCounts = new Map<string, number>();
  for (const row of rows) {
    if (row.data_model) {
      dataModelCounts.set(row.data_model, (dataModelCounts.get(row.data_model) || 0) + row.usage_count);
    }
  }
  
  let mostCommonDataModel: string | null = null;
  let maxCount = 0;
  for (const [dm, count] of dataModelCounts) {
    if (count > maxCount) {
      maxCount = count;
      mostCommonDataModel = dm;
    }
  }
  
  return {
    technique_id: techniqueId,
    count: rows.length,
    spl_structure: patterns,
    data_models: Array.from(dataModels),
    macros: Array.from(macros),
    fields: Array.from(fields),
    most_common_data_model: mostCommonDataModel,
  };
}

export function getFieldReference(dataModel: string): FieldReference[] {
  const db = getDb();
  initPatternsSchema();
  
  const rows = db.prepare(`
    SELECT * FROM field_reference WHERE data_model = ? ORDER BY usage_count DESC
  `).all(dataModel) as Array<{
    data_model: string;
    field_name: string;
    field_type: string | null;
    common_values: string;
    usage_examples: string;
    description: string | null;
    usage_count: number;
  }>;
  
  return rows.map(row => ({
    data_model: row.data_model,
    field_name: row.field_name,
    field_type: row.field_type,
    common_values: JSON.parse(row.common_values || '[]'),
    usage_examples: JSON.parse(row.usage_examples || '[]'),
    description: row.description,
    usage_count: row.usage_count,
  }));
}

export function getStyleConventions(conventionType?: string): StyleConvention[] {
  const db = getDb();
  initPatternsSchema();
  
  let sql = 'SELECT * FROM style_conventions';
  const params: string[] = [];
  
  if (conventionType) {
    sql += ' WHERE convention_type = ?';
    params.push(conventionType);
  }
  
  sql += ' ORDER BY confidence DESC';
  
  return db.prepare(sql).all(...params) as StyleConvention[];
}

export function getMacroReference(): Map<string, { count: number; examples: string[] }> {
  const db = getDb();
  initPatternsSchema();
  
  const rows = db.prepare(`
    SELECT pattern_content FROM detection_patterns WHERE pattern_type = 'spl_structure'
  `).all() as Array<{ pattern_content: string }>;
  
  const macroMap = new Map<string, { count: number; examples: string[] }>();
  
  for (const row of rows) {
    const content = JSON.parse(row.pattern_content) as PatternData;
    for (const macro of content.macros_used || []) {
      const existing = macroMap.get(macro) || { count: 0, examples: [] };
      existing.count++;
      macroMap.set(macro, existing);
    }
  }
  
  return macroMap;
}

// =============================================================================
// PATTERN EXTRACTION FUNCTIONS
// =============================================================================

export function extractSPLPatterns(): { extracted: number; techniques: number } {
  const db = getDb();
  initPatternsSchema();
  
  const splunkDetections = listBySource('splunk_escu', 9999);
  const techniquesProcessed = new Set<string>();
  let extracted = 0;
  
  for (const detection of splunkDetections) {
    const query = detection.query || '';
    if (!query) continue;
    
    // Better datamodel extraction - handles Endpoint.Processes, Network_Traffic.All_Traffic etc.
    const dataModelMatch = query.match(/from\s+datamodel[=\s]+["]?([A-Za-z_]+(?:\.[A-Za-z_]+)?)/i);
    const rawDataModel = dataModelMatch?.[1] || null;
    
    // Normalize the data model name to full format
    const dataModel = normalizeDataModel(rawDataModel);
    
    const patternData: PatternData = {
      uses_tstats: query.includes('tstats'),
      uses_datamodel: dataModel,
      macros_used: extractMacrosFromQuery(query),
      fields_used: extractFieldsFromQuery(query),
      aggregations: extractAggregationsFromQuery(query),
      where_patterns: extractWherePatterns(query),
      join_patterns: query.includes('join') ? ['JOIN'] : [],
    };
    
    // Store pattern for each technique
    for (const technique of detection.mitre_ids || []) {
      storePattern('spl_structure', technique, dataModel, 'splunk_escu', patternData, detection.id);
      techniquesProcessed.add(technique);
      extracted++;
    }
    
    // If no technique, still store the pattern
    if (!detection.mitre_ids || detection.mitre_ids.length === 0) {
      storePattern('spl_structure', null, dataModel, 'splunk_escu', patternData, detection.id);
      extracted++;
    }
  }
  
  return { extracted, techniques: techniquesProcessed.size };
}

export function extractSigmaPatterns(): { extracted: number; techniques: number } {
  const db = getDb();
  initPatternsSchema();
  
  const sigmaRules = listBySource('sigma', 9999);
  const techniquesProcessed = new Set<string>();
  let extracted = 0;
  
  for (const rule of sigmaRules) {
    const rawYaml = rule.raw_yaml || '';
    
    // Extract Sigma-specific patterns
    const patternData: PatternData = {
      uses_tstats: false,
      uses_datamodel: null, // Sigma doesn't use Splunk data models
      macros_used: [],
      fields_used: extractFieldsFromSigma(rawYaml),
      aggregations: rawYaml.includes('count') || rawYaml.includes('| count') ? ['count'] : [],
      where_patterns: extractSigmaConditionPatterns(rawYaml),
      join_patterns: [],
    };
    
    // Store pattern for each technique - data_model is null for Sigma (logsource_product is platform, not data model)
    for (const technique of rule.mitre_ids || []) {
      storePattern('sigma_structure', technique, null, 'sigma', patternData, rule.id);
      techniquesProcessed.add(technique);
      extracted++;
    }
  }
  
  return { extracted, techniques: techniquesProcessed.size };
}

function extractFieldsFromSigma(yaml: string): string[] {
  const fields = new Set<string>();
  
  // Common Sigma fields
  const commonFields = [
    'CommandLine', 'Image', 'ParentImage', 'ParentCommandLine',
    'User', 'TargetFilename', 'TargetObject', 'SourceImage',
    'TargetImage', 'ProcessId', 'ParentProcessId', 'OriginalFileName',
    'CurrentDirectory', 'IntegrityLevel', 'Hashes', 'Company',
    'Product', 'Description', 'FileVersion'
  ];
  
  for (const field of commonFields) {
    if (yaml.includes(field + ':') || yaml.includes(field + '|')) {
      fields.add(field);
    }
  }
  
  return Array.from(fields);
}

function extractSigmaConditionPatterns(yaml: string): string[] {
  const patterns = new Set<string>();
  
  if (yaml.includes(' and ')) patterns.add('AND');
  if (yaml.includes(' or ')) patterns.add('OR');
  if (yaml.includes(' not ')) patterns.add('NOT');
  if (yaml.includes('|contains')) patterns.add('CONTAINS');
  if (yaml.includes('|startswith')) patterns.add('STARTSWITH');
  if (yaml.includes('|endswith')) patterns.add('ENDSWITH');
  if (yaml.includes('|re')) patterns.add('REGEX');
  if (yaml.includes('|all')) patterns.add('ALL');
  
  return Array.from(patterns);
}

// =============================================================================
// KQL PATTERN EXTRACTION
// =============================================================================

export function extractKQLPatterns(): { extracted: number; techniques: number } {
  const db = getDb();
  initPatternsSchema();
  
  const kqlRules = listBySource('kql', 9999);
  const techniquesProcessed = new Set<string>();
  let extracted = 0;
  
  for (const rule of kqlRules) {
    const query = rule.query || '';
    if (!query) continue;
    
    const patternData: PatternData = {
      uses_tstats: false,
      uses_datamodel: null,
      macros_used: extractKQLFunctions(query),
      fields_used: extractKQLFields(query),
      aggregations: extractKQLAggregations(query),
      where_patterns: extractKQLOperators(query),
      join_patterns: query.toLowerCase().includes('join') ? ['JOIN'] : [],
    };
    
    // Store pattern for each technique
    for (const technique of rule.mitre_ids || []) {
      storePattern('kql_structure', technique, null, 'kql', patternData, rule.id);
      techniquesProcessed.add(technique);
      extracted++;
    }
    
    // If no technique, still store the pattern
    if (!rule.mitre_ids || rule.mitre_ids.length === 0) {
      storePattern('kql_structure', null, null, 'kql', patternData, rule.id);
      extracted++;
    }
  }
  
  return { extracted, techniques: techniquesProcessed.size };
}

function extractKQLFields(query: string): string[] {
  const fields = new Set<string>();
  
  // DYNAMIC EXTRACTION: Extract fields from various KQL patterns
  
  // 1. Fields from project statements: | project Field1, Field2, Field3 = expr
  const projectMatch = query.match(/\|\s*project\s+([^\|]+)/gi) || [];
  for (const match of projectMatch) {
    const parts = match.replace(/\|\s*project\s+/i, '').split(',');
    for (const part of parts) {
      const fieldName = part.trim().split('=')[0].trim();
      if (fieldName && !fieldName.includes('(') && /^[A-Za-z_][A-Za-z0-9_]*$/.test(fieldName)) {
        fields.add(fieldName);
      }
    }
  }
  
  // 2. Fields from extend statements: | extend NewField = expr
  const extendMatch = query.match(/\|\s*extend\s+([^\|]+)/gi) || [];
  for (const match of extendMatch) {
    const parts = match.replace(/\|\s*extend\s+/i, '').split(',');
    for (const part of parts) {
      const fieldName = part.trim().split('=')[0].trim();
      if (fieldName && !fieldName.includes('(') && /^[A-Za-z_][A-Za-z0-9_]*$/.test(fieldName)) {
        fields.add(fieldName);
      }
    }
  }
  
  // 3. Fields from where clauses: | where FieldName == "value" or FieldName contains "x"
  const whereFields = query.match(/\|\s*where\s+([A-Za-z_][A-Za-z0-9_]*)\s*(?:==|!=|=~|!~|has|contains|startswith|endswith|matches|in\s*\(|between)/gi) || [];
  for (const match of whereFields) {
    const fieldMatch = match.match(/where\s+([A-Za-z_][A-Za-z0-9_]*)/i);
    if (fieldMatch && fieldMatch[1]) {
      fields.add(fieldMatch[1]);
    }
  }
  
  // 4. Fields from summarize statements: | summarize count() by Field1, Field2
  const summarizeBy = query.match(/\|\s*summarize\s+[^\|]*\s+by\s+([^\|]+)/gi) || [];
  for (const match of summarizeBy) {
    const byPart = match.match(/by\s+([^\|]+)/i);
    if (byPart && byPart[1]) {
      const byFields = byPart[1].split(',');
      for (const f of byFields) {
        const fieldName = f.trim().split('=')[0].trim();
        if (fieldName && /^[A-Za-z_][A-Za-z0-9_]*$/.test(fieldName)) {
          fields.add(fieldName);
        }
      }
    }
  }
  
  // 5. Fields from join statements: | join kind=inner (Table) on FieldName
  const joinOn = query.match(/\|\s*join[^\|]*on\s+([A-Za-z_][A-Za-z0-9_]*)/gi) || [];
  for (const match of joinOn) {
    const onField = match.match(/on\s+([A-Za-z_][A-Za-z0-9_]*)/i);
    if (onField && onField[1]) {
      fields.add(onField[1]);
    }
  }
  
  // 6. Fields in comparison: FieldName == "value" (general pattern)
  const comparisonFields = query.match(/([A-Za-z_][A-Za-z0-9_]*)\s*(?:==|!=|=~|!~|<|>|<=|>=)\s*["'\d]/g) || [];
  for (const match of comparisonFields) {
    const fieldMatch = match.match(/^([A-Za-z_][A-Za-z0-9_]*)/);
    if (fieldMatch && fieldMatch[1]) {
      const field = fieldMatch[1];
      // Filter out KQL keywords
      const keywords = ['where', 'and', 'or', 'not', 'true', 'false', 'null', 'in', 'between'];
      if (!keywords.includes(field.toLowerCase())) {
        fields.add(field);
      }
    }
  }
  
  return Array.from(fields);
}

function extractKQLFunctions(query: string): string[] {
  const functions = new Set<string>();
  const queryLower = query.toLowerCase();
  
  // DYNAMIC EXTRACTION: Extract KQL operators and functions
  
  // 1. Extract tabular operators (pipe commands): | operator
  const tabularOps = query.match(/\|\s*([a-z_]+)/gi) || [];
  for (const op of tabularOps) {
    const opName = op.replace(/\|\s*/i, '').trim().toLowerCase();
    if (opName && opName.length > 1) {
      functions.add(opName);
    }
  }
  
  // 2. Extract function calls: functionName(
  const funcCalls = query.match(/([a-z_][a-z0-9_]*)\s*\(/gi) || [];
  for (const func of funcCalls) {
    const funcName = func.replace(/\s*\(/, '').trim().toLowerCase();
    // Filter out common non-functions
    if (funcName && funcName.length > 1 && !['http', 'https', 'if'].includes(funcName)) {
      functions.add(funcName);
    }
  }
  
  // 3. Detect string operators used
  if (queryLower.includes(' has ')) functions.add('has');
  if (queryLower.includes(' has_any ')) functions.add('has_any');
  if (queryLower.includes(' has_all ')) functions.add('has_all');
  if (queryLower.includes(' contains ')) functions.add('contains');
  if (queryLower.includes(' startswith ')) functions.add('startswith');
  if (queryLower.includes(' endswith ')) functions.add('endswith');
  if (queryLower.includes(' matches regex ')) functions.add('matches regex');
  if (queryLower.includes(' in ') || queryLower.includes(' in(')) functions.add('in');
  if (queryLower.includes(' in~ ') || queryLower.includes(' in~(')) functions.add('in~');
  if (queryLower.includes(' between ')) functions.add('between');
  if (queryLower.includes('isnotempty(')) functions.add('isnotempty');
  if (queryLower.includes('isempty(')) functions.add('isempty');
  if (queryLower.includes('isnull(')) functions.add('isnull');
  if (queryLower.includes('isnotnull(')) functions.add('isnotnull');
  
  return Array.from(functions);
}

function extractKQLAggregations(query: string): string[] {
  const aggs = new Set<string>();
  
  if (query.toLowerCase().includes('summarize')) aggs.add('summarize');
  if (query.toLowerCase().includes('count()')) aggs.add('count');
  if (query.toLowerCase().includes('dcount(')) aggs.add('dcount');
  if (query.toLowerCase().includes('sum(')) aggs.add('sum');
  if (query.toLowerCase().includes('avg(')) aggs.add('avg');
  if (query.toLowerCase().includes('make-set(')) aggs.add('make-set');
  if (query.toLowerCase().includes('make-list(')) aggs.add('make-list');
  
  return Array.from(aggs);
}

function extractKQLOperators(query: string): string[] {
  const operators = new Set<string>();
  
  if (query.includes(' and ') || query.includes(' && ')) operators.add('AND');
  if (query.includes(' or ') || query.includes(' || ')) operators.add('OR');
  if (query.includes('!') || query.includes(' not ')) operators.add('NOT');
  if (query.includes(' has ')) operators.add('HAS');
  if (query.includes(' contains ')) operators.add('CONTAINS');
  if (query.includes(' startswith ')) operators.add('STARTSWITH');
  if (query.includes(' endswith ')) operators.add('ENDSWITH');
  if (query.includes(' matches regex ')) operators.add('REGEX');
  if (query.includes(' in (') || query.includes(' in~(')) operators.add('IN');
  if (query.includes(' between ')) operators.add('BETWEEN');
  
  return Array.from(operators);
}

// =============================================================================
// ELASTIC PATTERN EXTRACTION
// =============================================================================

export function extractElasticPatterns(): { extracted: number; techniques: number } {
  const db = getDb();
  initPatternsSchema();
  
  const elasticRules = listBySource('elastic', 9999);
  const techniquesProcessed = new Set<string>();
  let extracted = 0;
  
  for (const rule of elasticRules) {
    const query = rule.query || '';
    if (!query) continue;
    
    const patternData: PatternData = {
      uses_tstats: false,
      uses_datamodel: null,
      macros_used: [],
      fields_used: extractElasticFields(query),
      aggregations: extractElasticAggregations(query),
      where_patterns: extractElasticOperators(query),
      join_patterns: [],
    };
    
    // Store pattern for each technique
    for (const technique of rule.mitre_ids || []) {
      storePattern('elastic_structure', technique, null, 'elastic', patternData, rule.id);
      techniquesProcessed.add(technique);
      extracted++;
    }
    
    // If no technique, still store the pattern
    if (!rule.mitre_ids || rule.mitre_ids.length === 0) {
      storePattern('elastic_structure', null, null, 'elastic', patternData, rule.id);
      extracted++;
    }
  }
  
  return { extracted, techniques: techniquesProcessed.size };
}

function extractElasticFields(query: string): string[] {
  const fields = new Set<string>();
  
  // DYNAMIC EXTRACTION: Extract fields from various Elastic/EQL patterns
  
  // 1. Extract field:value patterns from EQL/ES queries (primary method)
  // Matches: process.name:"cmd.exe" or host.os.name:windows
  const fieldValuePattern = /([a-zA-Z_][a-zA-Z0-9_\.]*)\s*:/g;
  let match;
  while ((match = fieldValuePattern.exec(query)) !== null) {
    const field = match[1].trim();
    // Filter out common false positives (URLs, etc.)
    if (field && 
        !['http', 'https', 'ftp', 'file'].includes(field.toLowerCase()) &&
        field.length > 1) {
      fields.add(field);
    }
  }
  
  // 2. Extract fields from EQL sequence/until blocks
  // Matches: [process where process.name == "cmd.exe"]
  const eqlWhereFields = query.match(/where\s+([a-zA-Z_][a-zA-Z0-9_\.]*)\s*(?:==|!=|:|in|like|regex)/gi) || [];
  for (const whereMatch of eqlWhereFields) {
    const fieldMatch = whereMatch.match(/where\s+([a-zA-Z_][a-zA-Z0-9_\.]*)/i);
    if (fieldMatch && fieldMatch[1]) {
      fields.add(fieldMatch[1]);
    }
  }
  
  // 3. Extract fields from EQL comparison operators
  // Matches: process.args : "*-nop*" or file.path == "C:\\Windows"
  const comparisonFields = query.match(/([a-zA-Z_][a-zA-Z0-9_\.]+)\s*(?:==|!=|>=|<=|>|<|~=)\s*["'\[]/g) || [];
  for (const compMatch of comparisonFields) {
    const fieldMatch = compMatch.match(/^([a-zA-Z_][a-zA-Z0-9_\.]+)/);
    if (fieldMatch && fieldMatch[1]) {
      fields.add(fieldMatch[1]);
    }
  }
  
  // 4. Extract fields from "in" expressions
  // Matches: process.name in ("cmd.exe", "powershell.exe")
  const inFields = query.match(/([a-zA-Z_][a-zA-Z0-9_\.]+)\s+in\s*\(/gi) || [];
  for (const inMatch of inFields) {
    const fieldMatch = inMatch.match(/^([a-zA-Z_][a-zA-Z0-9_\.]+)/);
    if (fieldMatch && fieldMatch[1]) {
      fields.add(fieldMatch[1]);
    }
  }
  
  // 5. Extract fields from wildcard matching
  // Matches: process.command_line : "*encoded*"
  const wildcardFields = query.match(/([a-zA-Z_][a-zA-Z0-9_\.]+)\s*:\s*["']\*/g) || [];
  for (const wcMatch of wildcardFields) {
    const fieldMatch = wcMatch.match(/^([a-zA-Z_][a-zA-Z0-9_\.]+)/);
    if (fieldMatch && fieldMatch[1]) {
      fields.add(fieldMatch[1]);
    }
  }
  
  // Filter out EQL keywords that might be captured
  const eqlKeywords = ['where', 'and', 'or', 'not', 'true', 'false', 'null', 'in', 'like', 'regex', 'sequence', 'until', 'by', 'with', 'maxspan'];
  return Array.from(fields).filter(f => !eqlKeywords.includes(f.toLowerCase()));
}

function extractElasticAggregations(query: string): string[] {
  const aggs = new Set<string>();
  
  // EQL sequence detection
  if (query.toLowerCase().includes('sequence')) aggs.add('sequence');
  if (query.toLowerCase().includes(' by ')) aggs.add('by');
  if (query.toLowerCase().includes('maxspan')) aggs.add('maxspan');
  if (query.toLowerCase().includes('until')) aggs.add('until');
  
  return Array.from(aggs);
}

function extractElasticOperators(query: string): string[] {
  const operators = new Set<string>();
  
  if (query.includes(' and ') || query.includes(' AND ')) operators.add('AND');
  if (query.includes(' or ') || query.includes(' OR ')) operators.add('OR');
  if (query.includes(' not ') || query.includes(' NOT ')) operators.add('NOT');
  if (query.includes(':*')) operators.add('WILDCARD');
  if (query.includes('~')) operators.add('FUZZY');
  if (query.includes('..')) operators.add('RANGE');
  if (query.includes(' where ')) operators.add('WHERE');
  
  return Array.from(operators);
}

export function extractFieldUsage(): { fields: number; dataModels: number } {
  const db = getDb();
  initPatternsSchema();
  
  const detections = listBySource('splunk_escu', 9999);
  const fieldUsage = new Map<string, { count: number; examples: string[] }>();
  const dataModels = new Set<string>();
  
  for (const detection of detections) {
    const query = detection.query || '';
    // Match datamodel=DataModel or datamodel=DataModel.Object
    const dataModelMatch = query.match(/from\s+datamodel[=\s]+["]?([A-Za-z_]+(?:\.[A-Za-z_]+)?)/i);
    if (!dataModelMatch) continue;
    
    // Normalize the data model name
    const rawDataModel = dataModelMatch[1];
    const dataModel = normalizeDataModel(rawDataModel);
    if (!dataModel) continue;
    
    dataModels.add(dataModel);
    
    const fields = extractFieldsFromQuery(query);
    for (const field of fields) {
      // Store with separator that won't conflict with data model dot
      const key = `${dataModel}|${field}`;
      const existing = fieldUsage.get(key) || { count: 0, examples: [] };
      existing.count++;
      if (existing.examples.length < 3) {
        existing.examples.push(detection.name);
      }
      fieldUsage.set(key, existing);
    }
  }
  
  // Store field references
  for (const [key, usage] of fieldUsage) {
    const [dataModel, fieldName] = key.split('|');
    storeFieldReference(dataModel, fieldName, 'string', [], usage.examples, null);
  }
  
  return { fields: fieldUsage.size, dataModels: dataModels.size };
}

export function extractMacroUsage(): { macros: number } {
  const db = getDb();
  initPatternsSchema();
  
  const detections = listBySource('splunk_escu', 9999);
  const macroUsage = new Map<string, { count: number; description: string }>();
  
  for (const detection of detections) {
    const query = detection.query || '';
    const macros = extractMacrosFromQuery(query);
    
    for (const macro of macros) {
      const existing = macroUsage.get(macro) || { count: 0, description: '' };
      existing.count++;
      macroUsage.set(macro, existing);
    }
  }
  
  // Store as style conventions
  for (const [macro, usage] of macroUsage) {
    storeStyleConvention('macro_usage', macro, JSON.stringify({ count: usage.count }), 'extracted', usage.count / detections.length);
  }
  
  return { macros: macroUsage.size };
}

export function extractNamingConventions(): { conventions: number } {
  const db = getDb();
  initPatternsSchema();
  
  const detections = listBySource('splunk_escu', 9999);
  const namingPatterns = new Map<string, number>();
  
  for (const detection of detections) {
    const name = detection.name || '';
    
    // Extract naming patterns
    if (name.startsWith('Windows')) namingPatterns.set('prefix_windows', (namingPatterns.get('prefix_windows') || 0) + 1);
    if (name.startsWith('Linux')) namingPatterns.set('prefix_linux', (namingPatterns.get('prefix_linux') || 0) + 1);
    if (name.startsWith('AWS')) namingPatterns.set('prefix_aws', (namingPatterns.get('prefix_aws') || 0) + 1);
    if (name.startsWith('Azure')) namingPatterns.set('prefix_azure', (namingPatterns.get('prefix_azure') || 0) + 1);
    if (name.startsWith('GCP')) namingPatterns.set('prefix_gcp', (namingPatterns.get('prefix_gcp') || 0) + 1);
    
    // Check for technique references in names
    if (name.includes('Injection')) namingPatterns.set('includes_technique', (namingPatterns.get('includes_technique') || 0) + 1);
    if (name.includes('Execution')) namingPatterns.set('includes_technique', (namingPatterns.get('includes_technique') || 0) + 1);
    if (name.includes('Persistence')) namingPatterns.set('includes_technique', (namingPatterns.get('includes_technique') || 0) + 1);
  }
  
  // Store naming conventions
  for (const [pattern, count] of namingPatterns) {
    storeStyleConvention('naming', pattern, String(count), 'extracted', count / detections.length);
  }
  
  return { conventions: namingPatterns.size };
}

// =============================================================================
// FULL EXTRACTION
// =============================================================================

export interface ExtractionResult {
  spl_patterns: { extracted: number; techniques: number };
  sigma_patterns: { extracted: number; techniques: number };
  kql_patterns: { extracted: number; techniques: number };
  elastic_patterns: { extracted: number; techniques: number };
  field_usage: { fields: number; dataModels: number };
  macro_usage: { macros: number };
  naming_conventions: { conventions: number };
  total_patterns: number;
}

export function extractAllPatterns(): ExtractionResult {
  console.error('[patterns] Starting pattern extraction...');
  
  const spl = extractSPLPatterns();
  console.error(`[patterns] Extracted ${spl.extracted} SPL patterns for ${spl.techniques} techniques`);
  
  const sigma = extractSigmaPatterns();
  console.error(`[patterns] Extracted ${sigma.extracted} Sigma patterns for ${sigma.techniques} techniques`);
  
  const kql = extractKQLPatterns();
  console.error(`[patterns] Extracted ${kql.extracted} KQL patterns for ${kql.techniques} techniques`);
  
  const elastic = extractElasticPatterns();
  console.error(`[patterns] Extracted ${elastic.extracted} Elastic patterns for ${elastic.techniques} techniques`);
  
  const fields = extractFieldUsage();
  console.error(`[patterns] Extracted ${fields.fields} field references across ${fields.dataModels} data models`);
  
  const macros = extractMacroUsage();
  console.error(`[patterns] Extracted ${macros.macros} macro usage patterns`);
  
  const naming = extractNamingConventions();
  console.error(`[patterns] Extracted ${naming.conventions} naming conventions`);
  
  const total = spl.extracted + sigma.extracted + kql.extracted + elastic.extracted;
  console.error(`[patterns] Pattern extraction complete: ${total} total patterns`);
  
  // Also store summary as a learning
  addLearning(
    'pattern_extraction',
    'Pattern extraction summary',
    `Extracted patterns from indexed detections: ${spl.extracted} SPL, ${sigma.extracted} Sigma, ${kql.extracted} KQL, ${elastic.extracted} Elastic, ${fields.fields} fields, ${macros.macros} macros`,
    JSON.stringify({ spl, sigma, kql, elastic, fields, macros, naming }),
    'detection_generation'
  );
  
  return {
    spl_patterns: spl,
    sigma_patterns: sigma,
    kql_patterns: kql,
    elastic_patterns: elastic,
    field_usage: fields,
    macro_usage: macros,
    naming_conventions: naming,
    total_patterns: total,
  };
}

// =============================================================================
// PATTERN STATS
// =============================================================================

export function getPatternStats(): {
  total_patterns: number;
  by_source: Record<string, number>;
  by_technique: number;
  fields_indexed: number;
  conventions_stored: number;
} {
  const db = getDb();
  initPatternsSchema();
  
  const totalPatterns = (db.prepare('SELECT COUNT(*) as count FROM detection_patterns').get() as { count: number }).count;
  
  const bySourceRows = db.prepare(`
    SELECT source_type, COUNT(*) as count FROM detection_patterns GROUP BY source_type
  `).all() as Array<{ source_type: string; count: number }>;
  
  const bySource: Record<string, number> = {};
  for (const row of bySourceRows) {
    bySource[row.source_type] = row.count;
  }
  
  const uniqueTechniques = (db.prepare(`
    SELECT COUNT(DISTINCT technique_id) as count FROM detection_patterns WHERE technique_id IS NOT NULL
  `).get() as { count: number }).count;
  
  const fieldsIndexed = (db.prepare('SELECT COUNT(*) as count FROM field_reference').get() as { count: number }).count;
  
  const conventionsStored = (db.prepare('SELECT COUNT(*) as count FROM style_conventions').get() as { count: number }).count;
  
  return {
    total_patterns: totalPatterns,
    by_source: bySource,
    by_technique: uniqueTechniques,
    fields_indexed: fieldsIndexed,
    conventions_stored: conventionsStored,
  };
}
