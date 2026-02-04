/**
 * Meta-Tool Types
 * Types for user-defined tools, query templates, and workflow automation
 * Enables runtime extension of MCP capabilities
 */

/**
 * A custom tool definition that can be registered at runtime
 */
export interface CustomTool {
  /** Unique identifier for the tool */
  id: string;
  /** Tool name (used in MCP tool invocation) */
  name: string;
  /** Human-readable description of what the tool does */
  description: string;
  /** 
   * Tool category for organization
   * Common categories: analysis, reporting, automation, integration
   */
  category: string;
  /** JSON Schema defining the tool's input parameters */
  input_schema: CustomToolInputSchema;
  /** 
   * The implementation - either a SQL query template or JavaScript code
   * Use {{param_name}} for parameter substitution in SQL
   */
  implementation: string;
  /** Type of implementation */
  implementation_type: 'sql' | 'javascript' | 'composite';
  /** For composite tools: list of tool IDs to chain */
  tool_chain?: string[];
  /** Whether this tool is enabled */
  enabled: boolean;
  /** Who created this tool */
  created_by?: string;
  /** ISO timestamp when tool was created */
  created_at: string;
  /** ISO timestamp when tool was last modified */
  modified_at: string;
  /** Number of times this tool has been invoked */
  invocation_count: number;
}

/**
 * JSON Schema for custom tool input parameters
 */
export interface CustomToolInputSchema {
  /** Schema type (always "object" for tool inputs) */
  type: 'object';
  /** Parameter definitions */
  properties: Record<string, CustomToolParameter>;
  /** List of required parameter names */
  required?: string[];
}

/**
 * A single parameter in a custom tool's input schema
 */
export interface CustomToolParameter {
  /** Parameter type */
  type: 'string' | 'number' | 'boolean' | 'array' | 'object';
  /** Parameter description */
  description: string;
  /** Default value if not provided */
  default?: unknown;
  /** For string types: enumerated allowed values */
  enum?: string[];
  /** For array types: schema for array items */
  items?: { type: string };
  /** For number types: minimum value */
  minimum?: number;
  /** For number types: maximum value */
  maximum?: number;
}

/**
 * A reusable query template with parameterized placeholders
 */
export interface QueryTemplate {
  /** Unique identifier */
  id: string;
  /** Template name */
  name: string;
  /** Human-readable description */
  description: string;
  /** 
   * The query template with {{param}} placeholders
   * Example: "SELECT * FROM detections WHERE mitre_ids LIKE '%{{technique}}%'"
   */
  template: string;
  /** Parameter definitions */
  parameters: QueryTemplateParameter[];
  /** Query type for categorization */
  query_type: 'detection_search' | 'coverage_analysis' | 'gap_analysis' | 'reporting' | 'custom';
  /** Expected output format */
  output_format: 'table' | 'json' | 'markdown' | 'csv';
  /** Tags for categorization and discovery */
  tags: string[];
  /** Who created this template */
  created_by?: string;
  /** ISO timestamp when created */
  created_at: string;
  /** Number of times this template has been used */
  usage_count: number;
}

/**
 * A parameter in a query template
 */
export interface QueryTemplateParameter {
  /** Parameter name (matches {{name}} in template) */
  name: string;
  /** Human-readable description */
  description: string;
  /** Parameter type */
  type: 'string' | 'number' | 'boolean' | 'string[]';
  /** Whether this parameter is required */
  required: boolean;
  /** Default value */
  default?: unknown;
  /** For string types: validation pattern (regex) */
  pattern?: string;
  /** Example values for documentation */
  examples?: string[];
}

/**
 * Result of executing a custom tool
 */
export interface CustomToolResult {
  /** Tool that was executed */
  tool_id: string;
  /** Whether execution succeeded */
  success: boolean;
  /** Result data (structure depends on tool) */
  data?: unknown;
  /** Error message if failed */
  error?: string;
  /** Execution time in milliseconds */
  execution_time_ms: number;
  /** ISO timestamp when executed */
  executed_at: string;
}

/**
 * Options for registering a custom tool
 */
export interface RegisterToolOptions {
  /** Whether to replace an existing tool with the same name */
  replace_existing?: boolean;
  /** Whether to validate the implementation before registering */
  validate?: boolean;
  /** Test input for validation */
  test_input?: Record<string, unknown>;
}

/**
 * Workflow definition - a sequence of tools to execute
 */
export interface Workflow {
  /** Unique identifier */
  id: string;
  /** Workflow name */
  name: string;
  /** Human-readable description */
  description: string;
  /** Ordered list of steps to execute */
  steps: WorkflowStep[];
  /** Input parameters for the workflow */
  input_schema: CustomToolInputSchema;
  /** Whether this workflow is enabled */
  enabled: boolean;
  /** ISO timestamp when created */
  created_at: string;
  /** Number of times this workflow has been run */
  run_count: number;
}

/**
 * A single step in a workflow
 */
export interface WorkflowStep {
  /** Step identifier (unique within workflow) */
  step_id: string;
  /** Tool ID to execute */
  tool_id: string;
  /** 
   * Input mapping - how to map workflow inputs and previous step outputs to this step's inputs
   * Use {{input.param}} for workflow inputs, {{steps.step_id.field}} for previous outputs
   */
  input_mapping: Record<string, string>;
  /** Whether to continue workflow if this step fails */
  continue_on_error?: boolean;
  /** Condition for executing this step (JavaScript expression) */
  condition?: string;
}
