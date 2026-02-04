/**
 * Knowledge Graph MCP Tools
 * 
 * 12 tools for managing the tribal knowledge layer:
 * - Entity management (create, delete, open)
 * - Relation management (create with reasoning)
 * - Observation management (add facts, delete)
 * - Decision logging (the WHY behind decisions)
 * - Learning management (reusable patterns)
 * - Search and graph reading
 */

import { defineTool } from '../registry.js';
import {
  createEntity,
  getEntity,
  deleteEntity,
  createRelation,
  addObservation,
  deleteObservation,
  logDecision,
  addLearning,
  applyLearning,
  getRelevantDecisions,
  getRelevantLearnings,
  listLearnings,
  searchKnowledge,
  readGraph,
  openEntity,
  getKnowledgeStats,
} from '../../db/knowledge.js';

export const knowledgeTools = [
  // ============================================================================
  // Tool 1: create_entity
  // ============================================================================
  defineTool({
    name: 'create_entity',
    description: `Create a knowledge entity representing a security concept. Use this to build the knowledge graph with threat actors, techniques, detections, campaigns, tools, vulnerabilities, and data sources.

Entity types:
- threat_actor: APT groups, criminal gangs (e.g., "APT29", "STORM-0501")
- technique: MITRE ATT&CK techniques (e.g., "T1059.001 PowerShell")
- detection: Security detection rules (e.g., "Suspicious PowerShell Execution")
- campaign: Attack campaigns (e.g., "SolarWinds Compromise")
- tool: Attack tools or malware (e.g., "Cobalt Strike", "Mimikatz")
- vulnerability: CVEs (e.g., "CVE-2024-1234")
- data_source: Log sources (e.g., "Windows Security Events")`,
    inputSchema: {
      type: 'object',
      properties: {
        name: {
          type: 'string',
          description: 'Unique name for the entity (e.g., "APT29", "T1059.001", "Cobalt Strike")',
        },
        entity_type: {
          type: 'string',
          description: 'Type of entity: threat_actor, technique, detection, campaign, tool, vulnerability, data_source',
          enum: ['threat_actor', 'technique', 'detection', 'campaign', 'tool', 'vulnerability', 'data_source'],
        },
      },
      required: ['name', 'entity_type'],
    },
    handler: async (args) => {
      const name = args.name as string;
      const entityType = args.entity_type as string;

      if (!name || !entityType) {
        throw new Error('Both name and entity_type are required');
      }

      // Check if entity already exists
      const existing = getEntity(name);
      if (existing) {
        return {
          status: 'exists',
          message: `Entity "${name}" already exists`,
          entity: existing,
        };
      }

      const entity = createEntity(name, entityType);
      return {
        status: 'created',
        entity,
      };
    },
  }),

  // ============================================================================
  // Tool 2: create_relation
  // ============================================================================
  defineTool({
    name: 'create_relation',
    description: `Create a relationship between two entities WITH reasoning explaining WHY they're connected. This is the core of tribal knowledge - capturing not just the connection but the insight behind it.

Relation types:
- uses: Threat actor uses technique/tool (e.g., APT29 uses Cobalt Strike)
- targets: Threat actor targets sector/system
- detects: Detection covers technique
- covers: Detection provides coverage for technique
- mitigates: Control mitigates technique
- exploits: Campaign exploits vulnerability
- attributed_to: Campaign attributed to threat actor
- depends_on: Detection depends on data source
- related_to: General relationship

IMPORTANT: The reasoning field is critical - explain WHY this connection exists.`,
    inputSchema: {
      type: 'object',
      properties: {
        from_entity: {
          type: 'string',
          description: 'Name of the source entity',
        },
        to_entity: {
          type: 'string',
          description: 'Name of the target entity',
        },
        relation_type: {
          type: 'string',
          description: 'Type of relationship: uses, targets, detects, covers, mitigates, exploits, attributed_to, depends_on, related_to',
        },
        reasoning: {
          type: 'string',
          description: 'REQUIRED: WHY does this relationship exist? This captures tribal knowledge.',
        },
        confidence: {
          type: 'number',
          description: 'Confidence in this relationship (0.0-1.0, default 1.0)',
        },
      },
      required: ['from_entity', 'to_entity', 'relation_type', 'reasoning'],
    },
    handler: async (args) => {
      const fromEntity = args.from_entity as string;
      const toEntity = args.to_entity as string;
      const relationType = args.relation_type as string;
      const reasoning = args.reasoning as string;
      const confidence = (args.confidence as number) || 1.0;

      if (!fromEntity || !toEntity || !relationType) {
        throw new Error('from_entity, to_entity, and relation_type are required');
      }

      if (!reasoning) {
        throw new Error('reasoning is required - explain WHY this connection exists');
      }

      const relation = createRelation(fromEntity, toEntity, relationType, reasoning, confidence);
      return {
        status: 'created',
        relation,
        note: 'Tribal knowledge captured in reasoning field',
      };
    },
  }),

  // ============================================================================
  // Tool 3: add_observation
  // ============================================================================
  defineTool({
    name: 'add_observation',
    description: `Add a fact or observation about an entity. Observations capture point-in-time knowledge that can be queried later.

Examples:
- "APT29 has been active since at least 2008"
- "This detection has high false positives in development environments"
- "T1059.001 is commonly used for initial access in ransomware"`,
    inputSchema: {
      type: 'object',
      properties: {
        entity_name: {
          type: 'string',
          description: 'Name of the entity this observation is about',
        },
        observation: {
          type: 'string',
          description: 'The fact or observation to record',
        },
        source: {
          type: 'string',
          description: 'Source of this observation (e.g., "CISA Advisory", "user input", "threat report")',
        },
        confidence: {
          type: 'number',
          description: 'Confidence in this observation (0.0-1.0, default 1.0)',
        },
      },
      required: ['entity_name', 'observation'],
    },
    handler: async (args) => {
      const entityName = args.entity_name as string;
      const observation = args.observation as string;
      const source = args.source as string | undefined;
      const confidence = (args.confidence as number) || 1.0;

      if (!entityName || !observation) {
        throw new Error('entity_name and observation are required');
      }

      const obs = addObservation(entityName, observation, source, confidence);
      return {
        status: 'added',
        observation: obs,
      };
    },
  }),

  // ============================================================================
  // Tool 4: delete_entity
  // ============================================================================
  defineTool({
    name: 'delete_entity',
    description: 'Remove an entity from the knowledge graph. This also removes all relations and observations associated with the entity.',
    inputSchema: {
      type: 'object',
      properties: {
        name: {
          type: 'string',
          description: 'Name or ID of the entity to delete',
        },
      },
      required: ['name'],
    },
    handler: async (args) => {
      const name = args.name as string;

      if (!name) {
        throw new Error('name is required');
      }

      const result = deleteEntity(name);
      if (!result.deleted) {
        return {
          status: 'not_found',
          message: `Entity "${name}" not found`,
        };
      }

      return {
        status: 'deleted',
        message: `Deleted entity "${name}"`,
        relations_removed: result.relations_removed,
        observations_removed: result.observations_removed,
      };
    },
  }),

  // ============================================================================
  // Tool 5: delete_observation
  // ============================================================================
  defineTool({
    name: 'delete_observation',
    description: 'Remove a specific observation by its ID. Use open_entity first to find observation IDs.',
    inputSchema: {
      type: 'object',
      properties: {
        observation_id: {
          type: 'string',
          description: 'UUID of the observation to delete',
        },
      },
      required: ['observation_id'],
    },
    handler: async (args) => {
      const obsId = args.observation_id as string;

      if (!obsId) {
        throw new Error('observation_id is required');
      }

      const deleted = deleteObservation(obsId);
      return {
        status: deleted ? 'deleted' : 'not_found',
        message: deleted ? `Deleted observation ${obsId}` : `Observation ${obsId} not found`,
      };
    },
  }),

  // ============================================================================
  // Tool 6: search_knowledge
  // ============================================================================
  defineTool({
    name: 'search_knowledge',
    description: `Search across all knowledge types: entities, relations, observations, decisions, and learnings. Uses full-text search to find relevant tribal knowledge.

Search examples:
- "PowerShell execution" - Find everything related to PowerShell
- "credential theft" - Find credential-related knowledge
- "APT29" - Find all knowledge about this threat actor`,
    inputSchema: {
      type: 'object',
      properties: {
        query: {
          type: 'string',
          description: 'Search query (supports FTS5 syntax)',
        },
        limit: {
          type: 'number',
          description: 'Maximum results to return (default 30)',
        },
      },
      required: ['query'],
    },
    handler: async (args) => {
      const query = args.query as string;
      const limit = (args.limit as number) || 30;

      if (!query) {
        throw new Error('query is required');
      }

      const results = searchKnowledge(query, limit);
      const stats = getKnowledgeStats();

      return {
        query,
        results,
        total_results: results.length,
        knowledge_stats: {
          total_entities: stats.entities,
          total_relations: stats.relations,
          total_observations: stats.observations,
          total_decisions: stats.decisions,
          total_learnings: stats.learnings,
        },
      };
    },
  }),

  // ============================================================================
  // Tool 7: read_graph
  // ============================================================================
  defineTool({
    name: 'read_graph',
    description: `Read the entire knowledge graph or a filtered subgraph. Returns entities, relations, and observations.

Use this to:
- Get an overview of all stored knowledge
- Filter by entity type to focus on specific concepts
- Understand the structure of captured tribal knowledge`,
    inputSchema: {
      type: 'object',
      properties: {
        entity_type: {
          type: 'string',
          description: 'Filter to specific entity type (threat_actor, technique, detection, etc.)',
        },
        limit: {
          type: 'number',
          description: 'Maximum entities/relations to return (default 500)',
        },
      },
    },
    handler: async (args) => {
      const entityType = args.entity_type as string | undefined;
      const limit = (args.limit as number) || 500;

      const graph = readGraph({ entity_type: entityType, limit });
      const stats = getKnowledgeStats();

      return {
        graph,
        full_stats: stats,
      };
    },
  }),

  // ============================================================================
  // Tool 8: open_entity
  // ============================================================================
  defineTool({
    name: 'open_entity',
    description: `Get complete information about a specific entity including all its relations and observations. This is the detailed view of a single knowledge node.`,
    inputSchema: {
      type: 'object',
      properties: {
        name: {
          type: 'string',
          description: 'Name or ID of the entity to open',
        },
      },
      required: ['name'],
    },
    handler: async (args) => {
      const name = args.name as string;

      if (!name) {
        throw new Error('name is required');
      }

      const result = openEntity(name);
      if (!result) {
        return {
          status: 'not_found',
          message: `Entity "${name}" not found`,
          suggestion: 'Use search_knowledge to find entities, or create_entity to create one',
        };
      }

      return {
        status: 'found',
        ...result,
        summary: {
          outgoing_relations: result.relations.outgoing.length,
          incoming_relations: result.relations.incoming.length,
          observations: result.observations.length,
        },
      };
    },
  }),

  // ============================================================================
  // Tool 9: log_decision
  // ============================================================================
  defineTool({
    name: 'log_decision',
    description: `Record WHY a significant decision was made. This is the gold of tribal knowledge - capturing the reasoning process so future agents can understand past decisions.

Decision types:
- gap_identified: A detection gap was found
- detection_recommended: A specific detection was recommended
- coverage_mapped: Coverage was analyzed and mapped
- priority_assigned: A priority decision was made
- false_positive_tuning: FP tuning recommendation
- threat_assessment: Threat level assessment
- data_source_selected: Data source was chosen

IMPORTANT: Be detailed in the reasoning - this helps future analysis.`,
    inputSchema: {
      type: 'object',
      properties: {
        decision_type: {
          type: 'string',
          description: 'Type of decision being logged',
          enum: ['gap_identified', 'detection_recommended', 'coverage_mapped', 'priority_assigned', 'false_positive_tuning', 'threat_assessment', 'data_source_selected'],
          examples: ['gap_identified', 'detection_recommended'],
        },
        context: {
          type: 'string',
          description: 'The situation/context that led to this decision',
          examples: ['Analyzing ransomware coverage for STORM-0501', 'Evaluating PowerShell detection options'],
        },
        decision: {
          type: 'string',
          description: 'The actual decision that was made',
          examples: ['T1486 has weak coverage', 'Recommend creating behavioral detection for encryption patterns'],
        },
        reasoning: {
          type: 'string',
          description: 'DETAILED explanation of WHY this decision was made - this is the tribal knowledge. Be specific!',
          examples: ['Only 2 detections cover this technique, both rely on file extension monitoring which ransomware can bypass by using random extensions'],
        },
        entities_involved: {
          type: 'array',
          items: { type: 'string' },
          description: 'Names of entities involved in this decision',
          examples: [['STORM-0501', 'T1486', 'ransomware']],
        },
        outcome: {
          type: 'string',
          description: 'Optional outcome or result of the decision',
          examples: ['Created detection XYZ', 'Flagged for next sprint'],
        },
        session_id: {
          type: 'string',
          description: 'Optional session ID to group related decisions',
        },
      },
      required: ['decision_type', 'context', 'decision', 'reasoning'],
    },
    handler: async (args) => {
      const decisionType = args.decision_type as string;
      const context = args.context as string;
      const decision = args.decision as string;
      const reasoning = args.reasoning as string;
      const entitiesInvolved = (args.entities_involved as string[]) || [];
      const outcome = args.outcome as string | undefined;
      const sessionId = args.session_id as string | undefined;

      if (!decisionType || !context || !decision || !reasoning) {
        throw new Error('decision_type, context, decision, and reasoning are all required');
      }

      const logged = logDecision(
        decisionType,
        context,
        decision,
        reasoning,
        entitiesInvolved,
        outcome,
        sessionId
      );

      return {
        status: 'logged',
        decision: logged,
        note: 'Tribal knowledge captured - this decision and reasoning will be available for future analysis',
      };
    },
  }),

  // ============================================================================
  // Tool 10: add_learning
  // ============================================================================
  defineTool({
    name: 'add_learning',
    description: `Store a pattern or insight derived from analysis for future reference. Learnings are reusable knowledge that can help future sessions.

Learning types:
- detection_pattern: A pattern for writing effective detections
- gap_pattern: A recurring type of detection gap
- user_preference: User preferences for analysis style
- false_positive_pattern: Common FP patterns to avoid
- threat_pattern: Recurring threat behaviors
- correlation_insight: Insights about technique correlations
- data_quality_insight: Insights about data source quality

Examples:
- "STORM-0501 consistently uses native tools before deploying ransomware"
- "Detections for T1059.001 need process parent filtering to reduce FPs"
- "User prefers prioritizing detections by MITRE tactic stage"`,
    inputSchema: {
      type: 'object',
      properties: {
        learning_type: {
          type: 'string',
          description: 'Type of learning: detection_pattern, gap_pattern, user_preference, false_positive_pattern, threat_pattern, correlation_insight, data_quality_insight',
        },
        title: {
          type: 'string',
          description: 'Short title for this learning',
        },
        insight: {
          type: 'string',
          description: 'The actual insight or pattern learned',
        },
        evidence: {
          type: 'string',
          description: 'Evidence supporting this learning (observations, decisions that led to it)',
        },
        applications: {
          type: 'string',
          description: 'How this learning can be applied in practice',
        },
      },
      required: ['learning_type', 'title', 'insight'],
    },
    handler: async (args) => {
      const learningType = args.learning_type as string;
      const title = args.title as string;
      const insight = args.insight as string;
      const evidence = args.evidence as string | undefined;
      const applications = args.applications as string | undefined;

      if (!learningType || !title || !insight) {
        throw new Error('learning_type, title, and insight are required');
      }

      const learning = addLearning(learningType, title, insight, evidence, applications);

      return {
        status: 'stored',
        learning,
        note: 'This learning will be suggested in future relevant contexts',
      };
    },
  }),

  // ============================================================================
  // Tool 11: get_relevant_decisions
  // ============================================================================
  defineTool({
    name: 'get_relevant_decisions',
    description: `Get past decisions relevant to the current context. Uses full-text search to find tribal knowledge that applies to your current analysis.

Use this to:
- See how similar situations were handled before
- Understand reasoning behind past recommendations
- Maintain consistency with previous decisions`,
    inputSchema: {
      type: 'object',
      properties: {
        context_query: {
          type: 'string',
          description: 'Description of current context to find relevant decisions (e.g., "ransomware detection gaps", "credential theft coverage")',
        },
        decision_type: {
          type: 'string',
          description: 'Optional filter by decision type',
        },
        session_id: {
          type: 'string',
          description: 'Optional filter by session',
        },
        limit: {
          type: 'number',
          description: 'Maximum decisions to return (default 20)',
        },
      },
      required: ['context_query'],
    },
    handler: async (args) => {
      const contextQuery = args.context_query as string;
      const decisionType = args.decision_type as string | undefined;
      const sessionId = args.session_id as string | undefined;
      const limit = (args.limit as number) || 20;

      if (!contextQuery) {
        throw new Error('context_query is required');
      }

      const decisions = getRelevantDecisions(contextQuery, {
        decision_type: decisionType,
        session_id: sessionId,
        limit,
      });

      return {
        context_query: contextQuery,
        relevant_decisions: decisions,
        count: decisions.length,
        note: decisions.length > 0 
          ? 'These past decisions may inform your current analysis'
          : 'No relevant past decisions found - this may be new territory',
      };
    },
  }),

  // ============================================================================
  // Tool 12: get_learnings
  // ============================================================================
  defineTool({
    name: 'get_learnings',
    description: `Get applicable learnings for the current task. Returns patterns and insights that may help with the current analysis.

Use this to:
- Apply proven patterns to new situations
- Remember user preferences
- Avoid known pitfalls`,
    inputSchema: {
      type: 'object',
      properties: {
        task_query: {
          type: 'string',
          description: 'Description of current task to find relevant learnings (e.g., "writing PowerShell detection", "analyzing APT coverage")',
        },
        learning_type: {
          type: 'string',
          description: 'Optional filter by learning type',
        },
        limit: {
          type: 'number',
          description: 'Maximum learnings to return (default 10)',
        },
        mark_applied: {
          type: 'boolean',
          description: 'If true, increment the times_applied counter for returned learnings',
        },
      },
      required: ['task_query'],
    },
    handler: async (args) => {
      const taskQuery = args.task_query as string;
      const learningType = args.learning_type as string | undefined;
      const limit = (args.limit as number) || 10;
      const markApplied = args.mark_applied as boolean;

      if (!taskQuery) {
        throw new Error('task_query is required');
      }

      const learnings = getRelevantLearnings(taskQuery, {
        learning_type: learningType,
        limit,
      });

      // Optionally mark learnings as applied
      if (markApplied && learnings.length > 0) {
        learnings.forEach(l => applyLearning(l.id));
      }

      // Also get most-applied learnings if query returns few results
      let topLearnings: typeof learnings = [];
      if (learnings.length < 3) {
        topLearnings = listLearnings(learningType, 5);
      }

      return {
        task_query: taskQuery,
        relevant_learnings: learnings,
        top_learnings: topLearnings.length > 0 ? topLearnings : undefined,
        count: learnings.length,
        note: learnings.length > 0
          ? 'Consider applying these learnings to your current task'
          : 'No directly relevant learnings found - consider adding new learnings from this session',
      };
    },
  }),
];

// Export the count for index.ts
export const knowledgeToolCount = knowledgeTools.length;
