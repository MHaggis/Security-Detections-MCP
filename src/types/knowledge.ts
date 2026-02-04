/**
 * Knowledge Graph Types
 * Types for the agent memory and knowledge graph system
 * Stores entities, relations, observations, decisions, and learnings
 */

/**
 * A knowledge entity represents a discrete concept in the security domain
 * Examples: threat actors, techniques, detections, campaigns, tools
 */
export interface KnowledgeEntity {
  /** Unique identifier for the entity */
  id: string;
  /** Human-readable name */
  name: string;
  /** 
   * Type classification for the entity
   * Common types: threat_actor, technique, detection, campaign, tool, vulnerability, data_source
   */
  entity_type: string;
  /** ISO timestamp when entity was created */
  created_at: string;
}

/**
 * A relation connects two entities with a typed relationship
 * Captures the connections and dependencies between security concepts
 */
export interface KnowledgeRelation {
  /** Unique identifier for the relation */
  id: string;
  /** Entity ID or name that this relation originates from */
  from_entity: string;
  /** Entity ID or name that this relation points to */
  to_entity: string;
  /** 
   * Type of relationship
   * Common types: uses, targets, detects, covers, mitigates, exploits, attributed_to
   */
  relation_type: string;
  /** 
   * WHY this connection was made - the reasoning behind the relationship
   * This captures tribal knowledge about why entities are connected
   */
  reasoning?: string;
  /** Confidence score (0.0-1.0) in this relationship */
  confidence: number;
  /** ISO timestamp when relation was created */
  created_at: string;
}

/**
 * An observation is a discrete fact or note about an entity
 * Captures point-in-time information learned about entities
 */
export interface KnowledgeObservation {
  /** Unique identifier for the observation */
  id: string;
  /** Entity name this observation is about */
  entity_name: string;
  /** The actual observation content */
  observation: string;
  /** Source of this observation (e.g., threat report, user input, analysis) */
  source?: string;
  /** Confidence score (0.0-1.0) in this observation */
  confidence: number;
  /** ISO timestamp when observation was recorded */
  created_at: string;
}

/**
 * A decision records a significant analytical decision made during a session
 * This captures the reasoning process - the "tribal knowledge" gold
 */
export interface KnowledgeDecision {
  /** Unique identifier for the decision */
  id: string;
  /** 
   * Type of decision made
   * Common types: gap_identified, detection_recommended, coverage_mapped, 
   * priority_assigned, false_positive_tuning, threat_assessment
   */
  decision_type: string;
  /** The context that led to this decision */
  context: string;
  /** The actual decision that was made */
  decision: string;
  /** 
   * WHY - the reasoning behind the decision
   * This is the most valuable field - captures expert thinking
   */
  reasoning: string;
  /** List of entity IDs or names involved in this decision */
  entities_involved: string[];
  /** Optional outcome or result of the decision */
  outcome?: string;
  /** Session ID to group related decisions */
  session_id?: string;
  /** ISO timestamp when decision was made */
  created_at: string;
}

/**
 * A learning represents a pattern or insight derived from multiple observations/decisions
 * These are reusable patterns that can be applied to future analysis
 */
export interface KnowledgeLearning {
  /** Unique identifier for the learning */
  id: string;
  /** 
   * Type of learning
   * Common types: detection_pattern, gap_pattern, user_preference, 
   * false_positive_pattern, threat_pattern, correlation_insight
   */
  learning_type: string;
  /** Short title describing the learning */
  title: string;
  /** The actual insight or pattern learned */
  insight: string;
  /** Evidence that supports this learning (observations, decisions that led to it) */
  evidence?: string;
  /** How this learning can be applied in practice */
  applications?: string;
  /** Number of times this learning has been applied */
  times_applied: number;
  /** ISO timestamp when learning was first recorded */
  created_at: string;
  /** ISO timestamp when learning was last applied */
  last_applied?: string;
}

/**
 * Query options for retrieving knowledge
 */
export interface KnowledgeQueryOptions {
  /** Filter by entity type */
  entity_type?: string;
  /** Filter by relation type */
  relation_type?: string;
  /** Filter by decision type */
  decision_type?: string;
  /** Filter by learning type */
  learning_type?: string;
  /** Filter by session ID */
  session_id?: string;
  /** Minimum confidence threshold (0.0-1.0) */
  min_confidence?: number;
  /** Maximum number of results */
  limit?: number;
  /** ISO timestamp to filter results after this date */
  since?: string;
}
