// Resource definitions and handlers
import {
  getStats,
  analyzeCoverage,
  identifyGaps,
  listByMitre,
  compareDetectionsBySource,
} from '../db/detections.js';
import {
  openEntity,
  listDecisions,
  listLearnings,
  getKnowledgeStats,
} from '../db/knowledge.js';

// =============================================================================
// TYPE DEFINITIONS
// =============================================================================

export interface ResourceDefinition {
  uri: string;
  name: string;
  description: string;
  mimeType: string;
}

export interface ResourceTemplateDefinition {
  uriTemplate: string;
  name: string;
  description: string;
  mimeType: string;
}

// =============================================================================
// STATIC RESOURCES
// =============================================================================

export const resources: ResourceDefinition[] = [
  // Detection resources
  {
    uri: 'detection://stats',
    name: 'Detection Statistics',
    description: 'Current detection index statistics',
    mimeType: 'application/json',
  },
  {
    uri: 'detection://coverage',
    name: 'Coverage Summary',
    description: 'MITRE ATT&CK tactic coverage summary',
    mimeType: 'application/json',
  },
  {
    uri: 'detection://gaps/ransomware',
    name: 'Ransomware Gaps',
    description: 'Current ransomware detection gaps',
    mimeType: 'application/json',
  },
  {
    uri: 'detection://gaps/apt',
    name: 'APT Gaps',
    description: 'Current APT detection gaps',
    mimeType: 'application/json',
  },
  {
    uri: 'detection://top-covered',
    name: 'Top Covered Techniques',
    description: 'Best-covered MITRE techniques',
    mimeType: 'application/json',
  },
  {
    uri: 'detection://sources/comparison',
    name: 'Source Comparison',
    description: 'Quick comparison of detection counts across sources (sigma, splunk, elastic, kql)',
    mimeType: 'application/json',
  },
  // Knowledge graph resources
  {
    uri: 'knowledge://graph/summary',
    name: 'Knowledge Graph Summary',
    description: 'Statistics and overview of the knowledge graph (entities, relations, decisions, learnings)',
    mimeType: 'application/json',
  },
  {
    uri: 'knowledge://decisions/recent',
    name: 'Recent Decisions',
    description: 'Recent analytical decisions and tribal knowledge captured in the knowledge graph',
    mimeType: 'application/json',
  },
  {
    uri: 'knowledge://learnings/all',
    name: 'All Learnings',
    description: 'All stored learnings and insights from the knowledge graph',
    mimeType: 'application/json',
  },
];

// =============================================================================
// RESOURCE TEMPLATES (Parameterized URIs)
// =============================================================================

export const resourceTemplates: ResourceTemplateDefinition[] = [
  {
    uriTemplate: 'detection://technique/{techniqueId}',
    name: 'Technique Detections',
    description: 'Get all detections for a specific MITRE ATT&CK technique (e.g., T1059.001)',
    mimeType: 'application/json',
  },
  {
    uriTemplate: 'detection://actor/{actorName}',
    name: 'Threat Actor Profile',
    description: 'Get threat actor profile and associated detections from knowledge graph',
    mimeType: 'application/json',
  },
  {
    uriTemplate: 'knowledge://entity/{entityName}',
    name: 'Knowledge Entity Details',
    description: 'Get complete knowledge graph entity details including relations and observations',
    mimeType: 'application/json',
  },
];

// =============================================================================
// RESOURCE LISTING
// =============================================================================

export function listResources() {
  return { resources };
}

export function listResourceTemplates() {
  return { resourceTemplates };
}

// =============================================================================
// TEMPLATE HANDLERS
// =============================================================================

/**
 * Get detections for a specific MITRE technique
 */
function getTechniqueResource(techniqueId: string): unknown {
  const detections = listByMitre(techniqueId, 100);
  
  return {
    technique_id: techniqueId,
    detection_count: detections.length,
    detections: detections.map(d => ({
      id: d.id,
      name: d.name,
      source_type: d.source_type,
      severity: d.severity,
      description: d.description?.substring(0, 200) + (d.description && d.description.length > 200 ? '...' : ''),
    })),
    by_source: {
      sigma: detections.filter(d => d.source_type === 'sigma').length,
      splunk_escu: detections.filter(d => d.source_type === 'splunk_escu').length,
      elastic: detections.filter(d => d.source_type === 'elastic').length,
      kql: detections.filter(d => d.source_type === 'kql').length,
    },
  };
}

/**
 * Get threat actor profile from knowledge graph
 */
function getActorResource(actorName: string): unknown {
  const entityResult = openEntity(actorName);
  
  if (!entityResult || !entityResult.entity) {
    return {
      actor_name: actorName,
      found: false,
      message: `No knowledge graph entry found for actor: ${actorName}`,
      suggestion: 'Use knowledge graph tools to create an entity for this threat actor',
    };
  }
  
  const { entity, relations, observations } = entityResult;
  
  // Extract techniques from relations
  const techniques = relations.outgoing
    .filter(r => r.relation_type === 'uses_technique' || r.relation_type === 'associated_with')
    .map(r => r.to_entity);
  
  // Extract related entities
  const relatedEntities = [
    ...relations.outgoing.map(r => ({ name: r.to_entity, relation: r.relation_type, direction: 'outgoing' })),
    ...relations.incoming.map(r => ({ name: r.from_entity, relation: r.relation_type, direction: 'incoming' })),
  ];
  
  return {
    actor_name: entity.name,
    found: true,
    entity_type: entity.entity_type,
    created_at: entity.created_at,
    techniques,
    observations: observations.map(o => ({
      observation: o.observation,
      source: o.source,
      confidence: o.confidence,
    })),
    related_entities: relatedEntities,
    relation_count: relations.outgoing.length + relations.incoming.length,
  };
}

/**
 * Get complete knowledge entity details
 */
function getKnowledgeEntityResource(entityName: string): unknown {
  const entityResult = openEntity(entityName);
  
  if (!entityResult || !entityResult.entity) {
    return {
      entity_name: entityName,
      found: false,
      message: `Entity not found in knowledge graph: ${entityName}`,
    };
  }
  
  const { entity, relations, observations } = entityResult;
  
  return {
    entity: {
      id: entity.id,
      name: entity.name,
      type: entity.entity_type,
      created_at: entity.created_at,
    },
    relations: {
      outgoing: relations.outgoing.map(r => ({
        to: r.to_entity,
        type: r.relation_type,
        reasoning: r.reasoning,
        confidence: r.confidence,
      })),
      incoming: relations.incoming.map(r => ({
        from: r.from_entity,
        type: r.relation_type,
        reasoning: r.reasoning,
        confidence: r.confidence,
      })),
    },
    observations: observations.map(o => ({
      observation: o.observation,
      source: o.source,
      confidence: o.confidence,
      created_at: o.created_at,
    })),
    summary: {
      total_relations: relations.outgoing.length + relations.incoming.length,
      total_observations: observations.length,
    },
  };
}

// =============================================================================
// STATIC RESOURCE CONTENT
// =============================================================================

function getStaticResourceContent(uri: string): unknown {
  switch (uri) {
    case 'detection://stats':
      return getStats();
    
    case 'detection://coverage': {
      const coverage = analyzeCoverage();
      return coverage.summary.coverage_by_tactic;
    }
    
    case 'detection://gaps/ransomware':
      return identifyGaps('ransomware');
    
    case 'detection://gaps/apt':
      return identifyGaps('apt');
    
    case 'detection://top-covered': {
      const coverage = analyzeCoverage();
      return coverage.top_covered;
    }
    
    case 'detection://sources/comparison': {
      // Get overall stats comparison
      const stats = getStats();
      return {
        total_detections: stats.total,
        by_source: {
          sigma: stats.sigma,
          splunk_escu: stats.splunk_escu,
          elastic: stats.elastic,
          kql: stats.kql,
        },
        by_severity: stats.by_severity,
        mitre_coverage: stats.mitre_coverage,
        by_mitre_tactic: stats.by_mitre_tactic,
      };
    }
    
    case 'knowledge://graph/summary':
      return getKnowledgeStats();
    
    case 'knowledge://decisions/recent': {
      const decisions = listDecisions(undefined, 20);
      return {
        count: decisions.length,
        decisions: decisions.map(d => ({
          id: d.id,
          type: d.decision_type,
          context: d.context,
          decision: d.decision,
          reasoning: d.reasoning,
          entities_involved: d.entities_involved,
          outcome: d.outcome,
          created_at: d.created_at,
        })),
      };
    }
    
    case 'knowledge://learnings/all': {
      const learnings = listLearnings(undefined, 50);
      return {
        count: learnings.length,
        learnings: learnings.map(l => ({
          id: l.id,
          type: l.learning_type,
          title: l.title,
          insight: l.insight,
          evidence: l.evidence,
          applications: l.applications,
          times_applied: l.times_applied,
          created_at: l.created_at,
          last_applied: l.last_applied,
        })),
      };
    }
    
    default:
      return null;
  }
}

// =============================================================================
// MAIN READ HANDLER
// =============================================================================

export async function readResource(uri: string) {
  let content: unknown;
  let mimeType = 'application/json';
  
  // Check for template matches first
  const techniqueMatch = uri.match(/^detection:\/\/technique\/(.+)$/);
  if (techniqueMatch) {
    const techniqueId = decodeURIComponent(techniqueMatch[1]);
    content = getTechniqueResource(techniqueId);
    return formatResourceResponse(uri, mimeType, content);
  }
  
  const actorMatch = uri.match(/^detection:\/\/actor\/(.+)$/);
  if (actorMatch) {
    const actorName = decodeURIComponent(actorMatch[1]);
    content = getActorResource(actorName);
    return formatResourceResponse(uri, mimeType, content);
  }
  
  const entityMatch = uri.match(/^knowledge:\/\/entity\/(.+)$/);
  if (entityMatch) {
    const entityName = decodeURIComponent(entityMatch[1]);
    content = getKnowledgeEntityResource(entityName);
    return formatResourceResponse(uri, mimeType, content);
  }
  
  // Fall through to static resources
  content = getStaticResourceContent(uri);
  
  if (content === null) {
    throw new Error(`Resource not found: ${uri}`);
  }
  
  const resource = resources.find(r => r.uri === uri);
  mimeType = resource?.mimeType || 'application/json';
  
  return formatResourceResponse(uri, mimeType, content);
}

/**
 * Format the resource response in MCP format
 */
function formatResourceResponse(uri: string, mimeType: string, content: unknown) {
  return {
    contents: [{
      uri,
      mimeType,
      text: JSON.stringify(content, null, 2),
    }],
  };
}
