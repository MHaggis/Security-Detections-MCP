/**
 * Threat Actor Coverage Analysis Tools
 *
 * MCP tools for analyzing detection coverage against specific
 * MITRE ATT&CK threat actors using STIX-sourced data.
 */

import { defineTool } from '../registry.js';
import {
  isStixLoaded,
  getActorByName,
  listActors,
  getActorTechniques,
  getActorCoverage,
  getSoftwareForActor,
  getAttackStats,
  generateNavigatorLayer,
} from '../../db/index.js';

const SOURCE_TYPES = ['sigma', 'splunk_escu', 'elastic', 'kql', 'sublime', 'crowdstrike_cql', 'jamf_protect'] as const;

function stixNotLoadedError() {
  return {
    error: true,
    code: 'STIX_NOT_LOADED',
    message: 'MITRE ATT&CK STIX data not loaded. Set the ATTACK_STIX_PATH environment variable to the path of enterprise-attack.json. Download from: https://github.com/mitre-attack/attack-stix-data',
  };
}

export const actorAnalysisTools = [
  defineTool({
    name: 'analyze_actor_coverage',
    description: 'Analyze detection coverage against a specific threat actor. Shows which of the actor\'s known MITRE ATT&CK techniques have detections, coverage percentage, and prioritized gaps. Requires STIX data (ATTACK_STIX_PATH env var).',
    inputSchema: {
      type: 'object',
      properties: {
        actor_name: {
          type: 'string',
          description: 'Threat actor name or alias (e.g., APT29, Cozy Bear, Lazarus Group, FIN7, HAFNIUM)',
        },
        source_type: {
          type: 'string',
          enum: [...SOURCE_TYPES],
          description: 'Filter detections to a specific source (optional)',
        },
        include_navigator_layer: {
          type: 'boolean',
          description: 'Include ATT&CK Navigator layer JSON in response (default: false)',
        },
      },
      required: ['actor_name'],
    },
    handler: async (args) => {
      if (!isStixLoaded()) return stixNotLoadedError();

      const actorName = args.actor_name as string;
      const sourceType = args.source_type as string | undefined;
      const includeNavigator = args.include_navigator_layer as boolean | undefined;

      const actor = getActorByName(actorName);
      if (!actor) {
        return {
          error: true,
          code: 'ACTOR_NOT_FOUND',
          message: `Threat actor not found: "${actorName}". Use list_actors to browse available actors.`,
        };
      }

      const coverage = getActorCoverage(actor.actor_id, sourceType);

      const result: Record<string, unknown> = {
        actor_name: coverage.actor.name,
        aliases: coverage.actor.aliases,
        total_techniques: coverage.total_techniques,
        covered_count: coverage.covered_count,
        gap_count: coverage.gap_count,
        coverage_percentage: coverage.coverage_percentage,
        coverage_by_tactic: coverage.by_tactic,
        covered_techniques: coverage.covered_techniques.map(t => ({
          technique_id: t.technique_id,
          name: t.technique_name,
          detection_count: t.detection_count,
          tactics: t.tactics,
        })),
        gap_techniques: coverage.gap_techniques.map(t => ({
          technique_id: t.technique_id,
          name: t.technique_name,
          tactics: t.tactics,
          priority: t.tactics.some(tac =>
            ['initial-access', 'execution', 'persistence', 'credential-access'].includes(tac)
          ) ? 'HIGH' : 'MEDIUM',
        })),
      };

      if (includeNavigator) {
        result.navigator_layer = generateNavigatorLayer({
          name: `${coverage.actor.name} Coverage`,
          description: `Detection coverage for ${coverage.actor.name} (${coverage.actor.aliases.join(', ')})`,
          actor_name: actorName,
        });
      }

      return result;
    },
  }),

  defineTool({
    name: 'list_actors',
    description: 'List all known MITRE ATT&CK threat actors with aliases and technique counts. Requires STIX data (ATTACK_STIX_PATH env var).',
    inputSchema: {
      type: 'object',
      properties: {
        search: {
          type: 'string',
          description: 'Search by actor name or alias (optional)',
        },
        limit: {
          type: 'number',
          description: 'Maximum results to return (default: 50)',
        },
      },
    },
    handler: async (args) => {
      if (!isStixLoaded()) return stixNotLoadedError();

      const search = args.search as string | undefined;
      const limit = (args.limit as number) || 50;

      const actors = listActors(search, limit);
      const stats = getAttackStats();

      return {
        total_actors: stats.actors,
        showing: actors.length,
        actors: actors.map(a => ({
          name: a.name,
          aliases: a.aliases,
          technique_count: a.technique_count,
        })),
      };
    },
  }),

  defineTool({
    name: 'compare_actor_coverage',
    description: 'Compare detection coverage across multiple threat actors. Shows shared technique gaps and unique risks per actor. Requires STIX data (ATTACK_STIX_PATH env var).',
    inputSchema: {
      type: 'object',
      properties: {
        actor_names: {
          type: 'array',
          items: { type: 'string' },
          description: 'List of threat actor names to compare (2-5 actors)',
        },
        source_type: {
          type: 'string',
          enum: [...SOURCE_TYPES],
          description: 'Filter detections to a specific source (optional)',
        },
      },
      required: ['actor_names'],
    },
    handler: async (args) => {
      if (!isStixLoaded()) return stixNotLoadedError();

      const actorNames = args.actor_names as string[];
      const sourceType = args.source_type as string | undefined;

      if (actorNames.length < 2 || actorNames.length > 5) {
        return { error: true, message: 'Provide 2-5 actor names for comparison' };
      }

      const coverages: Array<{
        name: string;
        coverage_percentage: number;
        total: number;
        covered: number;
        gaps: Set<string>;
        techniques: Set<string>;
      }> = [];

      for (const name of actorNames) {
        const actor = getActorByName(name);
        if (!actor) {
          return { error: true, message: `Actor not found: "${name}"` };
        }
        const cov = getActorCoverage(actor.actor_id, sourceType);
        coverages.push({
          name: cov.actor.name,
          coverage_percentage: cov.coverage_percentage,
          total: cov.total_techniques,
          covered: cov.covered_count,
          gaps: new Set(cov.gap_techniques.map(t => t.technique_id)),
          techniques: new Set([
            ...cov.covered_techniques.map(t => t.technique_id),
            ...cov.gap_techniques.map(t => t.technique_id),
          ]),
        });
      }

      // Find shared gaps (techniques that are gaps for ALL actors)
      const allGaps = coverages.map(c => c.gaps);
      const sharedGaps = [...allGaps[0]].filter(
        gap => allGaps.every(gs => gs.has(gap))
      );

      // Find unique techniques per actor (not used by any other)
      const uniqueTechniques: Record<string, string[]> = {};
      for (const cov of coverages) {
        const otherTechs = coverages
          .filter(c => c.name !== cov.name)
          .flatMap(c => [...c.techniques]);
        const otherSet = new Set(otherTechs);
        uniqueTechniques[cov.name] = [...cov.techniques].filter(t => !otherSet.has(t));
      }

      return {
        comparison: coverages.map(c => ({
          actor: c.name,
          total_techniques: c.total,
          covered: c.covered,
          coverage_percentage: c.coverage_percentage,
        })),
        shared_gaps: sharedGaps,
        shared_gap_count: sharedGaps.length,
        unique_techniques_per_actor: Object.fromEntries(
          Object.entries(uniqueTechniques).map(([k, v]) => [k, { count: v.length, techniques: v.slice(0, 20) }])
        ),
        recommendation: sharedGaps.length > 0
          ? `${sharedGaps.length} techniques are gaps across ALL compared actors — prioritize these for maximum coverage improvement.`
          : 'No shared gaps — each actor has distinct coverage gaps.',
      };
    },
  }),

  defineTool({
    name: 'get_actor_profile',
    description: 'Get full threat actor dossier: description, aliases, known techniques, software employed, and detection coverage status. Requires STIX data (ATTACK_STIX_PATH env var).',
    inputSchema: {
      type: 'object',
      properties: {
        actor_name: {
          type: 'string',
          description: 'Threat actor name or alias',
        },
      },
      required: ['actor_name'],
    },
    handler: async (args) => {
      if (!isStixLoaded()) return stixNotLoadedError();

      const actorName = args.actor_name as string;

      const actor = getActorByName(actorName);
      if (!actor) {
        return {
          error: true,
          code: 'ACTOR_NOT_FOUND',
          message: `Threat actor not found: "${actorName}". Use list_actors to browse available actors.`,
        };
      }

      const techniques = getActorTechniques(actor.actor_id);
      const software = getSoftwareForActor(actor.actor_id);
      const coverage = getActorCoverage(actor.actor_id);

      return {
        name: actor.name,
        aliases: actor.aliases,
        description: actor.description,
        modified: actor.modified,
        technique_count: techniques.length,
        techniques: techniques.map(t => ({
          technique_id: t.technique_id,
          name: t.technique_name,
          detection_count: t.detection_count,
          covered: t.detection_count > 0,
          tactics: t.tactics,
          procedure_context: t.description ? t.description.substring(0, 300) : null,
        })),
        software: software.map(s => ({
          name: s.name,
          type: s.software_type,
          platforms: s.platforms,
        })),
        coverage_summary: {
          total_techniques: coverage.total_techniques,
          covered: coverage.covered_count,
          gaps: coverage.gap_count,
          coverage_percentage: coverage.coverage_percentage,
          by_tactic: coverage.by_tactic,
        },
      };
    },
  }),
];
