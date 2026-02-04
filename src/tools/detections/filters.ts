// Filter tools for detections - list_by_* variants
import { defineTool } from '../registry.js';
import {
  listBySource,
  listByMitre,
  listByLogsource,
  listBySeverity,
  listByCve,
  listByAnalyticStory,
  listByProcessName,
  listByDetectionType,
  listByDataSource,
  listByMitreTactic,
  listByKqlCategory,
  listByKqlTag,
  listByKqlDatasource,
  validateTechniqueId,
} from '../../db/index.js';

export const filterTools = [
  defineTool({
    name: 'list_by_source',
    description: 'List detections filtered by source type',
    inputSchema: {
      type: 'object',
      properties: {
        source_type: {
          type: 'string',
          enum: ['sigma', 'splunk_escu', 'elastic', 'kql'],
          description: 'Source type to filter by',
        },
        limit: {
          type: 'number',
          description: 'Max results to return (default 100)',
        },
        offset: {
          type: 'number',
          description: 'Offset for pagination (default 0)',
        },
      },
      required: ['source_type'],
    },
    handler: async (args) => {
      const sourceType = args.source_type as 'sigma' | 'splunk_escu' | 'elastic' | 'kql';
      const limit = (args.limit as number) || 100;
      const offset = (args.offset as number) || 0;

      if (!sourceType) {
        return { error: true, message: 'source_type is required' };
      }

      const results = listBySource(sourceType, limit, offset);
      return { count: results.length, source_type: sourceType, detections: results };
    },
  }),

  defineTool({
    name: 'list_by_mitre',
    description: 'List detections that map to a specific MITRE ATT&CK technique',
    inputSchema: {
      type: 'object',
      properties: {
        technique_id: {
          type: 'string',
          description: 'MITRE ATT&CK technique ID (e.g., T1059.001)',
        },
        limit: {
          type: 'number',
          description: 'Max results to return (default 100)',
        },
        offset: {
          type: 'number',
          description: 'Offset for pagination (default 0)',
        },
      },
      required: ['technique_id'],
    },
    handler: async (args) => {
      const techniqueId = args.technique_id as string;
      const limit = (args.limit as number) || 100;
      const offset = (args.offset as number) || 0;

      if (!techniqueId) {
        return {
          error: true,
          code: 'MISSING_REQUIRED_ARG',
          message: 'technique_id is required',
          examples: ['T1059.001', 'T1547.001', 'T1003.001'],
          hint: 'Use format T####.### (e.g., T1059.001 for PowerShell)',
        };
      }

      const results = listByMitre(techniqueId, limit, offset);

      if (results.length === 0) {
        const validation = validateTechniqueId(techniqueId);
        return {
          results: [],
          technique_id: techniqueId,
          suggestions: {
            message: validation.suggestion || 'No detections found for this technique',
            similar_techniques: validation.similar,
            try_search: `search("${techniqueId.split('.')[0]}") for broader results`,
            tip: 'Parent techniques (T1059) may catch sub-techniques (T1059.001)',
          },
        };
      }

      return { count: results.length, technique_id: techniqueId, detections: results };
    },
  }),

  defineTool({
    name: 'list_by_logsource',
    description: 'List Sigma detections filtered by logsource (category, product, or service)',
    inputSchema: {
      type: 'object',
      properties: {
        category: {
          type: 'string',
          description: 'Logsource category (e.g., process_creation, network_connection)',
        },
        product: {
          type: 'string',
          description: 'Logsource product (e.g., windows, linux, aws)',
        },
        service: {
          type: 'string',
          description: 'Logsource service (e.g., sysmon, security, powershell)',
        },
        limit: {
          type: 'number',
          description: 'Max results to return (default 100)',
        },
        offset: {
          type: 'number',
          description: 'Offset for pagination (default 0)',
        },
      },
    },
    handler: async (args) => {
      const category = args.category as string | undefined;
      const product = args.product as string | undefined;
      const service = args.service as string | undefined;
      const limit = (args.limit as number) || 100;
      const offset = (args.offset as number) || 0;

      const results = listByLogsource(category, product, service, limit, offset);
      return { count: results.length, filters: { category, product, service }, detections: results };
    },
  }),

  defineTool({
    name: 'list_by_severity',
    description: 'List detections filtered by severity level',
    inputSchema: {
      type: 'object',
      properties: {
        level: {
          type: 'string',
          enum: ['informational', 'low', 'medium', 'high', 'critical'],
          description: 'Severity level to filter by',
        },
        limit: {
          type: 'number',
          description: 'Max results to return (default 100)',
        },
        offset: {
          type: 'number',
          description: 'Offset for pagination (default 0)',
        },
      },
      required: ['level'],
    },
    handler: async (args) => {
      const level = args.level as string;
      const limit = (args.limit as number) || 100;
      const offset = (args.offset as number) || 0;

      if (!level) {
        return { error: true, message: 'level is required' };
      }

      const results = listBySeverity(level, limit, offset);
      return { count: results.length, severity: level, detections: results };
    },
  }),

  defineTool({
    name: 'list_by_cve',
    description: 'List detections that cover a specific CVE vulnerability',
    inputSchema: {
      type: 'object',
      properties: {
        cve_id: {
          type: 'string',
          description: 'CVE ID (e.g., CVE-2024-27198, CVE-2021-44228)',
        },
        limit: {
          type: 'number',
          description: 'Max results to return (default 100)',
        },
        offset: {
          type: 'number',
          description: 'Offset for pagination (default 0)',
        },
      },
      required: ['cve_id'],
    },
    handler: async (args) => {
      const cveId = args.cve_id as string;
      const limit = (args.limit as number) || 100;
      const offset = (args.offset as number) || 0;

      if (!cveId) {
        return { error: true, message: 'cve_id is required' };
      }

      const results = listByCve(cveId, limit, offset);
      return { count: results.length, cve_id: cveId, detections: results };
    },
  }),

  defineTool({
    name: 'list_by_analytic_story',
    description: 'List Splunk detections that belong to a specific analytic story (e.g., "Ransomware", "Data Destruction")',
    inputSchema: {
      type: 'object',
      properties: {
        story: {
          type: 'string',
          description: 'Analytic story name or partial match (e.g., "Ransomware", "Windows Persistence")',
        },
        limit: {
          type: 'number',
          description: 'Max results to return (default 100)',
        },
        offset: {
          type: 'number',
          description: 'Offset for pagination (default 0)',
        },
      },
      required: ['story'],
    },
    handler: async (args) => {
      const story = args.story as string;
      const limit = (args.limit as number) || 100;
      const offset = (args.offset as number) || 0;

      if (!story) {
        return { error: true, message: 'story is required' };
      }

      const results = listByAnalyticStory(story, limit, offset);
      return { count: results.length, story, detections: results };
    },
  }),

  defineTool({
    name: 'list_by_process_name',
    description: 'List detections that reference a specific process name (e.g., "powershell.exe", "w3wp.exe", "cmd.exe")',
    inputSchema: {
      type: 'object',
      properties: {
        process_name: {
          type: 'string',
          description: 'Process name to search for (e.g., "powershell.exe", "cmd.exe", "nginx.exe")',
        },
        limit: {
          type: 'number',
          description: 'Max results to return (default 100)',
        },
        offset: {
          type: 'number',
          description: 'Offset for pagination (default 0)',
        },
      },
      required: ['process_name'],
    },
    handler: async (args) => {
      const processName = args.process_name as string;
      const limit = (args.limit as number) || 100;
      const offset = (args.offset as number) || 0;

      if (!processName) {
        return { error: true, message: 'process_name is required' };
      }

      const results = listByProcessName(processName, limit, offset);
      return { count: results.length, process_name: processName, detections: results };
    },
  }),

  defineTool({
    name: 'list_by_detection_type',
    description: 'List detections by type (TTP, Anomaly, Hunting, Correlation)',
    inputSchema: {
      type: 'object',
      properties: {
        detection_type: {
          type: 'string',
          enum: ['TTP', 'Anomaly', 'Hunting', 'Correlation'],
          description: 'Detection type to filter by',
        },
        limit: {
          type: 'number',
          description: 'Max results to return (default 100)',
        },
        offset: {
          type: 'number',
          description: 'Offset for pagination (default 0)',
        },
      },
      required: ['detection_type'],
    },
    handler: async (args) => {
      const detectionType = args.detection_type as string;
      const limit = (args.limit as number) || 100;
      const offset = (args.offset as number) || 0;

      if (!detectionType) {
        return { error: true, message: 'detection_type is required' };
      }

      const results = listByDetectionType(detectionType, limit, offset);
      return { count: results.length, detection_type: detectionType, detections: results };
    },
  }),

  defineTool({
    name: 'list_by_data_source',
    description: 'List detections that use a specific data source (e.g., "Sysmon", "Windows Security", "process_creation")',
    inputSchema: {
      type: 'object',
      properties: {
        data_source: {
          type: 'string',
          description: 'Data source to search for (e.g., "Sysmon", "Windows Security", "process_creation")',
        },
        limit: {
          type: 'number',
          description: 'Max results to return (default 100)',
        },
        offset: {
          type: 'number',
          description: 'Offset for pagination (default 0)',
        },
      },
      required: ['data_source'],
    },
    handler: async (args) => {
      const dataSource = args.data_source as string;
      const limit = (args.limit as number) || 100;
      const offset = (args.offset as number) || 0;

      if (!dataSource) {
        return { error: true, message: 'data_source is required' };
      }

      const results = listByDataSource(dataSource, limit, offset);
      return { count: results.length, data_source: dataSource, detections: results };
    },
  }),

  defineTool({
    name: 'list_by_mitre_tactic',
    description: 'List detections by MITRE ATT&CK tactic (e.g., "execution", "persistence", "credential-access")',
    inputSchema: {
      type: 'object',
      properties: {
        tactic: {
          type: 'string',
          enum: [
            'reconnaissance', 'resource-development', 'initial-access', 'execution',
            'persistence', 'privilege-escalation', 'defense-evasion', 'credential-access',
            'discovery', 'lateral-movement', 'collection', 'command-and-control',
            'exfiltration', 'impact',
          ],
          description: 'MITRE ATT&CK tactic to filter by',
        },
        limit: {
          type: 'number',
          description: 'Max results to return (default 100)',
        },
        offset: {
          type: 'number',
          description: 'Offset for pagination (default 0)',
        },
      },
      required: ['tactic'],
    },
    handler: async (args) => {
      const tactic = args.tactic as string;
      const limit = (args.limit as number) || 100;
      const offset = (args.offset as number) || 0;

      if (!tactic) {
        return { error: true, message: 'tactic is required' };
      }

      const results = listByMitreTactic(tactic, limit, offset);
      return { count: results.length, tactic, detections: results };
    },
  }),

  defineTool({
    name: 'list_by_kql_category',
    description: 'List KQL detections filtered by category (e.g., "Defender For Endpoint", "Azure Active Directory", "Threat Hunting")',
    inputSchema: {
      type: 'object',
      properties: {
        category: {
          type: 'string',
          description: 'KQL category derived from folder path (e.g., "Defender For Endpoint", "DFIR", "Sentinel")',
        },
        limit: {
          type: 'number',
          description: 'Max results to return (default 100)',
        },
        offset: {
          type: 'number',
          description: 'Offset for pagination (default 0)',
        },
      },
      required: ['category'],
    },
    handler: async (args) => {
      const category = args.category as string;
      const limit = (args.limit as number) || 100;
      const offset = (args.offset as number) || 0;

      if (!category) {
        return { error: true, message: 'category is required' };
      }

      const results = listByKqlCategory(category, limit, offset);
      return { count: results.length, category, detections: results };
    },
  }),

  defineTool({
    name: 'list_by_kql_tag',
    description: 'List KQL detections filtered by tag (e.g., "ransomware", "hunting", "ti-feed")',
    inputSchema: {
      type: 'object',
      properties: {
        tag: {
          type: 'string',
          description: 'Tag to filter by (e.g., "ransomware", "dfir", "apt")',
        },
        limit: {
          type: 'number',
          description: 'Max results to return (default 100)',
        },
        offset: {
          type: 'number',
          description: 'Offset for pagination (default 0)',
        },
      },
      required: ['tag'],
    },
    handler: async (args) => {
      const tag = args.tag as string;
      const limit = (args.limit as number) || 100;
      const offset = (args.offset as number) || 0;

      if (!tag) {
        return { error: true, message: 'tag is required' };
      }

      const results = listByKqlTag(tag, limit, offset);
      return { count: results.length, tag, detections: results };
    },
  }),

  defineTool({
    name: 'list_by_kql_datasource',
    description: 'List KQL detections that use a specific Microsoft data source (e.g., "DeviceProcessEvents", "SigninLogs", "EmailEvents")',
    inputSchema: {
      type: 'object',
      properties: {
        data_source: {
          type: 'string',
          description: 'Microsoft KQL table name (e.g., "DeviceProcessEvents", "AADSignInEventsBeta", "CloudAppEvents")',
        },
        limit: {
          type: 'number',
          description: 'Max results to return (default 100)',
        },
        offset: {
          type: 'number',
          description: 'Offset for pagination (default 0)',
        },
      },
      required: ['data_source'],
    },
    handler: async (args) => {
      const dataSource = args.data_source as string;
      const limit = (args.limit as number) || 100;
      const offset = (args.offset as number) || 0;

      if (!dataSource) {
        return { error: true, message: 'data_source is required' };
      }

      const results = listByKqlDatasource(dataSource, limit, offset);
      return { count: results.length, data_source: dataSource, detections: results };
    },
  }),
];
