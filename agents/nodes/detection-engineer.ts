/**
 * Detection Engineer Node
 * 
 * Creates Splunk detection YAMLs for coverage gaps.
 * Follows security_content conventions and CIM patterns.
 */

import { ChatAnthropic } from '@langchain/anthropic';
import { writeFileSync, existsSync, mkdirSync } from 'fs';
import { join } from 'path';
import { randomUUID } from 'node:crypto';
import { getConfig } from '../config.js';
import type { PipelineState, Gap, Detection } from '../state/types.js';

const DETECTION_ENGINEER_PROMPT = `You are an expert Splunk detection engineer for the security_content repository.

Create a detection YAML that:
1. Uses tstats with CIM data models (Endpoint.Processes, Network_Traffic, etc.)
2. Uses standard macros (\`process_powershell\`, \`sysmon\`, etc.)
3. Ends with a filter macro (\`detection_name_filter\`)
4. Has proper RBA risk scoring
5. Includes drilldown searches
6. Maps accurately to MITRE ATT&CK

CRITICAL: Follow this EXACT pattern used by 90%+ of the repository:

\`\`\`yaml
name: Windows_Technique_Description
id: <UUID>
version: 1
date: 'YYYY-MM-DD'
author: Autonomous Detection Agent, Splunk
status: production
type: TTP
description: Description of what this detects and why it matters.
data_source:
- Sysmon EventID 1
search: |
 | tstats \`security_content_summariesonly\` count min(_time) as firstTime max(_time) as lastTime 
 from datamodel=Endpoint.Processes 
 where Processes.process_name="suspicious.exe"
 by Processes.dest Processes.user Processes.process Processes.parent_process
 Processes.process_name Processes.process_id Processes.parent_process_name
 | \`drop_dm_object_name(Processes)\` 
 | \`security_content_ctime(firstTime)\` 
 | \`security_content_ctime(lastTime)\`
 | \`detection_name_filter\`
how_to_implement: Data requirements here.
known_false_positives: Expected benign triggers.
references:
- https://attack.mitre.org/techniques/TXXXX/
drilldown_searches:
- name: View the detection results for - "$dest$" and "$user$"
  search: '%original_detection_search% | search dest="$dest$" user="$user$"'
  earliest_offset: $info_min_time$
  latest_offset: $info_max_time$
- name: View risk events for the last 7 days for - "$dest$" and "$user$"
  search: '| from datamodel Risk.All_Risk | search normalized_risk_object IN ("$dest$", "$user$") starthoursago=168'
  earliest_offset: $info_min_time$
  latest_offset: $info_max_time$
rba:
  message: Risk message with $field$ variables
  risk_objects:
  - field: dest
    type: system
    score: 50
  - field: user
    type: user
    score: 50
  threat_objects:
  - field: process_name
    type: process_name
tags:
  analytic_story:
  - Story Name
  asset_type: Endpoint
  mitre_attack_id:
  - T1234.001
  product:
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
  security_domain: endpoint
  cve: []
tests:
- name: True Positive Test
  attack_data:
  - data: https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/...
    sourcetype: XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
    source: XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
\`\`\`

Create a detection for this technique gap:
`;

export async function detectionEngineerNode(state: PipelineState): Promise<Partial<PipelineState>> {
  console.log('[Detection Engineer] Creating detections for gaps...');
  
  // Filter to gaps with available data sources
  const gapsToAddress = state.gaps.filter(g => g.data_source_available && g.priority === 'high');
  
  if (gapsToAddress.length === 0) {
    console.log('[Detection Engineer] No high-priority gaps with available data sources');
    return { current_step: 'detection_creation_complete' };
  }

  const cfg = getConfig();
  const detectionsPath = join(cfg.securityContentPath, 'detections');
  
  // Dry-run mode: return mock detections
  if (cfg.dryRun || !cfg.anthropicApiKey) {
    console.log('[Detection Engineer] Dry-run mode - returning mock detections');
    const mockDetections: Detection[] = gapsToAddress.slice(0, cfg.maxDetectionsPerRun).map(gap => ({
      id: randomUUID(),
      name: `mock_detection_${gap.technique_id.toLowerCase().replace('.', '_')}`,
      file_path: join(detectionsPath, 'endpoint', `mock_${gap.technique_id.toLowerCase().replace('.', '_')}.yml`),
      technique_id: gap.technique_id,
      status: 'draft' as const,
      search: `| tstats count from datamodel=Endpoint.Processes where Processes.process_name="*" by Processes.dest | mock for ${gap.technique_id}`,
    }));
    
    console.log(`[Detection Engineer] Mock created ${mockDetections.length} detection(s)`);
    mockDetections.forEach(d => console.log(`  - ${d.name} (${d.technique_id})`));
    
    return {
      detections: mockDetections,
      current_step: 'detection_creation_complete',
      warnings: ['Dry-run mode: detections not actually written to disk'],
    };
  }
  
  const model = new ChatAnthropic({
    modelName: cfg.llmModel,
    temperature: 0,
  });

  const detections: Detection[] = [];
  const today = new Date().toISOString().split('T')[0];

  for (const gap of gapsToAddress.slice(0, cfg.maxDetectionsPerRun)) {
    try {
      console.log(`[Detection Engineer] Creating detection for ${gap.technique_id}...`);
      
      const context = state.techniques.find(t => t.id === gap.technique_id)?.context || '';
      
      const prompt = DETECTION_ENGINEER_PROMPT + `
Technique ID: ${gap.technique_id}
Technique Name: ${gap.technique_name}
Context from threat intel: ${context}
Today's date: ${today}
UUID to use: ${randomUUID()}

Return ONLY the complete YAML content, no explanation.`;

      const response = await model.invoke(prompt);
      const content = typeof response.content === 'string' 
        ? response.content 
        : JSON.stringify(response.content);
      
      // Extract YAML from response
      const yamlMatch = content.match(/```yaml\n([\s\S]*?)```/) || 
                       content.match(/name:[\s\S]*/);
      
      if (!yamlMatch) {
        console.log(`[Detection Engineer] Failed to extract YAML for ${gap.technique_id}`);
        continue;
      }

      const yamlContent = yamlMatch[1] || yamlMatch[0];
      
      // Extract detection name from YAML
      const nameMatch = yamlContent.match(/name:\s*(.+)/);
      const detectionName = nameMatch ? nameMatch[1].trim() : `windows_${gap.technique_id.toLowerCase().replace('.', '_')}_detection`;
      
      // Generate filename (snake_case)
      const fileName = detectionName.toLowerCase().replace(/\s+/g, '_').replace(/[^a-z0-9_]/g, '') + '.yml';
      const filePath = join(detectionsPath, 'endpoint', fileName);
      
      // Write detection file
      const endpointDir = join(detectionsPath, 'endpoint');
      if (!existsSync(endpointDir)) {
        mkdirSync(endpointDir, { recursive: true });
      }
      
      writeFileSync(filePath, yamlContent);
      console.log(`[Detection Engineer] Written: ${filePath}`);
      
      detections.push({
        id: randomUUID(),
        name: detectionName,
        file_path: filePath,
        technique_id: gap.technique_id,
        status: 'draft',
      });

    } catch (error) {
      console.error(`[Detection Engineer] Error creating detection for ${gap.technique_id}:`, error);
    }
  }

  console.log(`[Detection Engineer] Created ${detections.length} detection(s)`);

  return {
    detections,
    current_step: 'detection_creation_complete',
  };
}
