import { describe, it, expect, vi, beforeEach } from 'vitest';
import { setConfig, loadConfig, resetConfig } from '../../config.js';
import { mkdirSync, existsSync, readFileSync } from 'fs';
import { join } from 'path';
import { tmpdir } from 'os';

const tmpDir = join(tmpdir(), `det-eng-test-${Date.now()}`);

// Mock the LLM to return a valid detection YAML
vi.mock('@langchain/anthropic', () => ({
  ChatAnthropic: vi.fn().mockImplementation(function () {
    return {
      invoke: vi.fn().mockResolvedValue({
        content: `\`\`\`yaml
name: Windows LSASS Memory Dump Via Procdump
id: 00000000-0000-0000-0000-000000000001
version: 1
date: '2026-02-06'
author: Autonomous Detection Agent, Splunk
status: production
type: TTP
description: Detects LSASS memory dumping via procdump.
data_source:
- Sysmon EventID 1
search: |
  | tstats \\\`security_content_summariesonly\\\` count from datamodel=Endpoint.Processes where Processes.process_name="procdump*" by Processes.dest Processes.user
  | \\\`drop_dm_object_name(Processes)\\\`
  | \\\`windows_lsass_memory_dump_via_procdump_filter\\\`
tags:
  mitre_attack_id:
  - T1003.001
  product:
  - Splunk Enterprise
\`\`\``,
      }),
    };
  }),
}));

describe('detectionEngineerNode', () => {
  beforeEach(() => {
    resetConfig();
    const cfg = loadConfig();
    cfg.securityContentPath = tmpDir;
    cfg.anthropicApiKey = 'test-key';
    cfg.maxDetectionsPerRun = 2;
    setConfig(cfg);

    if (!existsSync(tmpDir)) {
      mkdirSync(tmpDir, { recursive: true });
    }
  });

  it('creates detection YAML for high-priority gaps', async () => {
    const { detectionEngineerNode } = await import('../../nodes/detection-engineer.js');

    const state: any = {
      techniques: [
        { id: 'T1003.001', name: 'LSASS Memory', tactic: 'Credential Access', confidence: 0.9, context: 'procdump LSASS dumping' },
      ],
      gaps: [
        { technique_id: 'T1003.001', technique_name: 'LSASS Memory', priority: 'high', reason: 'No coverage', data_source_available: true },
      ],
      detections: [],
      errors: [],
    };

    const result = await detectionEngineerNode(state);

    expect(result.detections).toBeDefined();
    expect(result.detections!.length).toBe(1);
    expect(result.detections![0].technique_id).toBe('T1003.001');
    expect(result.detections![0].status).toBe('draft');

    // file should exist on disk
    const filePath = result.detections![0].file_path;
    expect(existsSync(filePath)).toBe(true);

    const content = readFileSync(filePath, 'utf-8');
    expect(content).toContain('name:');
    expect(content).toContain('T1003.001');
  });

  it('skips gaps without available data sources', async () => {
    const { detectionEngineerNode } = await import('../../nodes/detection-engineer.js');

    const state: any = {
      techniques: [],
      gaps: [
        { technique_id: 'T9999.999', technique_name: 'Fake', priority: 'high', reason: 'test', data_source_available: false },
      ],
      detections: [],
      errors: [],
    };

    const result = await detectionEngineerNode(state);
    expect(result.detections?.length ?? 0).toBe(0);
  });
});
