import { describe, it, expect, vi, beforeEach } from 'vitest';
import { setConfig, loadConfig, resetConfig } from '../../config.js';

const MOCK_LLM_RESPONSE = {
  "techniques": [
    {
      "id": "T1003.001",
      "name": "LSASS Memory",
      "tactic": "Credential Access",
      "confidence": 0.95,
      "context": "Report describes using procdump to dump LSASS"
    },
    {
      "id": "T1059.001",
      "name": "PowerShell",
      "tactic": "Execution",
      "confidence": 0.8,
      "context": "PowerShell used for download cradle"
    }
  ]
};

const mockInvoke = vi.fn();
const mockWithStructuredOutput = vi.fn().mockImplementation(() => ({ invoke: mockInvoke }));

vi.mock('@langchain/anthropic', () => ({
  ChatAnthropic: vi.fn().mockImplementation(function () {
    return {
      withStructuredOutput: mockWithStructuredOutput,
    };
  }),
}));

// Static import so the mock is resolved before the module loads
import { ctiAnalystNode } from '../../nodes/cti-analyst.js';

describe('ctiAnalystNode', () => {
  beforeEach(() => {
    resetConfig();
    const cfg = loadConfig();
    cfg.anthropicApiKey = 'test-key';
    cfg.dryRun = false;
    setConfig(cfg);
    vi.clearAllMocks();
    mockInvoke.mockResolvedValue(MOCK_LLM_RESPONSE);
  });

  it('extracts techniques from threat intel', async () => {
    const state: any = {
      input_type: 'threat_report',
      input_content: 'APT group used procdump to dump LSASS memory and PowerShell download cradle.',
      techniques: [],
      gaps: [],
      detections: [],
      atomic_tests: [],
      attack_data_paths: [],
      prs: [],
      errors: [],
      warnings: [],
    };

    const result = await ctiAnalystNode(state);

    expect(mockWithStructuredOutput).toHaveBeenCalledOnce();
    expect(mockInvoke).toHaveBeenCalledWith(expect.stringContaining(state.input_content));
    expect(result.techniques).toEqual(MOCK_LLM_RESPONSE.techniques);
    expect(result.techniques!.length).toBe(2);
    expect(result.techniques![0].id).toBe('T1003.001');
    expect(result.techniques![1].id).toBe('T1059.001');
    expect(result.current_step).toBe('cti_analysis_complete');
  });

  it('handles empty LLM response gracefully', async () => {
    mockInvoke.mockResolvedValueOnce({ techniques: [] });

    const state: any = {
      input_content: 'Nothing interesting here.',
      techniques: [],
      errors: [],
    };

    const result = await ctiAnalystNode(state);
    expect(result.techniques).toEqual([]);
    expect(result.current_step).toBe('cti_analysis_complete');
    expect(result.errors).toBeUndefined();
  });

  it('handles LLM error gracefully', async () => {
    mockInvoke.mockRejectedValueOnce(new Error('API rate limit'));

    const state: any = {
      input_content: 'test content',
      techniques: [],
      errors: [],
    };

    const result = await ctiAnalystNode(state);
    expect(result.techniques).toEqual([]);
    expect(result.errors).toBeDefined();
    expect(result.errors![0]).toContain('rate limit');
    expect(result.current_step).toBe('cti_analysis_failed');
  });
});
