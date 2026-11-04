const fs = require('node:fs');
const args = process.argv.slice(2);
if (args[0] !== 'orchestrate' || args.includes('--no-approval')) process.exit(4);
const input = fs.readFileSync(args[args.indexOf('--file') + 1], 'utf8');
const scenario = process.env.TEST_SCENARIO || 'good';
if (scenario === 'failure') { console.error('secret-like child output must not enter queue errors'); process.exit(2); }
if (scenario === 'timeout') { setInterval(() => {}, 1000); return; }
if (scenario === 'malformed') { console.log('Pipeline result saved to: detection-pipeline-result.json\nnot-json'); return; }
const state = {
  workflow_id: 'fixture-workflow', current_step: 'awaiting_approval',
  input_content: input, child_dry_run: process.env.DRY_RUN,
  techniques: [{ id: 'T1059.001' }], gaps: [{ technique_id: 'T1059.001' }],
  detections: [{ id: 'fixture-detection', technique_id: 'T1059.001', file_path: process.env.TEST_ARTIFACT || '/fixture/detection.yml',
    status: 'validated', qa_status: 'pass', validation_result: { passed: true, event_count: 2 } }],
  atomic_tests: [{ technique_id: 'T1059.001', execution_status: 'completed' }],
  attack_data_paths: [process.env.TEST_ARTIFACT || '/fixture/data.json'], prs: [], errors: [], warnings: [],
  requires_approval: true,
};
if (scenario === 'empty') state.techniques = [];
if (scenario === 'incomplete') state.current_step = 'siem_validation_complete';
if (scenario === 'error') state.errors = ['failed validation'];
if (scenario === 'mock-live') state.warnings = ['Dry-run mode: using mock data'];
if (scenario === 'coverage-exit') { state.current_step = 'coverage_analysis_complete'; state.gaps = []; state.detections = []; }
if (scenario === 'temporary-artifact') { const path = require('node:path').join(process.cwd(), '..nested', 'artifact.yml'); fs.mkdirSync(require('node:path').dirname(path)); fs.writeFileSync(path, 'temporary'); state.detections[0].file_path = path; state.attack_data_paths = [path]; }
if (scenario === 'external-pr') state.prs = [{ status: 'draft', url: 'https://example.invalid/pr' }];
console.log('Agents log preamble');
console.log('Pipeline result saved to: detection-pipeline-result.json');
console.log(JSON.stringify(state));
