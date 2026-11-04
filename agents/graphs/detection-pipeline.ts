/**
 * Detection Engineering Pipeline Graph
 * 
 * LangGraph workflow that orchestrates the full threat-to-detection pipeline:
 * 1. CTI Analysis       - Extract TTPs from threat intel
 * 2. Coverage Analysis   - Identify gaps in existing detections
 * 3. Detection Engineer  - Create detections for gaps
 * 4. QA Review           - Quality checks on generated detections
 * 5. FP Analysis         - False positive risk assessment
 * 6. Atomic Execution    - Run atomic tests via Attack Range
 * 7. SIEM Validation     - Verify detections fire (any SIEM)
 * 8. Data Dump           - Export attack data for attack_data repo
 * 9. PR Staging          - Create DRAFT PRs for human review
 * 10. Verification       - Post-pipeline integrity check
 */

import { StateGraph, END, START, Annotation } from '@langchain/langgraph';
import { randomUUID } from 'node:crypto';

import { ctiAnalystNode } from '../nodes/cti-analyst.js';
import { coverageAnalyzerNode } from '../nodes/coverage-analyzer.js';
import { detectionEngineerNode } from '../nodes/detection-engineer.js';
import { qaReviewerNode } from '../nodes/qa-reviewer.js';
import { fpAnalystNode } from '../nodes/fp-analyst.js';
import { atomicExecutorNode } from '../nodes/atomic-executor.js';
import { siemValidatorNode } from '../nodes/siem-validator.js';
import { dataDumperNode } from '../nodes/data-dumper.js';
import { prStagerNode } from '../nodes/pr-stager.js';
import { verifierNode } from '../nodes/verifier.js';

const PipelineStateAnnotation = Annotation.Root({
  input_type: Annotation<'threat_report' | 'technique' | 'cisa_alert' | 'manual'>(),
  input_content: Annotation<string>(),
  input_url: Annotation<string | undefined>(),
  techniques: Annotation<Array<{
    id: string;
    name: string;
    tactic: string;
    confidence: number;
    context: string;
  }>>({
    default: () => [],
    reducer: (a, b) => b ?? a,
  }),
  gaps: Annotation<Array<{
    technique_id: string;
    technique_name: string;
    priority: 'high' | 'medium' | 'low';
    reason: string;
    data_source_available: boolean;
  }>>({
    default: () => [],
    reducer: (a, b) => b ?? a,
  }),
  detections: Annotation<Array<{
    id: string;
    name: string;
    technique_id: string;
    file_path: string;
    status: 'draft' | 'validated' | 'failed';
    search?: string;
    data_source?: string[];
    security_domain?: string;
    asset_type?: string;
    qa_status?: 'pass' | 'fail' | 'needs_improvement';
    qa_issues?: string[];
    fp_risk?: 'low' | 'medium' | 'high' | 'critical';
    fp_recommendations?: string[];
    validation_result?: {
      passed: boolean;
      event_count: number;
      error?: string;
    };
  }>>({
    default: () => [],
    reducer: (a, b) => b ?? a,
  }),
  atomic_tests: Annotation<Array<{
    technique_id: string;
    test_name: string;
    execution_status: 'pending' | 'running' | 'completed' | 'failed';
    output?: string;
    error?: string;
  }>>({
    default: () => [],
    reducer: (a, b) => b ?? a,
  }),
  attack_data_paths: Annotation<string[]>({
    default: () => [],
    reducer: (a, b) => b ?? a,
  }),
  prs: Annotation<Array<{
    repo: string;
    number?: number;
    url?: string;
    branch?: string;
    status: 'draft' | 'staged' | 'merged' | 'failed' | 'pending';
  }>>({
    default: () => [],
    reducer: (a, b) => b ?? a,
  }),
  workflow_id: Annotation<string>(),
  current_step: Annotation<string>(),
  errors: Annotation<string[]>({
    default: () => [],
    reducer: (a, b) => [...(a ?? []), ...(b ?? [])],
  }),
  warnings: Annotation<string[]>({
    default: () => [],
    reducer: (a, b) => [...(a ?? []), ...(b ?? [])],
  }),
  started_at: Annotation<string>(),
  completed_at: Annotation<string | undefined>(),
  requires_approval: Annotation<boolean>(),
  approval_reason: Annotation<string | undefined>(),
  approved: Annotation<boolean | undefined>(),
});

export type PipelineState = typeof PipelineStateAnnotation.State;

// ── Edge conditions ─────────────────────────────────────────

function shouldContinueToDetections(state: PipelineState): string {
  if (state.gaps.length === 0) {
    console.log('[Pipeline] No gaps found - ending');
    return '__end__';
  }
  return 'detection_engineer';
}

function shouldContinueToAtomic(state: PipelineState): string {
  const passedQA = state.detections.filter(
    d => !d.qa_status || d.qa_status === 'pass' || d.qa_status === 'needs_improvement'
  );
  if (passedQA.length === 0) {
    console.log('[Pipeline] All detections failed QA - ending');
    return '__end__';
  }
  return 'atomic_executor';
}

function shouldContinueToDataDump(state: PipelineState): string {
  const validatedCount = state.detections.filter(d => d.status === 'validated').length;
  if (validatedCount === 0) {
    console.log('[Pipeline] No validated detections - ending');
    return '__end__';
  }
  return 'data_dumper';
}

function handleApproval(state: PipelineState): string {
  if (state.requires_approval && !state.approved) {
    return '__end__';
  }
  return 'verifier';
}

// ── Graph construction ──────────────────────────────────────

export function createDetectionPipeline() {
  const workflow = new StateGraph(PipelineStateAnnotation)
    // Phase 1-2: Intel + Coverage
    .addNode('cti_analyst', ctiAnalystNode)
    .addNode('coverage_analyzer', coverageAnalyzerNode)
    // Phase 3: Create detections
    .addNode('detection_engineer', detectionEngineerNode)
    // Phase 4-5: Quality gates
    .addNode('qa_reviewer', qaReviewerNode)
    .addNode('fp_analyst', fpAnalystNode)
    // Phase 6-7: Test + Validate
    .addNode('atomic_executor', atomicExecutorNode)
    .addNode('siem_validator', siemValidatorNode)
    // Phase 8-9: Export + Stage
    .addNode('data_dumper', dataDumperNode)
    .addNode('pr_stager', prStagerNode)
    // Phase 10: Verify
    .addNode('verifier', verifierNode)

    // Edges
    .addEdge(START, 'cti_analyst')
    .addEdge('cti_analyst', 'coverage_analyzer')
    .addConditionalEdges('coverage_analyzer', shouldContinueToDetections, {
      'detection_engineer': 'detection_engineer',
      '__end__': END,
    })
    .addEdge('detection_engineer', 'qa_reviewer')
    .addEdge('qa_reviewer', 'fp_analyst')
    .addConditionalEdges('fp_analyst', shouldContinueToAtomic, {
      'atomic_executor': 'atomic_executor',
      '__end__': END,
    })
    .addEdge('atomic_executor', 'siem_validator')
    .addConditionalEdges('siem_validator', shouldContinueToDataDump, {
      'data_dumper': 'data_dumper',
      '__end__': END,
    })
    .addEdge('data_dumper', 'pr_stager')
    .addConditionalEdges('pr_stager', handleApproval, {
      'verifier': 'verifier',
      '__end__': END,
    })
    .addEdge('verifier', END);

  return workflow.compile();
}

// ── Helpers ─────────────────────────────────────────────────

export function createInitialState(
  inputType: PipelineState['input_type'],
  inputContent: string,
  inputUrl?: string
): Partial<PipelineState> {
  return {
    input_type: inputType,
    input_content: inputContent,
    input_url: inputUrl,
    techniques: [],
    gaps: [],
    detections: [],
    atomic_tests: [],
    attack_data_paths: [],
    prs: [],
    workflow_id: randomUUID(),
    current_step: 'initialized',
    errors: [],
    started_at: new Date().toISOString(),
    requires_approval: true,
  };
}

export async function runDetectionPipeline(
  inputType: PipelineState['input_type'],
  inputContent: string,
  inputUrl?: string
): Promise<PipelineState> {
  console.log('═══════════════════════════════════════════════════════════════');
  console.log('   Detection Engineering Pipeline v3.0');
  console.log('═══════════════════════════════════════════════════════════════');
  console.log(`Input type: ${inputType}`);
  console.log(`Input URL: ${inputUrl || 'N/A'}`);
  console.log(`SIEM Platform: ${process.env.SIEM_PLATFORM || 'splunk'}`);
  console.log('');

  const pipeline = createDetectionPipeline();
  const initialState = createInitialState(inputType, inputContent, inputUrl);

  console.log(`Workflow ID: ${initialState.workflow_id}`);
  console.log('Starting pipeline...\n');

  try {
    const finalState = await pipeline.invoke(initialState);

    finalState.completed_at = new Date().toISOString();

    console.log('\n═══════════════════════════════════════════════════════════════');
    console.log('   Pipeline Complete');
    console.log('═══════════════════════════════════════════════════════════════');
    console.log(`Techniques extracted: ${finalState.techniques.length}`);
    console.log(`Gaps identified: ${finalState.gaps.length}`);
    console.log(`Detections created: ${finalState.detections.length}`);
    console.log(`Detections validated: ${finalState.detections.filter((d: any) => d.status === 'validated').length}`);
    console.log(`PRs staged: ${finalState.prs.filter((p: any) => p.status === 'staged' || p.status === 'draft').length}`);

    if (finalState.errors.length > 0) {
      console.log(`\nErrors: ${finalState.errors.length}`);
      finalState.errors.forEach((e: string) => console.log(`  - ${e}`));
    }

    return finalState as PipelineState;

  } catch (error) {
    console.error('Pipeline failed:', error);
    throw error;
  }
}
