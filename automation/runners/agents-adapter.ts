import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { existsSync, statSync, mkdtempSync, writeFileSync, rmSync, realpathSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve, isAbsolute, relative, sep } from 'node:path';

const execFileAsync = promisify(execFile);
const RESULT_MARKER = 'Pipeline result saved to: detection-pipeline-result.json';
export class BlockedError extends Error {}
export type AdapterMode = 'disabled' | 'dry-run' | 'live';
export interface FeedItem { id: string; title: string; content: string | null; url: string | null; feed_source: string }
export interface AdapterResult {
  status: 'simulated' | 'awaiting_approval';
  mode: AdapterMode;
  pipeline: Record<string, unknown>;
}
export interface AdapterOptions {
  mode?: AdapterMode;
  cliPath?: string;
  timeoutMs?: number;
  env?: NodeJS.ProcessEnv;
}
function record(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === 'object' && !Array.isArray(value);
}
function records(value: unknown): value is Record<string, unknown>[] {
  return Array.isArray(value) && value.every(record);
}

/** Fail closed on changed CLI output, early graph exits and structured errors. */
export function parsePipelineOutput(stdout: string, mode: AdapterMode): AdapterResult {
  const marker = stdout.lastIndexOf(RESULT_MARKER);
  if (marker < 0) throw new Error('Agents CLI did not return its result marker');
  let state: unknown;
  try { state = JSON.parse(stdout.slice(marker + RESULT_MARKER.length).trim()); }
  catch { throw new Error('Agents CLI returned invalid JSON'); }
  if (!record(state) || typeof state.workflow_id !== 'string' || !state.workflow_id ||
      typeof state.current_step !== 'string' || !records(state.techniques) ||
      !records(state.gaps) || !records(state.detections) || !records(state.atomic_tests) ||
      !records(state.prs) || !Array.isArray(state.errors) || !Array.isArray(state.warnings) ||
      !Array.isArray(state.attack_data_paths) || typeof state.requires_approval !== 'boolean') {
    throw new Error('Malformed agents pipeline result');
  }
  if (state.errors.length) throw new Error('Agents pipeline returned errors; inspect its configuration and artifacts');
  if (!state.techniques.length || !state.techniques.every(t => typeof t.id === 'string' && /^T\d{4}(\.\d{3})?$/.test(t.id))) {
    throw new BlockedError('No valid techniques extracted; empty work cannot be marked completed');
  }
  if (mode === 'dry-run') return { status: 'simulated', mode, pipeline: state };
  if (mode !== 'live') throw new BlockedError('Live adapter mode is not enabled');
  if (state.warnings.some(w => typeof w !== 'string' || /dry.run|mock|skipped|not implemented/i.test(w))) {
    throw new BlockedError('Pipeline used simulated or incomplete work; human investigation required');
  }
  // Coverage currently does not provide per-technique success evidence on early exit.
  // An empty gaps array therefore cannot establish that coverage was actually checked.
  if (state.current_step !== 'awaiting_approval' || state.requires_approval !== true ||
      state.approved === true || state.prs.length !== 0) {
    throw new BlockedError(`Pipeline stopped at ${state.current_step}; only unstaged results awaiting human review are accepted`);
  }
  if (!state.atomic_tests.every(t => t.execution_status === 'completed')) {
    throw new BlockedError('Some atomic tests did not complete');
  }
  if (!state.detections.length || !state.detections.every(d =>
    typeof d.id === 'string' && typeof d.file_path === 'string' && d.file_path.length > 0 &&
    d.status === 'validated' && d.qa_status === 'pass' &&
    record(d.validation_result) && d.validation_result.passed === true &&
    typeof d.validation_result.event_count === 'number' && d.validation_result.event_count > 0 &&
    state.atomic_tests instanceof Array && state.atomic_tests.some(t => record(t) &&
      t.technique_id === d.technique_id && t.execution_status === 'completed'))) {
    throw new BlockedError('Detection, QA, atomic, or SIEM evidence is incomplete');
  }
  if (!state.attack_data_paths.length || !state.attack_data_paths.every(p => typeof p === 'string' && p.length)) {
    throw new BlockedError('Attack data export evidence is missing');
  }
  return { status: 'awaiting_approval', mode, pipeline: state };
}

/** Invoke the already-built agents CLI with argv, never interpolate feed text into a shell. */
export function createAgentsAdapter(options: AdapterOptions = {}): (feed: FeedItem) => Promise<AdapterResult> {
  const env = options.env ?? process.env;
  const mode = options.mode ?? (env.AUTOMATION_MODE || 'disabled');
  const cliPath = resolve(options.cliPath ?? env.AGENTS_CLI_PATH ?? join(__dirname, '../../../agents/dist/src/cli.js'));
  const timeout = options.timeoutMs ?? 30 * 60 * 1000;
  return async (feed) => {
    if (mode !== 'dry-run' && mode !== 'live') throw new BlockedError('Set AUTOMATION_MODE=dry-run or explicitly opt into live mode');
    if (!existsSync(cliPath)) throw new BlockedError('Agents CLI is missing; install and build agents/ or set AGENTS_CLI_PATH');
    if (mode === 'live' && !env.ANTHROPIC_API_KEY) throw new BlockedError('Live mode requires ANTHROPIC_API_KEY; mock fallback is not accepted');
    if (mode === 'live') {
      for (const key of ['SECURITY_CONTENT_PATH', 'ATTACK_DATA_PATH', 'ATTACK_RANGE_PATH']) {
        const path = env[key];
        if (!path || !isAbsolute(path) || !existsSync(path) || !statSync(path).isDirectory()) {
          throw new BlockedError(`Live mode requires an existing absolute ${key}`);
        }
      }
    }
    if (!Number.isFinite(timeout) || timeout <= 0) throw new BlockedError('Adapter timeout must be positive');
    const workspace = mkdtempSync(join(tmpdir(), 'detection-automation-'));
    try {
      const input = join(workspace, 'input.txt');
      writeFileSync(input, `Title: ${feed.title}\nURL: ${feed.url || ''}\n\n${feed.content || ''}`, { mode: 0o600 });
      let stdout: string;
      try {
        const result = await execFileAsync(process.execPath, [cliPath, 'orchestrate', '--type', 'threat_report', '--file', input], {
          cwd: workspace,
          timeout,
          killSignal: 'SIGKILL',
          maxBuffer: 8 * 1024 * 1024,
          env: { ...env, DRY_RUN: mode === 'dry-run' ? 'true' : 'false' },
          windowsHide: true,
        });
        stdout = result.stdout;
      } catch {
        // Child output may contain source text or secrets. Do not persist it in queue errors.
        throw new Error('Agents CLI failed, timed out, or exceeded output limit');
      }
      const result = parsePipelineOutput(stdout, mode);
      if (mode === 'live') {
        const detections = result.pipeline.detections as Record<string, unknown>[];
        const contentRoot = resolve(env.SECURITY_CONTENT_PATH || join(workspace, 'security_content'));
        const artifacts = [...detections.map(d => resolve(contentRoot, String(d.file_path))),
          ...(result.pipeline.attack_data_paths as string[]).map(p => resolve(workspace, p))];
        if (!artifacts.every(p => {
          if (!existsSync(p)) return false;
          const relativePath = relative(realpathSync(workspace), realpathSync(p));
          return statSync(p).isFile() && statSync(p).size > 0 &&
            (relativePath === '..' || relativePath.startsWith(`..${sep}`) || isAbsolute(relativePath));
        })) {
          throw new BlockedError('Pipeline artifacts are missing or temporary; configure persistent absolute repository paths');
        }
      }
      return result;
    } finally {
      rmSync(workspace, { recursive: true, force: true });
    }
  };
}
