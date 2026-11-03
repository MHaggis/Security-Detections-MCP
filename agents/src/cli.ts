#!/usr/bin/env node
/**
 * Detection Agents CLI
 * 
 * Command-line interface for the autonomous detection engineering pipeline.
 * Can be run from CLI, CI/CD, or invoked from Cursor.
 */

import 'dotenv/config';
import { Command } from 'commander';
import { readFileSync, existsSync } from 'fs';
import { runDetectionPipeline } from '../graphs/detection-pipeline.js';
import { getConfig, validateConfig } from '../config.js';

const program = new Command();

program
  .name('detection-agents')
  .description('Autonomous detection engineering powered by LangGraph')
  .version('3.0.0');

/**
 * Resolve input content from --url, --file, or --input flags.
 * Returns the resolved text or exits with an error.
 */
async function resolveInput(options: { url?: string; file?: string; input?: string; content?: string }): Promise<string> {
  if (options.url) {
    console.log(`Fetching content from: ${options.url}`);
    try {
      const resp = await fetch(options.url);
      if (!resp.ok) throw new Error(`HTTP ${resp.status}`);
      return await resp.text();
    } catch (err) {
      console.error(`Failed to fetch URL: ${err instanceof Error ? err.message : err}`);
      process.exit(1);
    }
  }

  if (options.file) {
    if (!existsSync(options.file)) {
      console.error(`File not found: ${options.file}`);
      process.exit(1);
    }
    return readFileSync(options.file, 'utf-8');
  }

  // --input and --content both map here (--content is the alias)
  const text = options.input || options.content;
  if (text) return text;

  console.error('Must provide --url, --file, --input, or --content');
  process.exit(1);
}

// ------------- orchestrate ------------------------------------------------

program
  .command('orchestrate')
  .description('Run the full detection engineering pipeline')
  .option('-t, --type <type>', 'Input type: threat_report, technique, cisa_alert, manual', 'threat_report')
  .option('-u, --url <url>', 'URL to fetch threat intel from')
  .option('-f, --file <file>', 'File containing threat intel')
  .option('-i, --input <input>', 'Direct input text')
  .option('-c, --content <content>', 'Direct input text (alias for --input)')
  .option('--no-approval', 'Skip approval requirement for PR staging')
  .action(async (options) => {
    const inputContent = await resolveInput(options);

    try {
      const result = await runDetectionPipeline(
        options.type,
        inputContent,
        options.url
      );

      console.log('\nPipeline result saved to: detection-pipeline-result.json');
      console.log(JSON.stringify(result, null, 2));
    } catch (error) {
      console.error('Pipeline failed:', error);
      process.exit(1);
    }
  });

// ------------- analyze ----------------------------------------------------

program
  .command('analyze')
  .description('Analyze threat intel for TTPs and coverage gaps (no detection creation)')
  .option('-u, --url <url>', 'URL to fetch threat intel from')
  .option('-f, --file <file>', 'File containing threat intel')
  .option('-i, --input <input>', 'Direct input text')
  .option('-c, --content <content>', 'Direct input text (alias for --input)')
  .option('--technique <id>', 'MITRE technique ID to analyze coverage for')
  .action(async (options) => {
    let inputContent: string;

    if (options.technique) {
      inputContent = `${options.technique}`;
    } else {
      inputContent = await resolveInput(options);
    }

    try {
      const { ctiAnalystNode } = await import('../nodes/cti-analyst.js');
      const { coverageAnalyzerNode } = await import('../nodes/coverage-analyzer.js');
      const { randomUUID } = await import('node:crypto');

      const state = {
        input_type: 'technique' as const,
        input_content: inputContent,
        techniques: [],
        gaps: [],
        detections: [],
        atomic_tests: [],
        attack_data_paths: [],
        prs: [],
        workflow_id: randomUUID(),
        current_step: 'initialized',
        errors: [] as string[],
        warnings: [] as string[],
        started_at: new Date().toISOString(),
        requires_approval: false,
      };

      console.log('═══════════════════════════════════════════════════════════════');
      console.log('   Analyze Mode (CTI + Coverage only)');
      console.log('═══════════════════════════════════════════════════════════════\n');

      const afterCti = await ctiAnalystNode(state);
      Object.assign(state, afterCti);

      if (state.techniques.length === 0) {
        console.log('\nNo techniques extracted from input.');
        process.exit(0);
      }

      const afterCoverage = await coverageAnalyzerNode(state);
      Object.assign(state, afterCoverage);

      console.log('\n═══════════════════════════════════════════════════════════════');
      console.log('   Analysis Complete');
      console.log('═══════════════════════════════════════════════════════════════');
      console.log(`Techniques extracted: ${state.techniques.length}`);
      console.log(`Gaps identified: ${state.gaps.length}`);
      if (state.gaps.length > 0) {
        console.log('\nGaps:');
        state.gaps.forEach((g: any) => console.log(`  [${g.priority}] ${g.technique_id} - ${g.reason}`));
      }
    } catch (error) {
      console.error('Analysis failed:', error);
      process.exit(1);
    }
  });

// ------------- validate ---------------------------------------------------

program
  .command('validate')
  .description('Validate existing detections via Attack Range')
  .option('-d, --detection <path>', 'Path to detection YAML')
  .option('-t, --technique <id>', 'MITRE technique ID to validate')
  .action(async (options) => {
    if (!options.detection && !options.technique) {
      console.error('Must provide --detection or --technique');
      process.exit(1);
    }

    const cfg = getConfig();
    const issues = validateConfig(cfg);
    if (issues.length > 0) {
      console.error('Config issues:');
      issues.forEach(i => console.error(`  - ${i}`));
    }

    if (options.detection && !existsSync(options.detection)) {
      console.error(`Detection file not found: ${options.detection}`);
      process.exit(1);
    }

    console.log('═══════════════════════════════════════════════════════════════');
    console.log('   Validate Mode');
    console.log('═══════════════════════════════════════════════════════════════');

    if (options.detection) {
      console.log(`Detection: ${options.detection}`);
    }
    if (options.technique) {
      console.log(`Technique: ${options.technique}`);
    }

    console.log(`\nSIEM Platform: ${cfg.dryRun ? 'DRY RUN' : (process.env.SIEM_PLATFORM || 'splunk')}`);

    if (cfg.dryRun) {
      console.log('\n[Dry Run] Skipping actual validation');
      console.log('Validation would:');
      console.log('  1. Check Attack Range status');
      console.log('  2. Run Atomic Red Team tests');
      console.log('  3. Wait for log ingestion');
      console.log('  4. Execute detection query in SIEM');
      console.log('  5. Report pass/fail');
      process.exit(0);
    }

    try {
      const { getAttackRangeTool } = await import('../tools/attack-range.js');
      const tool = getAttackRangeTool();
      const status = await tool.getStatus();

      if (!status.running) {
        console.error('\nAttack Range is not running.');
        console.error('Start it with: cd $ATTACK_RANGE_PATH && python attack_range.py build');
        process.exit(1);
      }

      console.log(`\nAttack Range: Running`);
      console.log(`  Splunk: ${status.splunk_url}`);
      console.log(`  Target: ${status.windows_target}`);

      if (options.technique) {
        console.log(`\nRunning atomic test for ${options.technique}...`);
        const result = await tool.runAtomicTest(options.technique);
        console.log(`  Result: ${result.success ? 'PASSED' : 'FAILED'}`);
        if (result.error) console.log(`  Error: ${result.error}`);
      }
    } catch (error) {
      console.error('Validation failed:', error instanceof Error ? error.message : error);
      process.exit(1);
    }
  });

// ------------- status -----------------------------------------------------

program
  .command('status')
  .description('Check status of Attack Range and MCPs')
  .action(async () => {
    console.log('═══════════════════════════════════════════════════════════════');
    console.log('   Pipeline Status');
    console.log('═══════════════════════════════════════════════════════════════\n');

    const cfg = getConfig();
    const issues = validateConfig(cfg);

    // Config status
    console.log('Configuration:');
    console.log(`  SIEM Platform:  ${process.env.SIEM_PLATFORM || 'splunk (default)'}`);
    console.log(`  LLM Model:      ${cfg.llmModel}`);
    console.log(`  API Key:        ${cfg.anthropicApiKey ? 'Set' : 'NOT SET'}`);
    console.log(`  Content Path:   ${cfg.securityContentPath} ${existsSync(cfg.securityContentPath) ? '(exists)' : '(NOT FOUND)'}`);
    console.log(`  Dry Run:        ${cfg.dryRun}`);
    console.log(`  Splunk MCP:     ${cfg.splunkMcpEnabled}`);

    if (issues.length > 0) {
      console.log('\n  Issues:');
      issues.forEach(i => console.log(`    ⚠ ${i}`));
    }

    // MCP status
    console.log('\nMCP Servers:');
    try {
      const { getMCPClient } = await import('../tools/mcp-client.js');
      const client = getMCPClient();
      const result = await client.callTool({
        server: 'security-detections',
        tool: 'get_stats',
        arguments: {},
      });
      if (result.success) {
        const stats = result.result as any;
        console.log(`  security-detections: OK (${stats.total} detections)`);
      } else {
        console.log(`  security-detections: Error - ${result.error}`);
      }
    } catch {
      console.log('  security-detections: Not reachable');
    }

    // Attack Range status
    console.log('\nAttack Range:');
    const arPath = cfg.attackRangePath;
    if (!existsSync(arPath)) {
      console.log(`  Path: ${arPath} (NOT FOUND)`);
      console.log('  Status: Not configured');
    } else {
      try {
        const { getAttackRangeTool } = await import('../tools/attack-range.js');
        const tool = getAttackRangeTool();
        const arStatus = await tool.getStatus();
        console.log(`  Path: ${arPath}`);
        console.log(`  Status: ${arStatus.running ? 'Running' : 'Not running'}`);
        if (arStatus.running) {
          console.log(`  Splunk URL: ${arStatus.splunk_url}`);
          console.log(`  Windows Target: ${arStatus.windows_target}`);
          if (arStatus.target_ip) console.log(`  Target IP: ${arStatus.target_ip}`);
        }
      } catch {
        console.log(`  Path: ${arPath}`);
        console.log('  Status: Error checking status');
      }
    }

    console.log('');
  });

program.parse();
