# Detection Agents - LangGraph Autonomous Pipeline

The core autonomous detection engineering pipeline built with LangGraph v1.x.

> **First time?** See the [Setup Guide](../SETUP.md) for prerequisites (Node.js 20+, build tools) and platform-specific instructions.

## Quick Start

```bash
# Install dependencies (force npm registry)
npm install --registry https://registry.npmjs.org/

# Configure environment
cp .env.example .env
# Edit .env: set SIEM_PLATFORM, ANTHROPIC_API_KEY, SECURITY_CONTENT_PATH

# Type check
npm run typecheck

# Build
npm run build

# Test with dry run first (no lab or LLM calls)
DRY_RUN=true npm run orchestrate -- --type technique --input "T1566.004 Spearphishing Voice"

# Run with real LLM (creates actual detections)
npm run orchestrate -- --type technique --input "T1566.004 Spearphishing Voice"
```

### ⚠️ Important Notes

1. **Coverage-aware behavior**: The pipeline checks existing detections first. If coverage exists, it will skip detection creation (this is correct behavior).
   - ✅ `T1566.004` - No existing coverage → Creates detection
   - ⚠️ `T1003.001` - 100+ existing detections → Skips (no gap)

2. **Dry run vs Real run**:
   - `DRY_RUN=true` - Uses mock data, no LLM calls, no file writes
   - Normal run - Calls LLM, creates YAML files, attempts atomic tests

3. **Attack Range requirement**: Atomic tests and validation require Attack Range to be running. If not available, the pipeline will create detections but skip validation (expected behavior).

## Pipeline Overview

The pipeline adapts to your SIEM via `SIEM_PLATFORM` (set in `.env`). See [docs/E2E-TESTING-GUIDE.md](../docs/E2E-TESTING-GUIDE.md) for full setup per SIEM.

```
Input (CISA Alert / Threat Report / Technique)
    │
    ▼
┌─────────────┐
│ CTI Analyst │  Extract MITRE ATT&CK techniques
└─────────────┘
    │
    ▼
┌──────────────────┐
│ Coverage Analyzer│  Check existing coverage, identify gaps
└──────────────────┘
    │
    ▼
┌────────────────────┐
│ Detection Engineer │  Generate detections (SPL / KQL / EQL / Sigma)
└────────────────────┘
    │
    ▼
┌──────────────┐
│ QA Reviewer  │  Quality checks on generated detections
└──────────────┘
    │
    ▼
┌──────────────┐
│ FP Analyst   │  False positive risk assessment
└──────────────┘
    │
    ▼
┌──────────────────┐
│ Atomic Executor  │  Run Atomic Red Team tests on lab targets
└──────────────────┘
    │
    ▼
┌──────────────────┐
│ SIEM Validator   │  Validate detections fire (any SIEM via SIEM_PLATFORM)
└──────────────────┘
    │
    ▼
┌─────────────┐
│ Data Dumper │  Export attack data from SIEM
└─────────────┘
    │
    ▼
┌───────────┐
│ PR Stager │  Create DRAFT PRs (never auto-merge)
└───────────┘
    │
    ▼
┌───────────┐
│ Verifier  │  Post-pipeline integrity check
└───────────┘
```

## Directory Structure

```
agents/
├── graphs/
│   └── detection-pipeline.ts   # Main LangGraph workflow
├── nodes/
│   ├── cti-analyst.ts          # TTP extraction
│   ├── coverage-analyzer.ts    # Gap analysis
│   ├── detection-engineer.ts   # Detection generation
│   ├── qa-reviewer.ts          # Quality gate
│   ├── fp-analyst.ts           # False positive risk assessment
│   ├── atomic-executor.ts      # Atomic test execution
│   ├── siem-validator.ts       # Multi-SIEM detection validation
│   ├── splunk-validator.ts     # Splunk-specific validation
│   ├── data-dumper.ts          # Attack data export
│   ├── pr-stager.ts            # PR creation
│   ├── verifier.ts             # Post-pipeline integrity check
│   └── attack-range-builder.ts # Lab infrastructure management
├── tools/
│   ├── mcp-client.ts           # MCP server interface
│   └── attack-range.ts         # Attack Range CLI wrapper
├── state/
│   └── types.ts                # TypeScript interfaces
├── src/
│   ├── cli.ts                  # CLI entry point
│   └── index.ts                # API exports
├── package.json
├── tsconfig.json
└── README.md
```

## State Type

The pipeline state flows through all nodes:

```typescript
interface PipelineState {
  // Input
  input_type: 'threat_report' | 'technique' | 'cisa_alert' | 'manual';
  input_content: string;
  input_url?: string;
  
  // Extracted
  techniques: Technique[];       // From CTI analysis
  gaps: Gap[];                   // From coverage analysis
  
  // Created
  detections: Detection[];       // Generated YAMLs
  atomic_tests: AtomicTest[];    // Test results
  attack_data_paths: string[];   // Exported data
  prs: PR[];                     // Staged PRs
  
  // Metadata
  workflow_id: string;
  current_step: string;
  errors: string[];
  started_at: string;
  completed_at?: string;
  
  // Approval
  requires_approval: boolean;
  approval_reason?: string;
  approved?: boolean;
}
```

## CLI Commands

```bash
# Full pipeline (pick one input method)
npm run orchestrate -- --type technique --input "T1566.004 Spearphishing Voice"
npm run orchestrate -- --type technique --content "T1566.004 Spearphishing Voice"  # alias
npm run orchestrate -- --type cisa_alert --url https://www.cisa.gov/news-events/cybersecurity-advisories/aa24-131a
npm run orchestrate -- --type threat_report --file ./report.md
npm run orchestrate -- --type manual --input "PowerShell encoded commands..."

# Coverage analysis only (no detection creation)
npm run analyze -- --technique T1003.001
npm run analyze -- --input "T1566.004 Spearphishing Voice"

# Validation only (requires Attack Range)
npm run validate -- --technique T1003.001
npm run validate -- --detection /path/to/detection.yml

# Check environment status
npm run status
```

## Troubleshooting

### "No techniques extracted"
**Cause**: LLM couldn't parse the input or input was too vague.
**Fix**: Be more specific. Instead of `"T1003.001"`, use `"T1003.001 LSASS Memory Dumping"`.

### "No gaps found - ending"
**Cause**: Existing detections already cover this technique (correct behavior).
**Fix**: This is expected! Check coverage with a technique that has gaps (e.g., `T1566.004`).

### "Attack Range is not running"
**Cause**: Attack Range isn't set up or isn't running.
**Fix**: 
- For testing: This is fine - detections are still created
- For validation: Set up Attack Range per the [E2E Testing Guide](../docs/E2E-TESTING-GUIDE.md)
- Alternative: Use `DRY_RUN=true` to skip validation entirely

### Detection created but not validated
**Cause**: Attack Range or Splunk MCP not available.
**Fix**: This is expected behavior when lab infrastructure isn't available. The detection YAML is still created in `security_content/detections/`.

## API Usage

```typescript
import { 
  runDetectionPipeline,
  createDetectionPipeline,
  createInitialState,
} from 'detection-agents';

// Full pipeline
const result = await runDetectionPipeline('technique', 'T1003.001 LSASS');
console.log(result.detections);  // Generated detections
console.log(result.prs);         // Staged PRs

// Custom pipeline with specific nodes
import { ctiAnalystNode, coverageAnalyzerNode } from 'detection-agents';
// ... build your own workflow
```

## Environment Variables

Copy `agents/.env.example` to `agents/.env` and configure. Key variables:

| Variable | Description | Default | Required |
|----------|-------------|---------|----------|
| `SIEM_PLATFORM` | Target SIEM: `splunk`, `sentinel`, `elastic`, `sigma` | `splunk` | Yes |
| `ANTHROPIC_API_KEY` | Claude API key (or `OPENAI_API_KEY` etc.) | - | Yes |
| `SECURITY_CONTENT_PATH` | Path to detection content repo | `./security_content` | Yes |
| `SPLUNK_MCP_ENABLED` | Enable Splunk MCP calls | `false` | Splunk only |
| `ATTACK_RANGE_PATH` | Attack Range location | `~/attack_range` | Splunk only |
| `AZURE_WORKSPACE_NAME` | Azure Log Analytics workspace | - | Sentinel only |
| `ELASTICSEARCH_URL` | Elasticsearch endpoint | `http://localhost:9200` | Elastic only |
| `SIGMA_TARGET_BACKEND` | Sigma conversion target | `splunk` | Sigma only |

See `agents/.env.example` for the full list with detailed comments.

## MCP Integration

The pipeline uses three MCPs (the first is always used; the second depends on your SIEM):

### security-detections (all SIEMs)
- `list_by_mitre` - Check existing coverage
- `analyze_coverage` - Get coverage stats
- `identify_gaps` - Find gaps for threats
- `analyze_procedure_coverage` - Break down which behaviors a detection actually catches within a technique
- `compare_procedure_coverage` - Cross-source procedure matrix (which source catches which behaviors)
- `generate_navigator_layer` - Export ATT&CK Navigator layer JSON (supports actor filtering)
- `analyze_actor_coverage` - Coverage analysis against a specific MITRE ATT&CK threat actor
- `list_actors` - Browse all 172 MITRE ATT&CK threat actors with technique counts
- `compare_actor_coverage` - Compare coverage across multiple threat actors, find shared gaps
- `get_actor_profile` - Full actor dossier: description, aliases, techniques, software, coverage

### splunk-mcp (Splunk only)
- `run_detection` - Execute detection YAML
- `search` - Run arbitrary SPL
- `export_dump` - Export data to file

> **Non-Splunk users**: Validation and data export use native APIs instead of Splunk MCP. See [docs/E2E-TESTING-GUIDE.md](../docs/E2E-TESTING-GUIDE.md) for per-SIEM validation methods.

### mitre-attack (all SIEMs)
- `get_technique` - Technique details
- `get_group_techniques` - APT TTPs

## Dependencies

```json
{
  "@langchain/langgraph": "^1.1.2",
  "@langchain/anthropic": "^1.3.12",
  "@langchain/core": "^1.1.17",
  "zod": "^4.6.7",
  "commander": "^12.0.0",
  "yaml": "^2.4.0"
}
```

## Development

```bash
# Watch mode
npm run dev

# Type check
npm run typecheck

# Build
npm run build

# Test (when tests are added)
npm test
```

## License

Apache 2.0
