# Project health maintenance contract

Assurance: A2. Baseline: `origin/main` at `54a588c` (3.3.0).

## Intent and scope

Restore trustworthy local and CI checks after a maintenance gap, preserve
current upstream Splunk metadata, and make the compiled detection-agent CLI
query the same real local SQLite data as source execution. Prepare changes for
human review; do not merge, publish packages, deploy, run paid providers, or
change hosted authentication/database policy.

## Required behaviors and evidence

| ID | Behavior | Acceptance evidence |
| --- | --- | --- |
| HEALTH-001 | Legacy nested and current top-level Splunk metadata preserve technique, story, CVE, asset and date fields; explicit top-level metadata wins. | `tests/splunk-parser-test.js`; current upstream content integration and engineering suites. |
| HEALTH-002 | Default user cache path remains unchanged. Both SQLite entry points honor `DETECTIONS_DB_PATH`. The indexer releases query connections before replacing the database and its own connection afterward. Destructive tests use disposable databases and close connections before cleanup. | `tests/cross-platform-test.js`; independent source review; Linux/Windows CI. |
| HEALTH-003 | The built server initializes over real MCP stdio, advertises core tools, returns indexed fixture data, and rejects unknown tools. | `tests/mcp-smoke-test.js`, enforced without `continue-on-error` in CI. |
| HEALTH-004 | Source and compiled agents resolve the local database independently of the caller's working directory; absent databases remain pending. | Four subprocess integration cases in `agents/tests/tools/mcp-client.test.ts`. |
| HEALTH-005 | Compiled agent package entry points exist and structured-response tests match production contracts. | Agent build/typecheck, Vitest, dry-run CLI smoke checks and package import. |
| HEALTH-006 | CI executes parser regressions, live-content queries, agent tests and web static/build checks, and propagates CLI process failures. | `.github/workflows/ci.yml`, `agents-cli.yml`, independent review and the PR's Actions results. |

The MCP server now requires Node 20+ because the patched SDK's transitive HTTP
server requires Node 20. Agents require Node 20.19+ or 22.12+ for their updated
test toolchain. CI exercises current Node 20/22 versions.

## Reproduction

Follow SETUP.md to clone Sigma and Splunk content. Set `SIGMA_PATHS`,
`SPLUNK_PATHS` and `STORY_PATHS`, then run `npm ci && npm test` and
`npm run test:ci`. Content tests create their own databases and extract patterns;
they no longer depend on a previously populated personal cache. `npm test`
fails with instructions when required source paths are absent.

For agents, build the root package first, then run `npm ci`,
`npm run typecheck`, `npm run build` and `npm test -- --run` in `agents/`.
For web, run `npm ci`, `npm run lint`, `npm run typecheck` and `npm run build`
in `web/`. No deployment credentials are needed for these build checks.

## Review boundaries and remaining debt

Compatible dependency updates remove all root audit findings and all critical
findings across the three packages. Remaining audit findings require separate
compatibility work: agents' uuid and Zod; web's mcp-handler-pinned SDK, Zod,
Next's nested PostCSS and ESLint dependency tree. A successful build does not
prove those remaining vulnerabilities harmless. Do not run `audit fix --force`
or override security gates to declare a release ready.

This change does not prove authenticated hosted UI workflows, live provider
calls, SIEM/Attack Range execution, production Supabase migrations or package
publication. The older `automation/` platform is outside this verified slice.
Stop on a failing required check; record limitations rather than weaken it.

Rollback: revert the maintenance commit. No database migrations or production
writes are part of this change. Review readiness and production release
readiness must be reported separately.
