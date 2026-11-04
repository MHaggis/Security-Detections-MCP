# Legacy automation readiness (issue #33)

Assurance: A2 for the SQLite queue / subprocess integration. Live infrastructure execution remains experimental; this change does not activate a production worker, scheduler, PR publisher, or notification channel.

## Intent and acceptance

A queued threat report must invoke the actual compiled agents CLI or expose a clear blocked/failure state. Placeholder or synthetic work must never claim validated completion. The package must build independently and be tested in CI.

| Behavior ID | Contract | Evidence |
| --- | --- | --- |
| AUTO-INGEST-001 | One atomic source-qualified feed + job; retry is idempotent | collector tests with real SQLite rollback/dedup |
| AUTO-QUEUE-001 | Atomic single claim, bounded attempts, explicit unsupported/configuration failures | queue tests with two workers and failure paths |
| AUTO-ADAPTER-001 | Literal argv/file input, bounded child, structured output validation | actual subprocess fixtures; malformed/error/timeout cases |
| AUTO-RESULT-001 | Simulation remains simulated; incomplete live evidence blocks | fixture cases and real compiled agents dry-run integration |
| AUTO-REVIEW-001 | Review stored result without replaying external work | approval/rejection/expiry transactions |
| AUTO-OPS-001 | Runnable independent package; opt-in UTC scheduling; honest reporting | strict build, compiled CLIs from alternate cwd, schedule/report tests |

## Scope and integration

The production seam is `agents/dist/src/cli.js orchestrate --type threat_report --file ...`. Unit tests use a subprocess fixture, and the integration test invokes the real compiled CLI in dry-run mode. The queue uses a dedicated database, never the replaceable MCP cache. Human approval records local review only; the agents CLI has no durable resume operation and must not be rerun to publish previously reviewed work.

## Stop rules and constraints

No live credentials, cloud/range operations, continuous scheduler, or PR/notification side effects are needed to validate this slice. Live mode requires explicit configuration, persistent artifacts, and passing structured evidence. Missing coverage evidence is blocked. Crashed live jobs require operator inspection before any replay. Do not turn fixture evidence into claims of production security validation.

## Release evidence

Required gates: independent automation build/typecheck; isolated SQLite/subprocess regression suite; real compiled agents dry-run adapter test; automation dependency audit; Linux and Windows CI; independent code review before merge. Actual Attack Range/Splunk/LLM and live feed validation are intentionally excluded from this release claim and remain operator prerequisites for experimental live use. The README, deployment guide, and reference YAML reflect those limits.

Rollback: revert code while retaining the dedicated queue and persistent artifacts. Do not automatically replay old jobs or trust the legacy placeholder's `completed` records. Use a new database if an old approval schema is incompatible.
