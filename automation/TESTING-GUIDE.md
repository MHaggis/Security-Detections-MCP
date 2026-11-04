# Automation verification

From the repository root, install and build dependencies as in the README, then run:

```sh
npm test --prefix automation
npm run typecheck --prefix automation
npm run test:agents --prefix automation
npm audit --prefix automation
```

`npm test` compiles every automation TypeScript module with this package's own strict `tsconfig.json`, then uses Node's test runner. Tests create private temporary SQLite files and delete them after closing connections. They do not read or replace your MCP detection cache.

Coverage includes feed parsing and deduplication, atomic rollback, source-qualified feed IDs, HTTP failures, compare-and-set claims, bounded retries, disabled mode, malformed/missing jobs, literal shell metacharacters, malformed/empty/error CLI output, child timeout, incomplete live results, persistent-artifact checks, human review/expiry, UTC schedule validation, collection deduplication, truthful reports, and compiled CLI invocation from another working directory.

The subprocess fixture supplies synthetic evidence for live-mode rejection and review-state tests. Those tests are not live LLM, Attack Range, Splunk, GitHub, or notification validation. `test:agents` separately invokes the actual compiled agents CLI in dry-run mode and proves the adapter/SQLite integration. It verifies synthetic detections remain `simulated` and generate no approval request.

The dedicated `automation.yml` GitHub Actions workflow runs these checks on Linux and Windows with Node 22, builds the real prerequisite packages, and audits the automation lockfile. No workflow credentials or live services are required.

A production/live certification still requires controlled authorized infrastructure testing, artifact inspection, and independent review. No test in this package claims that a synthetic run created usable detection coverage.
