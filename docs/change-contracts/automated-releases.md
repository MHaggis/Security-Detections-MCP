# Automatic release contract

User intent: wire this repository's successful-main-CI → npm → MCP Registry pipeline like `magicsword-io/magicsword-mcp`, with setup instructions (2026-11-04).

Assurance A3: this changes the release authorization boundary and distributes executable artifacts. Independent release review, adversarial orchestration tests, clean installed package tests, Linux/Windows CI and explicit first-publication evidence are required.

| Behavior | Contract | Evidence |
| --- | --- | --- |
| REL-001 | Only successful same-repository main push runs can authorize release; all five required workflows must pass for that exact SHA. | Untrusted/fork/stale/missing/pending/failed tests; production workflow status check. |
| REL-002 | Versions advance published npm and git baselines; retry does not duplicate a release. | Numeric semver, prerelease, npm-ahead, duplicate/in-flight/failed dispatch tests. |
| REL-003 | Tags and current main bind the release to tested source. | Tag collision, main advancement and stable tag validation; live API checks before writes. |
| REL-004 | package, lock, Registry and MCP initialize agree on version and identity. | Metadata tests; official Registry validator; installed stdio initialization. |
| REL-005 | Publish exactly the tested production tarball with no unexpected files. | Clean consumer native SQLite/MCP test; archive allowlist; digest, path/version tamper tests; retained artifact. |
| REL-006 | npm and Registry publishing use short-lived workflow identity. | No static npm token reference; isolated npm-release job; pinned publisher digest; first actual publishing run. |

Required workflow files: `ci.yml`, `agents-cli.yml`, `automation.yml`, `hosted-security.yml`, `release-validation.yml`. The integrated branch removes main-push path filters from prerequisite workflows so every main commit has all required evidence. PR filters may remain. The orchestrator intentionally blocks on absent workflows rather than guessing whether they were applicable.

No account settings, credentials, remote release, npm publish, or Registry writes were performed while implementing this slice. The user must configure npm trusted publishing for owner `MHaggis`, repository `Security-Detections-MCP`, workflow `publish.yml`, environment `npm-release`, with direct publishing allowed. GitHub environment configuration is coordinated by the lead.

Rollback: disable the automatic-release workflow to stop new allocations, then revert workflow changes through review. A published npm version is immutable; repair with a new verified version. Retain failed run/tag evidence; do not delete tags and republish different source under the same version. Registry-only recovery reruns the failed Registry job after npm success.

Stop on an unknown npm baseline, failed/missing prerequisite, mismatched release/tag/commit, package metadata or digest mismatch, unauthorized npm identity, or unverified Registry publication. No secret-token fallback or test bypass is permitted.

Local evidence (2026-11-04): 20 release regression/adversarial tests pass; strict TypeScript and build pass; installed tarball runs on Node 22.22.0 and Node 24.22.2 with 81 tools, matching MCP package version, real SQLite fixture query and unknown-tool rejection. Root dependency audit is clean. `actionlint` passes all three release workflows. Official mcp-publisher 1.8.1 validates server.json against the Registry; its Linux archive SHA-256 was fetched and independently compared against the release metadata. Independent release reviewer returned READY_WITH_RISKS, retaining the integration, Linux/Windows CI and first live publication gates above. Logs are local `.context/release-*.log` and `.context/registry-validation.log`.

## First-publication regression and repair

The first live candidate (`v3.3.1`, run 41876314748) reached npm but failed before authentication or publication: npm interpreted bare `release-assets/security-detections-mcp-3.3.1.tgz` as a GitHub package shorthand. No npm version was published by that run. The publisher now resolves the archive to an absolute path before invoking npm.

REL-005 now also exercises the actual installed npm publish parser with `--dry-run --offline --ignore-scripts`, empty user/global npm configurations, an environment that excludes token/OIDC/application variables, and a loopback registry. It verifies package identity and unchanged original/copied SHA-256 bytes. Every Linux/Windows installed-package validation runs this check against its actual candidate tarball. A separate real-CLI regression uses lifecycle scripts that fail if executed and rejects a mismatched expected version.

Verified locally with Node 24 / npm 11.12.0 against the exact retained failed-run tarball: version 3.3.1, SHA-256 `16241ddc7a0442d02c15e6608864f4ff7b73884c22dcf04cb1b9932f38e95bc5`. This is a dry-run parser check only; account OIDC authorization and successful publication still require a new live run after all required main checks.
