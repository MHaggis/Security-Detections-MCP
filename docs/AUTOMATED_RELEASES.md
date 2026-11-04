# Automatic npm and MCP Registry releases

A successful main commit now flows through:

```text
Merge to main
  → all five main workflows pass for the same commit
  → Release after main CI selects the next version and creates a GitHub release
  → Publish npm package tests and retains a tarball
  → npm trusted publishing publishes those exact bytes
  → the official MCP Registry receives the matching server.json
```

This follows the [MagicSword MCP release setup](https://github.com/magicsword-io/magicsword-mcp/actions), with an installed native-SQLite package check for this server. It releases the local `security-detections-mcp` npm package. Vercel deployments and Nightly Detection Sync remain separate: hosted users already receive deployed code and refreshed catalog data without reinstalling npm.

## One-time account setup

1. Sign in to npm with an owner/maintainer account for [security-detections-mcp](https://www.npmjs.com/package/security-detections-mcp), open **Settings → Trusted Publisher**, and choose **GitHub Actions**.
2. Enter these exact values:

   | Setting | Value |
   | --- | --- |
   | Organization or user | `MHaggis` |
   | Repository | `Security-Detections-MCP` |
   | Workflow filename | `publish.yml` |
   | Environment name | `npm-release` |
   | Allowed actions | Enable direct `npm publish` |

   Enter the workflow filename only. npm's newer publisher form defaults to staged publishing; this workflow needs direct publishing enabled. Dist-tag management permission is not required. See [npm's trusted publishing documentation](https://docs.npmjs.com/trusted-publishers/).
3. In [GitHub repository environments](https://github.com/MHaggis/Security-Detections-MCP/settings/environments), ensure `npm-release` exists. Required reviewers can provide a manual approval gate if desired. If restricting allowed deployment refs, permit the stable `v*` release tags. The workflow uses GitHub-hosted Ubuntu, Node 24, npm 11.12.0, and `id-token: write` for short-lived publishing identity.
4. Merge the reviewed workflows. Every required main workflow must run without main-push path filters: **CI - Build and Test**, **Agents CLI - Smoke Tests**, **Automation queue**, **Hosted database security**, and **Release validation**. A failed, pending, absent, fork, or stale run cannot authorize a release.
5. Watch [Actions](https://github.com/MHaggis/Security-Detections-MCP/actions). The last successful prerequisite starts **Release after main CI**, which explicitly dispatches **Publish npm package** on the new tag. GitHub does not automatically trigger a release workflow for releases created using `GITHUB_TOKEN`, so the explicit dispatch is necessary.
6. Verify the npm version and the [Registry entry](https://registry.modelcontextprotocol.io/v0.1/servers/io.github.MHaggis%2Fsecurity-detections-mcp/versions/latest). Check that `publish-npm` and `publish-registry` both succeed. Before Registry publication, a read-only gate fetches the exact npm version and verifies its name, version and case-sensitive `mcpName` against the materialized server.json. Registry publication uses GitHub OIDC and the case-sensitive `io.github.MHaggis` namespace (matching the canonical GitHub owner exactly); no Registry PAT is configured. See the [official Registry automation guide](https://github.com/modelcontextprotocol/registry/blob/main/docs/modelcontextprotocol-io/github-actions.mdx).

No `NPM_SECRET` is needed by the replacement workflow. Remove the old secret after the first successful trusted publication and after checking that no other workflow uses it.

## Versions and retries

The release planner compares the source version, all stable git tags, and all stable published npm versions. A deliberately higher source version wins; otherwise it increments the highest patch version. With the current 3.3.0 npm baseline, the first release is 3.3.1 unless a newer version appears first. Prerelease tags are ignored. A rerun reuses the tag already identifying the tested commit, never allocates a second version for it.

During the release build, `npm version --no-git-tag-version` materializes the selected tag into package.json, package-lock.json and server.json. No bot version commit is pushed to main. The server reports that package version in MCP initialization. Source metadata can therefore stay at a baseline between releases. For an intentional minor/major bump, run `npm version minor --no-git-tag-version` (or `major`) in a PR; the version hook synchronizes Registry metadata.

If npm setup is incomplete, configure the publisher and rerun the failed jobs on the existing tagged publication. If npm succeeded but Registry failed, rerun **only failed jobs**, which retries Registry without attempting to republish immutable npm bytes. To recover a release created before dispatch, rerun its **Release after main CI** job. It dispatches an existing unstarted release. If a publication already failed, inspect and rerun that publication rather than rerunning all stages or making another tag.

Publication refuses to proceed if main advanced while the artifact was being prepared. Allow the newer main commit to pass all checks; its release receives a new version. Old unstarted tags can remain as traceable unsuccessful candidates. Published npm versions cannot be overwritten: fix forward with a new release. An emergency rollback requires deliberately restoring the prior implementation in a new tested commit, not replacing bytes under an existing version.

## What is verified

The release validation workflow tests orchestration guards and installs an npm tarball into a clean consumer directory on Linux and Windows. It opens a disposable SQLite database, initializes the real stdio server, checks its reported version and tools, queries a Jamf fixture, and rejects an unknown tool. The package allowlist prevents `.context`, credentials, web code and source worktrees from entering the archive.

The publication build has no OIDC permission. The separate publishing job downloads its retained tarball, verifies SHA-256 and package identity, checks the exact main CI again, and publishes with lifecycle scripts disabled. The Registry publisher is pinned to v1.8.1 with a verified archive digest. Local dry runs do not prove npm account trust or a completed Registry publication; the first green production run is the release evidence for those boundaries.

Local checks:

```sh
npm ci
npm run lint
npm run test:release
npm run release:verify
npm run build
npm run test:package
```

Clients using `npx -y security-detections-mcp@latest` resolve the newest package when launched; restart the MCP connection after a release. Clients pinned to a version remain pinned until their configured version is changed. Global installs require `npm install --global security-detections-mcp@latest`, followed by restarting the MCP connection. Existing running processes do not hot-update or restart automatically.


Registry namespace casing is significant. The successful GitHub OIDC login for this repository grants `io.github.MHaggis/*`; lowercase `io.github.mhaggis/*` is a different Registry namespace. Both npm's `mcpName` and server.json must use `io.github.MHaggis/security-detections-mcp`. Schema validation alone does not verify authenticated namespace permissions. Version 3.3.2 published to npm successfully, but its lowercase metadata was rejected by the Registry; correcting immutable npm metadata requires a new patch publication. See the [Registry's namespace case-sensitivity issue](https://github.com/modelcontextprotocol/registry/issues/689).
