# Dependency security remediation (#32)

## Intent and scope

Remove the remaining agent and hosted-web dependency advisories while retaining
UUID identity, structured LLM output, hosted read-only tools, and the existing
bearer-token and daily-quota boundary. No database policy, production settings,
secrets, deployment, or provider calls are part of this change.

The hosted protocol migration is assurance A3 because authentication enforcement
must remain intact across the upgraded handler. Independent security review and
explicit release evidence are required before production promotion.

## Behavior and evidence

- DEP-001: Agent workflow/detection IDs remain unique RFC 4122 version-4 UUIDs.
  Verify generation and full agent regressions with native `crypto.randomUUID`.
- DEP-002: Zod 4 preserves the structured CTI response contract, confidence bounds,
  tool argument bounds/enums/defaults, and rejection before database dispatch.
- DEP-003: The mounted hosted route supports legacy MCP initialize/list/call and
  the current SDK protocol using the real handler and tool schemas.
- DEP-004: Missing/malformed/invalid/revoked tokens, blocked accounts, exhausted
  quotas, and backend failures stop before tool dispatch. Authorization passes
  only the hashed token to the unchanged atomic quota RPC.
- DEP-005: Clean installs, audit, agents tests/build, web lint/typecheck/build pass.

Protocol tests replace only the database boundary with deterministic fixtures;
they exercise production route/auth/token/tool code and the installed protocol
handler. They do not prove deployed RPC transactionality or production login.
Authenticated production smoke and independent review remain release gates.

## Compatibility and rollback

Hosted HTTP+SSE from protocol 2024-11-05 remains unsupported; the existing endpoint
was already Streamable HTTP only. Existing `/api/mcp/mcp` URLs stay stable. The new
handler also supports the current stateless MCP protocol. No session persistence
or new authorization permissions are introduced.

Rollback is a revert of this commit and redeployment of the prior lockfile/build;
there are no database changes. Stop on unresolved auth/schema regressions or
upstream advisories without a supported compatible fix; do not suppress findings.

## Verified dependency choices

- Agents use Zod 4.6.7 and Node's `crypto.randomUUID()`; uuid and its types are removed.
- Hosted tools use mcp-handler 2.3.0, MCP server SDK 2.4.0, Zod 4.6.7,
  and Next 16.4.5. SDK v2 requires `z.object(...)` Standard Schemas and the
  handler's combined options argument. Legacy clients remain tested.
- The public `/api/mcp/mcp` path is explicitly enforced because handler v2
  delegates routing to the host framework. Subscription streams remain disabled.
- ESLint uses its CLI and the native Next flat config. The latest peer-compatible
  ESLint is 9.39.5; its lifecycle is deprecated. ESLint 10.14.0 was evaluated but
  is outside the latest React/import/jsx-a11y plugins' declared peer ranges.
- Web development/runtime is declared Node >=22.13.0. Supabase package versions
  are pinned at the existing lockfile versions (SSR 0.6.1, JS 2.103.0); auth/RLS
  behavior and SQL are unchanged.

Official migration references:
- https://github.com/vercel-labs/mcp-handler/blob/main/CHANGELOG.md
- https://zod.dev/v4/changelog
- https://nextjs.org/docs/app/guides/upgrading/version-16
- https://eslint.org/version-support

## Evidence recorded on 2026-11-03

Local environment: macOS arm64, Node 22.22.0, npm 10.9.4. npm 11 was used only
for dependency resolution; final clean installations use npm 10.

Passed after clean installs:

- Root MCP build (prerequisite for agent database integration).
- Agents typecheck/build and 42 tests, including UUID state preservation,
  structured-schema constraints, and source/compiled SQLite client integration.
- Web typecheck, production Next build, and ESLint (0 errors; 7 pre-existing
  unused-catch warnings in `scripts/seed-from-sqlite.ts`).
- 25 hosted route tests: real protocol handler, tool schemas and auth code, with
  only the database functions replaced. Tests include legacy initialize/list/call,
  current protocol discover/list/call, schema rejection, token rejection,
  blocked accounts, final-quota-call behavior and backend errors.
- `npm run test:http --prefix web`: built Next server on localhost with the real
  Supabase HTTP client and a local RPC fixture. Exercises initialize, list all 25
  tools, call, missing/invalid token rejection, quota rejection, argument rejection,
  hashed-token RPC payloads, and protected `/account` redirect to `/login`.
- Agents full audit: 0. Web production-only audit: 0.

Not run: live provider calls, real Supabase atomic quota/RLS execution,
production authenticated session/browser testing, deployment. The local HTTP
fixture proves client/protocol compatibility, not database transaction semantics.
Independent review remains required before merge; production validation remains
required before promotion.

## Remaining upstream blocker — keep #32 open

The complete web audit still reports **16 moderate development dependency
findings**, all arising from minimatch through the lint toolchain. There are no
remaining high or critical findings, and the production-only audit is clean.

[GHSA-g3hv-75wg-m249](https://github.com/advisories/GHSA-g3hv-75wg-m249)
affects minimatch <11.0.1. As verified from current npm package metadata, the
latest ESLint 10.14.0 and typescript-eslint still use minimatch 10, while the latest
eslint-plugin-react 7.37.5, eslint-plugin-import 2.32.0 and eslint-plugin-jsx-a11y
6.10.2 use minimatch 3 and declare ESLint peers through 9. Minimatch 11 changes
exports relative to the callable v3 API; an unconditional major override is not a
supported repair. npm audit's proposed downgrade to ESLint 4/Next config 12 is
also not acceptable.

No overrides, advisory ignores, disabled lint rules, or audit exclusions were
added. Production-only audit is an additional measurement, not a substitute for
the failing full audit. Closure of #32 requires upstream-compatible lint updates
followed by a clean full audit and a supported ESLint lifecycle combination.
