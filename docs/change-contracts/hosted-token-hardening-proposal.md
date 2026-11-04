# Hosted token integrity — A3 proposal

This is a separate security change from dependency remediation #32. Implementation
and independent security review are required before applying any production SQL.

## Outcome and observed risk

Authenticated users must not reset billing/quota counters, reinstate revoked
tokens, change authorization fields, or truncate shared tables through the Data
API. The migration-014 owner INSERT/UPDATE policies do not constrain columns;
when paired with authenticated table grants, they bypass route restrictions.
The parent separately confirmed broad production grants, including TRUNCATE.
RLS does not enforce TRUNCATE authorization.

`increment_mcp_call` also reads token revocation before acquiring locks and uses
an unpinned search path in a SECURITY DEFINER function. These are pre-existing
issues and require independent review rather than being hidden in a dependency
upgrade.

## Proposed behavior and implementation boundaries

- AUTH-001: Browser roles cannot mutate token hashes, ownership, counters, reset
  dates or revocation directly. Existing authenticated server routes already use
  the service client; remove browser token INSERT/UPDATE privileges and policies.
  Retain only explicitly needed read permissions. Audit all public table grants;
  revoke browser TRUNCATE globally. Do not remove legitimate profile/content CRUD
  without a consumer inventory.
- AUTH-002: Calling the quota RPC requires service_role. Preserve explicit denial
  to PUBLIC/anon/authenticated. Prefer SECURITY INVOKER where service permissions
  suffice; if definer is retained, qualify all table names and pin the search path
  to trusted schemas with pg_temp last. No new callable privileged helper.
- AUTH-003: Serialize per-user quota evaluation on a stable existing user/profile
  row, then re-read and lock the current token before testing revocation and
  incrementing. Concurrent revoke and successful use must have a defined ordering.
  Concurrent calls with different tokens cannot both consume the last allowance.
  New token insertion cannot create an unlocked quota partition.
- AUTH-004: Rejected calls do not increment usage; revoked token usage still counts
  toward user quota; UTC daily reset works; blocked accounts fail closed.
- AUTH-005: Token create/revoke/account screens and the authenticated MCP route
  continue to work with the existing service-backed APIs.

## Evidence and rollout gates

Use native PostgreSQL with real roles/RLS plus actual PostgREST where relevant.
Prove own/other-user counter updates, ownership reassignment, revocation reversal,
malformed negative counter inserts, quota reset-date writes and TRUNCATE all fail.
Use separate concurrent connections to test last-slot contention across tokens
and revocation ordering. A sequential rollback smoke does not establish these.
Run the existing 25 protocol tests and built HTTP smoke, then authenticated hosted
initialize/list/call after deployment. Confirm grants/policies/function settings
against the intended project, preserve a restorable schema/ACL snapshot and
independently review the exact migration. Stop on user-facing auth regression or
any successful bypass. Record passed/failed/skipped evidence before release.

`web/tests/sql/mcp-auth-rollback.sql` supplies a transaction-only diagnostic using
one fresh synthetic auth user. It executes the existing RPC as service_role and
reports the known direct-owner-write weakness. It changes no committed data;
assertion failures require disconnect or explicit ROLLBACK. Unexpected signup
hooks stop the test before user insertion. Local syntax/behavior validation used
PostgreSQL17 with migration014 and minimal auth/profile scaffolding; production
schema and HTTP behavior still require separate evidence.

Rollback must preserve security restrictions. Prefer a compatible forward fix;
do not restore broad browser grants to repair an application bug. Keep service
role secret credentials out of tests, logs and commits.
