# Hosted account and quota enforcement

Assurance: A3. User authorized project fixes and deployment; production database
inspection confirmed broad token/profile writes and TRUNCATE grants. This slice
closes those direct Data API paths without changing legitimate account routes.

## Behavior contract

- SEC-001: authenticated owners can read their tokens; other users cannot. Only
  service_role can create, revoke, or alter token accounting/identity. Existing
  account routes already authenticate users and use service_role for all writes.
- SEC-002: direct profile inserts/updates can set only id, display_name and
  avatar_url. Owner RLS remains enforced for the layout's fallback upsert.
  Tier, role, provider keys, billing and usage fields require server routes.
- SEC-003: quota checks serialize on the user's profile and reread/lock the token
  before revocation and counter checks. Exactly one concurrent request can spend
  the final allowance; a revocation committed while a call waits is respected.
  Missing profiles fail closed. Revoked-token history still counts toward quota.
- SEC-004: anon/authenticated/PUBLIC cannot TRUNCATE public application tables.
  Future tables created by postgres inherit no TRUNCATE grant to these roles.
- SEC-005: only service_role invokes accounting RPCs. Fixed search_path places
  trusted schemas before pg_temp. MCP tables are schema-qualified. Chat callers
  continue using the same service-client RPC and existing limit parameters.

## Evidence and release

`PG_BIN=/path/to/postgresql/bin python3 web/tests/security/test_database.py`
creates a disposable native PostgreSQL cluster, installs tracked legacy schema,
models actual production default grants, migrates twice, and checks role/RLS,
profile fallback, privileged account management, quota resets, cross-token
history, concurrent final allowance and revoke-before-waiting-call completion.
No real credentials, production data, auth provider or LLM calls are involved.

Independent security review and a reviewed migration checksum are required before
production. Apply transactionally with a bounded lock timeout. Verify actual
role/column privileges and rollback-only quota/account behavior afterward.
Existing catalog/user rows are preserved. Stop on an unexpected grant/policy,
failed invariant or API account regression. Prefer correcting the migration
forward; restoring broad writes would restore the demonstrated vulnerabilities.

The postgres default privilege change covers this project's migration owner;
other object-creating roles require their own explicit review. TRUNCATE is not
exposed as an ordinary PostgREST operation, so its broad grant is defense-in-depth
hardening, not evidence of a direct unauthenticated HTTP truncate exploit.
