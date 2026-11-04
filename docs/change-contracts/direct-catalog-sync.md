# Dedicated PostgreSQL catalog sync

Assurance A3. User authorized completing production ingestion and release.
The encoded Data API request also hit Cloudflare HTML403 in run41888987901;
the normal PostgreSQL wire protocol is the supported ingestion path for this
catalog. No WAF rules, addresses, request identity, or role timeouts are weakened.

## Required behaviors

- DIRECT-001: nightly uses only SUPABASE_CATALOG_DATABASE_URL, a dedicated
  catalog_sync login. Missing secret, unknown transport, or connection failure
  stops the job. Legacy HTTP requires explicit CATALOG_SEED_TRANSPORT=http and
  is never selected as fallback. Nightly no longer receives a service-role key.
- DIRECT-002: pg client verifies certificate trust and hostname with its trusted CA store.
  URL parsing rejects query options and admin/service usernames, then passes
  discrete connection fields and rejectUnauthorized=true. Extra trusted roots,
  if provider configuration requires them, use Node's explicit CA mechanism;
  verification may not be disabled. Errors expose only safe error codes and the
  fixed statement-timeout message, never URL/password/driver details.
- DIRECT-003: migration creates catalog_sync NOLOGIN/NOSUPERUSER/NOBYPASSRLS,
  NOCREATEDB/NOCREATEROLE/NOINHERIT with no memberships. Lead separately provisions
  LOGIN/password and GitHub secret after review; migration contains no password.
- DIRECT-004: role gets only catalog SELECT/INSERT/UPDATE on the nine seed tables
  plus sync_runs; edge SELECT/INSERT/DELETE supports the existing invoker trigger.
  Role-specific RLS write policies do not broaden anonymous/authenticated rights.
  Existing public SELECT policies permit catalog reads. RPC remains invoker and
  bounded by the same table/column maps,100 rows,2MiB and atomic edge semantics.
- DIRECT-005: auth/profile/token rows, quota RPCs, persistent DDL, role escalation,
  server files/programs and TRUNCATE remain denied. PUBLIC TEMP is inherited and
  permits temporary tables; this does not grant persistent DDL. Remove PUBLIC
  EXECUTE on handle_new_user so a temporary trigger cannot reuse its definer
  privileges. Existing signup trigger must still create the profile correctly.
- DIRECT-006: direct SQL covers count, sync lifecycle and parameterized catalog
  function calls. It validates acknowledgements, records failed runs and keeps
  bounded57014 splitting. Role statement/lock timeout defaults remain8s; these
  defaults are operational limits, not immutable security restrictions on a login.

## Evidence and release

`web/tests/direct-catalog.integration.mjs` creates disposable PostgreSQL17 with
TLS and SCRAM login authentication. It exercises all nine writes, two-source
identity/edges, blocked CQL fixture through actual seed twice, failed sync,
spoofed JWT claims, sensitive column grants, quota/DDL/TRUNCATE/serverfile/role
and temporary-trigger negatives, normal signup, certificate trust/hostname,
wrong password, absent/invalid settings and timeout splitting. The existing
HTTP suite retains explicit HTTP coverage. Both run in the catalog-postgres CI
job; web lint/typecheck/tests remain required.

Independent security review and CI precede migration/provisioning. After
provisioning the login and secret, run one normal nightly job, verify completed
status, per-source counts, preserved colliding rules and zero orphan edges.
Stop on TLS, permission, row/edge integrity or failed-status errors. Disable the
login and remove the secret if provisioning or release validation fails; do not
substitute an admin credential or silently return to HTTP.
