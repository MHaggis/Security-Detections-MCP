# Pin application function resolution

Assurance: A3 for the existing signup trigger; A2 for read-only catalog RPCs.
The production Supabase security advisor reported twenty application functions
without a fixed search_path after the catalog and account migrations. This
follow-up pins those exact functions to `pg_catalog, public, pg_temp`.

## Behavior and evidence

- PATH-001: exactly the nineteen named catalog RPCs and `handle_new_user()` gain
  the fixed path. All other pg_proc attributes, including bodies, owners, ACLs,
  SECURITY DEFINER/INVOKER, volatility and argument defaults, remain unchanged.
- PATH-002: all nineteen catalog RPCs return the same results for anon,
  authenticated and service_role when callers supply hostile temporary tables
  and a temporary-schema-first search_path. The fixture includes a shared UUID
  across two sources and an actor/technique relation.
- PATH-003: signup still creates the default public profile; a temporary profiles
  table cannot intercept it. Account isolation, quota and concurrency regressions
  remain passing. Applying the migration repeatedly is safe.

The existing native PostgreSQL security suite now installs the full current
schema and tests these invariants. Eleven tests pass on PostgreSQL 17; the
existing hosted-security CI runs the same suite on PostgreSQL 16. No vendor-owned
functions or trigger invocation permissions are changed. No schema, table,
credential, user record or RLS policy changes are needed.

Release requires independent review, a transactionally bounded application of the
reviewed migration, read-only function configuration verification, and another
production Supabase advisor run. Stop if function identity/ownership/body/grants
change or catalog/signup behavior regresses. Roll back only the named function
configuration if needed; no data rollback is required.
