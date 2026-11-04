# Hosted sync statement timeouts

Assurance: A2. Production sync run 41876041179 reached detection batch 4000,
then PostgreSQL canceled the 500-row write at the existing eight-second role
limit. The sync correctly recorded failure, but could not finish the catalog.

## Outcome and bounds

Use batches of at most 100 rows for seed upserts. When PostgreSQL explicitly
returns SQLSTATE 57014 and a statement-timeout message, split the canceled batch
in half and submit its halves sequentially. The statement's rollback makes this
retry safe; composite upsert and technique reconciliation remain atomic per
request. Each retry has fewer rows, with a maximum depth of seven splits for a
100-row batch; a single-row timeout fails the sync. No role timeout is increased.

Explicit cancellation, network errors, invalid data, constraint errors and
permission failures propagate. Successfully committed earlier batches remain;
failed syncs are recorded and can be rerun idempotently. A partially synced
catalog must never be reported as a completed sync.

## Behaviors and evidence

- SYNC-001: canceled batches leave no detection rows or technique edges.
- SYNC-002: the real seed script splits timed-out batches and finishes all rows.
- SYNC-003: repeated sync preserves both source/ID pairs and replaces old edges.
- SYNC-004: single-row timeout and explicit cancellation fail the sync without
  an unbounded retry; other existing remote/local failures remain failures.

`web/tests/source-identity.integration.mjs` runs these cases through PostgreSQL
17, PostgREST, the actual Supabase client and the actual seed CLI. A test-only
per-row `pg_sleep` trigger and 800ms connection-role limit produce real statement
timeouts. The test first asserts a full write returns 57014 and rolls back, then
runs two full seed passes and verifies exact rows and edges. Existing tests also
exercise remote constraint failure and malformed local technique data.

Independent review and passing CI are required before merge. Production release
evidence is a successful manual sync and aggregate source/edge integrity checks
at the unchanged hosted timeout. Stop if the smaller single-row write still
fails or source-qualified identity/edge checks fail.
