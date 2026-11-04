# Source-qualified detection identity

Issue: #34. Assurance: A2 for catalog identity and A3 for the catalog privilege
cleanup, with independent security/release review and production-semantic
SQLite/Postgres tests. Authentication and profile/accounting hardening are
covered by the separate hosted-security contract.

## Approved outcome

User requested all follow-ups fixed and working PRs merged (2026-11-03).
Two different source formats carrying the same upstream rule ID must both remain
indexed, queryable and correctly attributed, including after repeat nightly sync.

## Identity and compatibility design

Use `(source_type, id)` as the database identity. Keep `id` equal to the upstream
rule ID; do not rewrite published UUIDs or introduce opaque replacement IDs.
`source_type` is one of the existing seven source formats. Updating the same
pair replaces that source's rule; updating a different source never overwrites
it. Multiple copies of the same upstream ID within a source remain one rule.

The detection-technique junction gains `source_type` and uses
`(source_type, detection_id, technique_id)` as its primary key. Joins include both
source and detection ID. Counts of distinct detections count source/ID pairs.
Pattern examples already carry source_type; retain that association.

Retrieval accepts optional source_type. An unqualified ID with exactly one
matching row remains compatible. If multiple sources match, return an explicit
ambiguity error listing the available sources; never select the first row.
Search/list outputs already include source_type. Hosted detail links add
`?source_type=...`, while old unique-ID links keep working. Ambiguous old links
present source choices rather than a wrong rule or generic 404.

## Required behavior inventory

| ID | Required behavior | Evidence |
| --- | --- | --- |
| ID-001 | Same UUID in Sigma and Elastic yields two retained rows and source-specific searches. | Original real-rule collision fixture; both SQLite insertion APIs; Postgres upserts. |
| ID-002 | Repeating an upsert updates only the matching source/ID pair. | Different names/queries in two rows; repeat/updating negative cases. |
| ID-003 | Qualified lookup is exact; unique legacy lookup works; ambiguous lookup errors with source choices. | Local MCP, hosted MCP/AI helpers, raw-YAML and HTTP detail routes. |
| ID-004 | Junctions, coverage and pattern examples cannot mix sources with a shared ID. | Different techniques per colliding rule; join/count assertions in real databases. |
| ID-005 | Existing single-key SQLite/Postgres schemas migrate transactionally with rows, FTS and links preserved. | Upgrade from legacy schema; deliberately failed migration/constraint tests; repeat initialization. |
| ID-006 | Sync uses actual composite conflict targets and propagates write errors. | Real Postgres conflict/upsert tests; explicit source counts before/after two syncs; no swallowed failed batches. |
| ID-007 | Anonymous/authenticated catalog reads remain permitted and writes remain denied; the existing service role retains sync access and its RLS bypass privileges. | Postgres role/RLS/grant assertions, including forbidden source mutation and orphan edges. |

## Integration and release order

1. Review this design and affected consumers before implementation.
2. Test against disposable native SQLite and PostgreSQL, including legacy
   upgrades and all seven configured source formats. Use native PostgreSQL
   16/17 for role/concurrency tests and Dockerized PostgreSQL/PostgREST for
   actual Supabase client and Data API tests.
3. Independently review final migrations, grants, source lookup and seed failure
   behavior. Run root/agents/web checks and Linux/Windows CI.
4. Before production schema changes, identify the correct project, pause the
   nightly workflow, confirm no sync is active, verify recoverability, and retain
   the reviewed migration hash.
   No customer data/credentials may be copied to .context.
5. Migrate catalog keys and deploy compatible readers/sync as one controlled
   sequence. Existing rows are not renamed or deleted. Old id-only sync writers
   must not overlap the rollout. Run aggregate integrity and denied-write checks,
   then a bounded catalog sync and repeat source-count validation.

Rollback should prefer restoring the compatible reader/sync release. Reverting
to a global ID-only primary key after recovering colliding rows would lose data;
do not delete recovered rules to make an old schema fit. Any destructive schema
rollback requires a separate decision and verified backup.

Stop on row loss, an orphan edge, incorrect source selection, an unverified
production project, changed auth/RLS semantics, or a required gate failure.
Missing access or unavailable authenticated browser evidence is a concrete
blocker, not permission to mark a release ready.

## Local SQLite implementation evidence

`tests/source-identity-test.js` exercises ID-001 through ID-005 against native
SQLite using both insertion APIs and the MCP stdio transport. The original
Sigma and Elastic FastPass rules are checked-in collision fixtures. It covers
qualified and ambiguous lookup, compatibility for unique IDs, repeated updates,
source-specific technique joins/counts, FTS updates, and exact edge replacement.
Legacy upgrade checks preserve rowids, existing links and full-text results,
repeat initialization, foreign-key enforcement, and rollback after orphan or
invalid legacy-ID failures. The legacy indexer and modular API share schema,
lookup and write helpers so the two paths cannot drift on identity.

SQLite insertion uses `ON CONFLICT(source_type, id) DO UPDATE`; database triggers
reconcile technique edges in the same statement transaction. The schema upgrade
runs as one transaction and restores the connection's foreign-key setting even
on failure. It preserves existing indexes/triggers and rebuilds FTS after the
table key change. No existing detection rows are deleted by the migration.
