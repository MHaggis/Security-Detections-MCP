# Lossless hosted catalog transport

Assurance A3: a service-only database API for existing public catalog ingestion.
User authorized completing maintenance, tests and release. Independent design
review approved the bounded invoker design after the body-specific cause was
established.

## Problem and evidence

Production sync 41882402407 on main4c158f9 reached detection batch9600, then
Cloudflare blocked the request body with HTML403. Six denied anonymous
comparisons showed the first100 public CQL rules triggered the block while
benign before/after controls, other rules and a larger benign body reached the
normal JSON permission denial. This establishes a content-dependent false
positive. No WAF setting, client identity, address or credential was changed.
See `web/tests/fixtures/README.md` for source attribution and exact payload hash.

## Behaviors

- TRANSPORT-001: rule text roundtrips exactly using base64 UTF8 JSON inside a
  dedicated `seed_catalog_batch` RPC; no fields are dropped or interpreted as SQL.
- TRANSPORT-002: only service_role may execute; function is SECURITY INVOKER,
  search_path empty, and adds no table privileges. CREATE and public-role EXECUTE
  revocations occur in one transaction. Existing RLS/grants remain unchanged.
- TRANSPORT-003: only nine direct seed tables are accepted with static allowed
  columns and fixed conflict keys. User/auth/sync tables and trigger-owned
  detection_techniques are excluded. Unknown or default/generated-owned columns
  are rejected. Identifiers come from allowlists; values use EXECUTE USING.
- TRANSPORT-004: reject encoded text above2796204 bytes before decoding; decoded
  limit2097152 bytes, canonical base64, valid UTF8 JSON,1..100 homogeneous objects
  with nonempty string conflict keys. Invalid inputs fail without partial writes.
- TRANSPORT-005: omitted database defaults are preserved. `processed` acknowledges
  accepted input rows, including already-present key-only rows; it does not claim
  newly inserted rows. Client validates the acknowledgement before continuing.
- TRANSPORT-006: split oversized batches before encoding; oversized single rows
  fail explicitly. Existing confirmed57014 timeout splitting remains bounded;
  generic errors and403 responses fail. No hosted timeout is increased.
- TRANSPORT-007: existing composite upsert, FK and edge trigger stay atomic within
  each request. A failed full sync is recorded failed even after earlier batches
  committed; a repeat sync remains idempotent.

## Validation and release

`web/tests/source-identity.integration.mjs` exercises real PostgreSQL17,
PostgREST14, Supabase client and actual seed CLI. It checks every allowlist target,
PK-only repeats, defaults, malformed input/bounds, denied public callers,
constraint rollback, the exact blocked CQL payload's every mapped field, byte
splitting, incorrect acknowledgement failures, and actual statement timeouts.

Require independent security review, web typecheck and CI before merge. Deploy
the reviewed migration before the new seed writer, then run one normal full
production sync at existing role limits. Verify completed status plus per-source
counts, exact collision retention and no orphan edges. Stop on any boundary or
integrity failure. Do not retry arbitrary403s or modify edge security to force a
successful run. Reverting to direct upserts preserves schema compatibility but
reintroduces the known blocked-content failure.
