# Atomic local index and pattern builds

Assurance: A1 focused SQLite transaction and performance fix, with independent
review. Repeated full-content Windows CI runs spend more than twenty minutes
indexing and extracting patterns. Each rule previously committed separately.

## Outcomes and boundaries

- IDX-001: One transaction commits the complete new detection/story index,
  including FTS and source-qualified technique edges. Counters return only after
  commit. Expected parser rejections still increment failure counters.
- IDX-002: An unexpected SQLite or directory traversal error propagates and rolls
  back all new rows. Missing optional paths (`ENOENT`) retain their skip behavior.
  Existing parser-level handling of malformed/unreadable rule content is unchanged.
- IDX-003: Full pattern extraction commits patterns, field references, conventions
  and its summary learning together on the same connection. Failure preserves
  pre-existing records. Completion is logged only after commit.
- IDX-004: Subsequent rebuild/extraction succeeds after a failed attempt. Indexer
  connections still close in the outer `finally`, including on Windows.

The indexer already removes the previous cache before initializing the new one.
This change does **not** preserve that previous cache on failure; it leaves a new
empty cache that `needsIndexing` identifies for retry. It changes no hosted sync
behavior, standalone pattern extraction tools, journal mode, or synchronous
settings. It does not change SQLite durability settings.

## Evidence

`tests/cross-platform-test.js` runs in existing Linux/Windows CI and now has 18
checks. New checks verify colliding Sigma/Elastic rows, FTS and materialized edges;
a real SQLite error after a successful insert; native `ENOTDIR` after an earlier
source; missing paths and parser failure counts; and a late native trigger error
on the summary learning after pattern writes. They verify rollback and retry.

Local build/typecheck and the complete Sigma/Splunk test suite pass (18 platform,
source identity and parser tests, real MCP stdio, 23 integration, 15 engineering).
Independent review and Windows CI remain release gates recorded by the lead.

A disposable 1,500-rule fixture benchmark ran baseline and transaction variants
alternately twice on macOS with the same native SQLite settings. Index time fell
from 1,115–1,148 ms to 301–353 ms; pattern extraction from 396–424 ms to 48–63 ms.
Combined time fell from 1,539–1,544 ms to 349–416 ms (3.7–4.4× faster). Both variants
retained all 1,500 rows and reported 1,500 pattern operations. This is local
performance evidence, not a measured Windows speedup. No personal cache was used.
