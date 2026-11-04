# Hosted catalog identity integration

Run from the repository root with Node 22 and Docker available:

```sh
npm ci --prefix web
node --experimental-strip-types web/tests/source-identity.integration.mjs
```

The test runs PostgreSQL 17 and PostgREST 14 containers on an isolated Docker
network, binds localhost ports 54380/54381, and deletes only its own named
containers/network and disposable SQLite file. It uses synthetic catalog data
and a disposable JWT signing key; production credentials are not used.

It installs the tracked legacy schema/RLS/functions, inserts a legacy rule and
edge, proves a failed migration rolls back, then applies the identity migration.
It exercises real Supabase client composite upserts and relationship embedding,
source-specific RPC results, trigger edge replacement, batch atomicity, foreign
keys, all seven source formats, anonymous/authenticated read and denied writes
(including TRUNCATE), and the actual hosted lookup helpers.

It also runs the real seed script twice from a disposable SQLite database,
verifies stable source counts and exact edges, and proves both a remote optional
STIX-table error and malformed local technique data mark the sync failed.

For production rollout, suspend old sync writers before migration and keep them
suspended until composite-aware readers and the seed script are deployed.
The migration preserves catalog rows, existing technique edges, policies and
SELECT permissions, and revokes unsafe public TRUNCATE privileges on the two
catalog tables. Reverting to the old ID-only primary key after recovering
collisions would lose rules; use a compatible forward fix instead.
