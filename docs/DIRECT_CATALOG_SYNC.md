# Direct catalog sync operations

Nightly uses SUPABASE_CATALOG_DATABASE_URL with the dedicated catalog_sync role.
For the session pooler, the username is catalog_sync.<project-reference>; the
database is postgres. The pg client always verifies TLS certificate trust and
hostname. Supply no sslmode or other URL query parameters. Never put this URL in
logs, tracked files, workflow outputs, PR text or local evidence artifacts.

Apply the reviewed direct_catalog_sync_role migration first. It creates a role
that cannot log in. A trusted administrator then generates a high-entropy random
password in memory, derives a SCRAM verifier client-side (for example with
psycopg2 encrypt_password), enables LOGIN using only the safely quoted verifier, and
verifies a TLS connection as that role. Send the URL directly to GitHub secret
SUPABASE_CATALOG_DATABASE_URL through protected stdin. Keep the workflow paused
until provisioning succeeds. If any step fails, restore NOLOGIN and clear the
new database password so an incomplete provisioning does not leave an active
account. A newly written GitHub secret may remain unusable until replaced; do
not delete an existing working secret before its replacement is ready. Never
place the raw generated password in ALTER ROLE SQL.

For rotation, pause the sync workflow and wait for its active job to finish.
Generate a new password, update the database login and GitHub secret, verify TLS
and the role's grants, then resume and manually run one sync. Validate completed
status, source counts and edge integrity. If verification fails, disable LOGIN;
do not reuse the administrator URL as a workaround.

The role has no account/auth/token or quota access. It can manage catalog rows
and sync statuses and inherits PostgreSQL's ordinary temporary-table permission.
It cannot truncate catalog tables or create persistent schemas/tables/roles.
Its eight-second statement and lock timeouts are defaults. Keep them unchanged
for normal sync; batch splitting handles statement timeouts.

The source script defaults to PostgreSQL and fails when its dedicated secret is
absent. CATALOG_SEED_TRANSPORT=http is an explicit compatibility/test path and
requires the legacy HTTP credentials. There is no automatic fallback; production
nightly supplies only the dedicated PostgreSQL secret.
