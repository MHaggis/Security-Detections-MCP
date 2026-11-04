import pg from 'pg';

/** Parse explicitly so connection-string SSL options cannot override verification. */
export function catalogConnectionConfig(connectionString) {
  try {
    const url = new URL(connectionString);
    const user = decodeURIComponent(url.username);
    const password = decodeURIComponent(url.password);
    if (!['postgres:', 'postgresql:'].includes(url.protocol) || !url.hostname ||
        !/^catalog_sync(?:\.[a-z0-9]+)?$/.test(user) || !password ||
        url.pathname !== '/postgres' || url.search || url.hash) throw new Error();
    const port = url.port ? Number(url.port) : 5432;
    if (!Number.isInteger(port) || port < 1 || port > 65535) throw new Error();
    return {
      host: url.hostname, port, user, password, database: 'postgres',
      ssl: { rejectUnauthorized: true },
      connectionTimeoutMillis: 15000,
      application_name: 'security-detections-catalog-sync',
    };
  } catch {
    throw new Error('Invalid SUPABASE_CATALOG_DATABASE_URL: expected the dedicated catalog_sync login, postgres database, and no URL options');
  }
}

/** Never forward driver messages/details: they can contain credentials or SQL values. */
export function safeDatabaseError(error) {
  const code = typeof error?.code === 'string' && /^[A-Z0-9_]{1,64}$/.test(error.code) ? error.code : 'UNKNOWN';
  const timeout = code === '57014' && /statement timeout/i.test(String(error?.message));
  return Object.assign(new Error(timeout
    ? 'canceling statement due to statement timeout'
    : `Catalog database operation failed (${code})`), { code });
}

export function createCatalogPostgres(connectionString) {
  const client = new pg.Client(catalogConnectionConfig(connectionString));
  let connected = false;
  let connectionError;
  client.on('error', error => { connectionError = safeDatabaseError(error); });
  async function query(text, values = []) {
    try {
      if (connectionError) throw connectionError;
      if (!connected) { await client.connect(); connected = true; }
      return await client.query(text, values);
    } catch (error) { throw safeDatabaseError(error); }
  }
  return {
    async count() {
      const result = await query('SELECT count(*)::text AS count FROM public.detections');
      const count = Number(result.rows[0].count);
      if (!Number.isSafeInteger(count) || count < 0) throw new Error('Invalid catalog count');
      return count;
    },
    async start(source, count) {
      const result = await query("INSERT INTO public.sync_runs(source_type, detections_total, detections_added, detections_updated, status) VALUES ($1, $2, 0, 0, 'running') RETURNING id", [source, count]);
      return result.rows[0].id;
    },
    async complete(id, metrics) {
      const result = await query("UPDATE public.sync_runs SET completed_at=now(), detections_total=$2, detections_added=$3, detections_updated=$4, status='completed', error=NULL WHERE id=$1 AND status='running'", [id, metrics.detectionsTotal, metrics.detectionsAdded, metrics.detectionsUpdated]);
      if (result.rowCount !== 1) throw new Error('Sync completion did not update one running row');
    },
    async fail(id, message) {
      const result = await query("UPDATE public.sync_runs SET completed_at=now(), status='failed', error=$2 WHERE id=$1 AND status='running'", [id, message]);
      if (result.rowCount !== 1) throw new Error('Sync failure did not update one running row');
    },
    async write(table, payload) {
      try {
        const result = await query('SELECT public.seed_catalog_batch($1, $2) AS acknowledgement', [table, payload]);
        return { data: result.rows[0].acknowledgement, error: null };
      } catch (error) { return { data: null, error: safeDatabaseError(error) }; }
    },
    async close() { try { await client.end(); } catch (error) { throw safeDatabaseError(error); } },
  };
}
