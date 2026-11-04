import Database from 'better-sqlite3';
import { readFileSync } from 'node:fs';
import { join, resolve } from 'node:path';

/** The queue has its own explicit database, never the MCP's re-indexed cache. */
export function databasePath(): string {
  const path = process.env.AUTOMATION_DB_PATH;
  if (!path) throw new Error('Set AUTOMATION_DB_PATH to a dedicated automation SQLite database');
  return resolve(path);
}

export function openDatabase(path: string): Database.Database {
  const db = new Database(path);
  try {
    db.pragma('journal_mode = WAL');
    db.pragma('foreign_keys = ON');
    db.pragma('busy_timeout = 5000');
    for (const migration of ['001_add_job_queue.sql', '002_approvals.sql']) {
      db.exec(readFileSync(join(__dirname, '..', 'migrations', migration), 'utf8'));
    }
    const columns = db.prepare('PRAGMA table_info(approval_requests)').all() as { name: string }[];
    if (!columns.some(column => column.name === 'job_id')) {
      throw new Error('Legacy approval schema is incompatible; use a new dedicated AUTOMATION_DB_PATH and retain the old database for review');
    }
    return db;
  } catch (error) {
    db.close();
    throw error;
  }
}

if (require.main === module) {
  try {
    openDatabase(databasePath()).close();
    console.log('Automation schema initialized');
  } catch (error) {
    console.error(error instanceof Error ? error.message : String(error));
    process.exitCode = 1;
  }
}
