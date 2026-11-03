import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

// Import before database modules: lifecycle tests deliberately destroy their DB.
// Never accept a caller's database path for these destructive tests.
const directory = mkdtempSync(join(tmpdir(), 'security-detections-mcp-test-'));
process.env.DETECTIONS_DB_PATH = join(directory, 'detections.sqlite');
// Load after setting the environment; close both singletons before unlinking,
// since Windows keeps open SQLite files locked.
const modular = await import('../dist/db/connection.js');
const legacy = await import('../dist/db.js');
process.on('exit', () => {
  modular.closeDb();
  legacy.closeDb();
  rmSync(directory, { recursive: true, force: true });
});
