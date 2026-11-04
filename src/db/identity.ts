import type Database from 'better-sqlite3';
import type { Detection } from '../types.js';

export class AmbiguousDetectionIdError extends Error {
  readonly code = 'AMBIGUOUS_DETECTION_ID';
  constructor(readonly id: string, readonly sources: string[]) {
    super(`Detection ID ${id} occurs in multiple sources (${sources.join(', ')}). Specify source_type.`);
    this.name = 'AmbiguousDetectionIdError';
  }
}

export function findDetectionRow(db: Database.Database, id: string, sourceType?: string): Record<string, unknown> | undefined {
  const rows = sourceType === undefined
    ? db.prepare('SELECT * FROM detections WHERE id = ? ORDER BY source_type').all(id)
    : db.prepare('SELECT * FROM detections WHERE id = ? AND source_type = ?').all(id, sourceType);
  if (rows.length > 1) throw new AmbiguousDetectionIdError(id, rows.map(row => (row as { source_type: string }).source_type));
  return rows[0] as Record<string, unknown> | undefined;
}

/** Rebuild the legacy primary key inside the caller's schema transaction. */
export function migrateDetectionIdentity(db: Database.Database): boolean {
  const info = db.pragma('table_info(detections)') as { name: string; pk: number }[];
  if (!info.length || info.some(c => c.name === 'source_type' && c.pk > 0)) return false;
  const original = db.prepare("SELECT sql FROM sqlite_master WHERE type = 'table' AND name = 'detections'").get() as { sql: string };
  const junction = db.prepare("SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'detection_techniques'").get();
  if (junction) {
    // Preserve old edges, including links not reconstructed from mitre_ids.
    db.exec(`CREATE TEMP TABLE identity_edges AS
      SELECT d.source_type, dt.detection_id, dt.technique_id FROM detection_techniques dt
      LEFT JOIN detections d ON d.id = dt.detection_id`);
    if (db.prepare('SELECT 1 FROM identity_edges WHERE source_type IS NULL LIMIT 1').get()) {
      throw new Error('Cannot migrate orphan detection technique links');
    }
    db.exec('DROP TABLE detection_techniques');
  }
  const schemaObjects = db.prepare("SELECT sql FROM sqlite_master WHERE tbl_name = 'detections' AND type IN ('trigger', 'index') AND sql IS NOT NULL").all() as { sql: string }[];
  db.exec('DROP TABLE IF EXISTS detections_fts');
  for (const trigger of db.prepare("SELECT name FROM sqlite_master WHERE type = 'trigger' AND tbl_name = 'detections'").all() as { name: string }[]) {
    db.exec(`DROP TRIGGER "${trigger.name.replaceAll('"', '""')}"`);
  }
  const create = original.sql.replace(/CREATE TABLE (?:IF NOT EXISTS )?["`]?detections["`]?/i, 'CREATE TABLE detections_identity_new')
    .replace(/id TEXT PRIMARY KEY/i, 'id TEXT NOT NULL').replace(/\)\s*$/, ', PRIMARY KEY (source_type, id))');
  db.exec(create);
  db.exec(`INSERT INTO detections_identity_new(rowid, ${info.map(c => '"' + c.name.replaceAll('"', '""') + '"').join(', ')}) SELECT rowid, * FROM detections`);
  db.exec('DROP TABLE detections; ALTER TABLE detections_identity_new RENAME TO detections');
  if (junction) {
    db.exec(`CREATE TABLE detection_techniques (
      source_type TEXT NOT NULL, detection_id TEXT NOT NULL, technique_id TEXT NOT NULL,
      PRIMARY KEY(source_type, detection_id, technique_id),
      FOREIGN KEY(source_type, detection_id) REFERENCES detections(source_type, id) ON DELETE CASCADE ON UPDATE CASCADE);
      INSERT INTO detection_techniques SELECT * FROM identity_edges;
      DROP TABLE identity_edges;`);
  }
  for (const object of schemaObjects) db.exec(object.sql);
  return true;
}

const columns = ["id", "name", "description", "query", "source_type", "mitre_ids", "logsource_category", "logsource_product", "logsource_service", "severity", "status", "author", "date_created", "date_modified", "refs", "falsepositives", "tags", "file_path", "raw_yaml", "cves", "analytic_stories", "data_sources", "detection_type", "asset_type", "security_domain", "process_names", "file_paths", "registry_paths", "mitre_tactics", "platforms", "kql_category", "kql_tags", "kql_keywords", "sublime_attack_types", "sublime_detection_methods", "sublime_tactics"];

export function upsertDetection(database: Database.Database, detection: Detection): void {
  
  const stmt = database.prepare(`
    INSERT INTO detections
    (id, name, description, query, source_type, mitre_ids, logsource_category,
     logsource_product, logsource_service, severity, status, author,
     date_created, date_modified, refs, falsepositives, tags, file_path, raw_yaml,
     cves, analytic_stories, data_sources, detection_type, asset_type, security_domain,
     process_names, file_paths, registry_paths, mitre_tactics, platforms, kql_category, kql_tags, kql_keywords,
     sublime_attack_types, sublime_detection_methods, sublime_tactics)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    ON CONFLICT(source_type, id) DO UPDATE SET
      ${columns.filter(c => c !== 'id' && c !== 'source_type').map(c => `${c} = excluded.${c}`).join(', ')}
  `);

  stmt.run(
    detection.id,
    detection.name,
    detection.description,
    detection.query,
    detection.source_type,
    JSON.stringify(detection.mitre_ids),
    detection.logsource_category,
    detection.logsource_product,
    detection.logsource_service,
    detection.severity,
    detection.status,
    detection.author,
    detection.date_created,
    detection.date_modified,
    JSON.stringify(detection.references),
    JSON.stringify(detection.falsepositives),
    JSON.stringify(detection.tags),
    detection.file_path,
    detection.raw_yaml,
    JSON.stringify(detection.cves),
    JSON.stringify(detection.analytic_stories),
    JSON.stringify(detection.data_sources),
    detection.detection_type,
    detection.asset_type,
    detection.security_domain,
    JSON.stringify(detection.process_names),
    JSON.stringify(detection.file_paths),
    JSON.stringify(detection.registry_paths),
    JSON.stringify(detection.mitre_tactics),
    JSON.stringify(detection.platforms),
    detection.kql_category,
    JSON.stringify(detection.kql_tags),
    JSON.stringify(detection.kql_keywords),
    JSON.stringify(detection.sublime_attack_types),
    JSON.stringify(detection.sublime_detection_methods),
    JSON.stringify(detection.sublime_tactics)
  );
}
