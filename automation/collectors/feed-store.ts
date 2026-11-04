import Database from 'better-sqlite3';
import { createHash, randomUUID } from 'node:crypto';
import { openDatabase } from '../db';

export interface FeedItem { id: string; title: string; content: string; url: string; publishedAt: Date }
export function feedId(source: string, guid: string): string {
  return createHash('sha256').update(`${source}:${guid}`).digest('hex');
}
export class FeedStore {
  protected readonly db: Database.Database;
  constructor(path: string) { this.db = openDatabase(path); }
  close(): void { this.db.close(); }
  /** Dedupe, insert and queue creation are one transaction, including the reverse link. */
  ingest(item: FeedItem, source: string): boolean {
    if (!item.id || !source || !item.title || !item.url || !Number.isFinite(item.publishedAt.getTime())) {
      throw new Error('Feed item must have identity, source, title, URL, and valid publication date');
    }
    return this.db.transaction(() => {
      const inserted = this.db.prepare(`INSERT OR IGNORE INTO feed_items
        (id, feed_source, title, content, url, published_at) VALUES (?, ?, ?, ?, ?, ?)`)
        .run(item.id, source, item.title, item.content, item.url, item.publishedAt.toISOString());
      if (!inserted.changes) return false;
      const id = `job_${randomUUID()}`;
      this.db.prepare("INSERT INTO jobs (id, job_type, payload) VALUES (?, 'threat_analysis', ?)")
        .run(id, JSON.stringify({ feed_item_id: item.id }));
      this.db.prepare('UPDATE feed_items SET job_id=? WHERE id=?').run(id, item.id);
      return true;
    }).immediate();
  }
}
