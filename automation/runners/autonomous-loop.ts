import Database from 'better-sqlite3';
import { randomUUID } from 'node:crypto';
import { databasePath, openDatabase } from '../db';
import { CISARSSCollector } from '../collectors/cisa-rss-collector';
import { AdapterResult, BlockedError, createAgentsAdapter, FeedItem } from './agents-adapter';

export interface Job {
  id: string; job_type: string; status: string; priority: number; payload: string;
  retry_count: number; max_retries: number;
}

export class AutonomousLoop {
  private readonly db: Database.Database;
  private running = false;
  private wake?: () => void;

  constructor(path: string, private readonly orchestrate = createAgentsAdapter(), private readonly pollInterval = 30000) {
    this.db = openDatabase(path);
    this.path = path;
  }
  private readonly path: string;

  getJob(id: string): Job | null {
    return this.db.prepare('SELECT * FROM jobs WHERE id=?').get(id) as Job | undefined ?? null;
  }

  getNextJob(): Job | null {
    return this.db.prepare(`SELECT * FROM jobs WHERE status = 'pending' AND retry_count < max_retries
      ORDER BY priority ASC, created_at ASC, id ASC LIMIT 1`).get() as Job | undefined ?? null;
  }

  /** Compare-and-set prevents two workers from running the same queued job. */
  private claim(jobId: string): boolean {
    return this.db.transaction(() => {
      const changed = this.db.prepare(`UPDATE jobs SET status='running', started_at=CURRENT_TIMESTAMP,
        completed_at=NULL, error=NULL WHERE id=? AND status='pending' AND retry_count < max_retries`).run(jobId).changes;
      if (changed) this.db.prepare("UPDATE feed_items SET status='processing' WHERE job_id=?").run(jobId);
      return changed > 0;
    }).immediate();
  }

  async processJob(job: Job): Promise<boolean> {
    if (!this.claim(job.id)) return false;
    let liveResultReceived = false;
    try {
      if (job.job_type === 'feed_collection') {
        if (process.env.AUTOMATION_MODE !== 'live') throw new BlockedError('Scheduled feed collection requires AUTOMATION_MODE=live');
        const collector = new CISARSSCollector(this.path);
        try {
          const result = await collector.collectFeeds();
          this.db.prepare("UPDATE jobs SET status='completed', result=?, completed_at=CURRENT_TIMESTAMP WHERE id=? AND status='running'")
            .run(JSON.stringify({ kind: 'feed_collection', ...result }), job.id);
        } finally { collector.close(); }
        return true;
      }
      if (job.job_type !== 'threat_analysis') throw new BlockedError(`Unsupported job type: ${job.job_type}`);
      const payload: unknown = JSON.parse(job.payload);
      if (!payload || typeof payload !== 'object' || !('feed_item_id' in payload) || typeof payload.feed_item_id !== 'string') {
        throw new Error('Job payload must contain feed_item_id');
      }
      const feed = this.db.prepare('SELECT * FROM feed_items WHERE id=? AND job_id=?').get(payload.feed_item_id, job.id) as FeedItem | undefined;
      if (!feed) throw new Error('Linked feed item not found');
      const result = await this.orchestrate(feed);
      liveResultReceived = result.mode === 'live';
      if (result.status !== 'simulated' && result.status !== 'awaiting_approval') throw new Error('Adapter returned unsupported completion status');
      this.persistResult(job.id, result);
    } catch (error) {
      const blocked = error instanceof BlockedError || liveResultReceived;
      const message = error instanceof Error ? error.message : 'Unknown processing error';
      this.db.transaction(() => {
        this.db.prepare(`UPDATE jobs SET
          retry_count=retry_count+?,
          status=CASE WHEN ? THEN 'blocked' WHEN retry_count+1 >= max_retries THEN 'failed' ELSE 'pending' END,
          error=?, result=NULL, completed_at=CASE WHEN ? OR retry_count+1 >= max_retries THEN CURRENT_TIMESTAMP ELSE NULL END
          WHERE id=? AND status='running'`).run(blocked ? 0 : 1, blocked ? 1 : 0, message, blocked ? 1 : 0, job.id);
        this.db.prepare(`UPDATE feed_items SET status=(SELECT status FROM jobs WHERE id=?) WHERE job_id=?`).run(job.id, job.id);
      }).immediate();
    }
    return true;
  }

  private persistResult(jobId: string, result: AdapterResult): void {
    this.db.transaction(() => {
      const serialized = JSON.stringify(result);
      const workflow = result.pipeline.workflow_id;
      this.db.prepare(`UPDATE jobs SET status=?, result=?, workflow_id=?, error=NULL, completed_at=CURRENT_TIMESTAMP
        WHERE id=? AND status='running'`).run(result.status, serialized, String(workflow), jobId);
      this.db.prepare('UPDATE feed_items SET status=?, metadata=? WHERE job_id=?').run(result.status, serialized, jobId);
      if (result.status === 'awaiting_approval') {
        this.db.prepare(`INSERT INTO approval_requests (id, workflow_id, job_id, data) VALUES (?, ?, ?, ?)`)
          .run(`approval_${randomUUID()}`, String(workflow), jobId, serialized);
      }
    }).immediate();
  }

  async processNext(): Promise<boolean> {
    const job = this.getNextJob();
    return job ? this.processJob(job) : false;
  }

  async start(): Promise<void> {
    this.running = true;
    while (this.running) {
      await this.processNext();
      if (this.running) await new Promise<void>(resolve => {
        const timer = setTimeout(() => { this.wake = undefined; resolve(); }, this.pollInterval);
        this.wake = () => { clearTimeout(timer); this.wake = undefined; resolve(); };
      });
    }
  }

  stop(): void { this.running = false; this.wake?.(); }
  close(): void { this.stop(); this.db.close(); }
  getStats(): unknown[] { return this.db.prepare('SELECT status, job_type, COUNT(*) AS count FROM jobs GROUP BY status, job_type').all(); }
}

if (require.main === module) {
  async function main(): Promise<void> {
    const command = process.argv[2] || 'once';
    if (!['once', 'start', 'status'].includes(command)) throw new Error('Usage: autonomous-loop.js [once|start|status]');
    const loop = new AutonomousLoop(databasePath());
    process.once('SIGINT', () => loop.stop());
    process.once('SIGTERM', () => loop.stop());
    try {
      if (command === 'start') await loop.start();
      else if (command === 'status') console.table(loop.getStats());
      else {
        const job = loop.getNextJob();
        if (job) {
          await loop.processJob(job);
          if (['blocked', 'failed', 'pending'].includes(loop.getJob(job.id)?.status || 'failed')) process.exitCode = 1;
        }
        console.table(loop.getStats());
      }
    } finally { loop.close(); }
  }
  main().catch(error => { console.error(error instanceof Error ? error.message : String(error)); process.exitCode = 1; });
}
