import Database from 'better-sqlite3';
import { databasePath, openDatabase } from '../db';

export interface ApprovalRequest {
  id: string; job_id: string; workflow_id: string; status: string; data: string;
  requested_at: string; checkpoint_type: string;
}

/** Reviews persisted results only. Never retries the pipeline or publishes a PR. */
export class ApprovalSystem {
  private readonly db: Database.Database;
  constructor(path: string) { this.db = openDatabase(path); }
  close(): void { this.db.close(); }
  getApproval(id: string): ApprovalRequest | null {
    return this.db.prepare('SELECT * FROM approval_requests WHERE id=?').get(id) as ApprovalRequest | undefined ?? null;
  }
  getPendingApprovals(): ApprovalRequest[] {
    return this.db.prepare("SELECT * FROM approval_requests WHERE status='pending' ORDER BY requested_at").all() as ApprovalRequest[];
  }
  private resolve(id: string, actor: string, approved: boolean, reason?: string): void {
    if (!actor.trim()) throw new Error('Reviewer identity is required');
    this.db.transaction(() => {
      const approval = this.getApproval(id);
      if (!approval || approval.status !== 'pending') throw new Error('Approval does not exist or is already resolved');
      const jobStatus = approved ? 'reviewed' : 'cancelled';
      const changed = this.db.prepare(`UPDATE jobs SET status=?, completed_at=CURRENT_TIMESTAMP
        WHERE id=? AND status='awaiting_approval'`).run(jobStatus, approval.job_id).changes;
      if (!changed) throw new Error('Job is not awaiting approval');
      this.db.prepare(`UPDATE approval_requests SET status=?, resolved_at=CURRENT_TIMESTAMP, resolved_by=?, reason=? WHERE id=?`)
        .run(approved ? 'approved' : 'rejected', actor, reason ?? null, id);
      this.db.prepare('UPDATE feed_items SET status=? WHERE job_id=?').run(jobStatus, approval.job_id);
    }).immediate();
  }
  async approve(id: string, actor: string): Promise<void> { this.resolve(id, actor, true); }
  async reject(id: string, actor: string, reason?: string): Promise<void> { this.resolve(id, actor, false, reason); }
  async processExpiredApprovals(): Promise<void> {
    this.db.transaction(() => {
      const expired = this.db.prepare(`SELECT * FROM approval_requests WHERE status='pending'
        AND datetime(requested_at, '+' || timeout_hours || ' hours') <= datetime('now')`).all() as ApprovalRequest[];
      for (const request of expired) {
        this.db.prepare("UPDATE approval_requests SET status='expired', resolved_at=CURRENT_TIMESTAMP WHERE id=?").run(request.id);
        this.db.prepare("UPDATE jobs SET status='cancelled', error='Human review expired' WHERE id=? AND status='awaiting_approval'").run(request.job_id);
        this.db.prepare("UPDATE feed_items SET status='cancelled' WHERE job_id=? AND status='awaiting_approval'").run(request.job_id);
      }
    }).immediate();
  }
}

if (require.main === module) {
  async function main(): Promise<void> {
    const system = new ApprovalSystem(databasePath());
    try {
      const command = process.argv[2] || 'list';
      const id = process.argv[3];
      const actor = process.env.USER || process.env.USERNAME || 'local-reviewer';
      if (command === 'list') console.table(system.getPendingApprovals());
      else if (command === 'check-expired') await system.processExpiredApprovals();
      else if (command === 'approve' && id) await system.approve(id, actor);
      else if (command === 'reject' && id) await system.reject(id, actor, process.argv[4]);
      else throw new Error('Usage: approval-system.js [list|approve <id>|reject <id> [reason]|check-expired]');
    } finally { system.close(); }
  }
  main().catch(error => { console.error(error instanceof Error ? error.message : String(error)); process.exitCode = 1; });
}
