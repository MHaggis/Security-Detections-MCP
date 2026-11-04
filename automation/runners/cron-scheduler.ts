import Database from 'better-sqlite3';
import { CronJob } from 'cron';
import { randomUUID } from 'node:crypto';
import { databasePath, openDatabase } from '../db';

interface ScheduledJob { id: string; name: string; cron_expression: string; job_type: string; enabled: number; last_run: string | null; next_run: string | null }

/** Scheduling only queues collection; the explicit live worker performs network I/O. */
export class CronScheduler {
  private readonly db: Database.Database;
  private readonly jobs = new Map<string, CronJob>();
  constructor(path: string) { this.db = openDatabase(path); }
  loadSchedules(): ScheduledJob[] {
    return this.db.prepare('SELECT * FROM job_schedule WHERE enabled=1 ORDER BY name').all() as ScheduledJob[];
  }
  createJob(jobType: string): string {
    if (jobType !== 'feed_collection') throw new Error('Only feed_collection schedules are supported');
    return this.db.transaction(() => {
      const existing = this.db.prepare("SELECT id FROM jobs WHERE job_type='feed_collection' AND status IN ('pending','running') LIMIT 1").get() as { id: string } | undefined;
      if (existing) return existing.id;
      const id = `job_${randomUUID()}`;
      this.db.prepare("INSERT INTO jobs (id,job_type,payload) VALUES (?,'feed_collection','{}')").run(id);
      return id;
    }).immediate();
  }
  start(): void {
    if (this.jobs.size) throw new Error('Scheduler is already running');
    try {
      for (const schedule of this.loadSchedules()) {
        if (schedule.job_type !== 'feed_collection') throw new Error(`Unsupported schedule ${schedule.id}: ${schedule.job_type}`);
        const cron = new CronJob(schedule.cron_expression, () => {
          try {
            this.createJob(schedule.job_type);
            this.db.prepare('UPDATE job_schedule SET last_run=CURRENT_TIMESTAMP,next_run=? WHERE id=?')
              .run(cron.nextDate().toJSDate().toISOString(), schedule.id);
          } catch (error) { console.error('Scheduled enqueue failed:', error); }
        }, null, false, 'UTC');
        this.jobs.set(schedule.id, cron);
        this.db.prepare('UPDATE job_schedule SET next_run=? WHERE id=?').run(cron.nextDate().toJSDate().toISOString(), schedule.id);
        cron.start();
      }
    } catch (error) { this.stop(); throw error; }
  }
  stop(): void { for (const job of this.jobs.values()) void job.stop(); this.jobs.clear(); }
  close(): void { this.stop(); this.db.close(); }
  getStatus(): ScheduledJob[] { return this.loadSchedules(); }
  addSchedule(name: string, expression: string, jobType: string): string {
    if (jobType !== 'feed_collection') throw new Error('Only feed_collection schedules are supported');
    new CronJob(expression, () => {}, null, false, 'UTC'); // validate without starting
    const id = `schedule_${randomUUID()}`;
    this.db.prepare('INSERT INTO job_schedule (id,name,cron_expression,job_type) VALUES (?,?,?,?)').run(id, name, expression, jobType);
    return id;
  }
  removeSchedule(id: string): void {
    void this.jobs.get(id)?.stop(); this.jobs.delete(id);
    this.db.prepare('DELETE FROM job_schedule WHERE id=?').run(id);
  }
}

if (require.main === module) {
  let scheduler: CronScheduler | undefined;
  try {
    const command = process.argv[2] || 'status';
    scheduler = new CronScheduler(databasePath());
    if (command === 'start') {
      scheduler.start();
      console.log('Scheduler active (UTC). Collection requires a live worker.');
      for (const signal of ['SIGINT', 'SIGTERM']) process.once(signal, () => { scheduler?.close(); });
    } else {
      if (command === 'status') console.table(scheduler.getStatus());
      else if (command === 'add' && process.argv[3] && process.argv[4]) {
        console.log(scheduler.addSchedule(process.argv[3], process.argv[4], process.argv[5] || 'feed_collection'));
      } else throw new Error('Usage: cron-scheduler.js [status|start|add <name> <cron> [feed_collection]]');
      scheduler.close();
    }
  } catch (error) { scheduler?.close(); console.error(error instanceof Error ? error.message : String(error)); process.exitCode = 1; }
}
