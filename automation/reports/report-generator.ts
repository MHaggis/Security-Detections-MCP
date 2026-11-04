import Database from 'better-sqlite3';
import { writeFileSync } from 'node:fs';
import { databasePath, openDatabase } from '../db';

interface ReportConfig { type: 'daily' | 'weekly' | 'monthly' | 'custom'; startDate?: string; endDate?: string; includeNavigator: boolean; outputPath: string }
interface JobRow { status: string; job_type: string; result: string | null }

/** Reports actual queue states; simulated work never counts as reviewed detection coverage. */
export class ReportGenerator {
  private readonly db: Database.Database;
  constructor(path: string) { this.db = openDatabase(path); }
  close(): void { this.db.close(); }
  private rows(config: ReportConfig): JobRow[] {
    const since = new Date();
    const days = config.type === 'daily' ? 1 : config.type === 'monthly' ? 30 : 7;
    since.setUTCDate(since.getUTCDate() - days);
    const start = config.startDate || since.toISOString();
    const end = config.endDate || new Date().toISOString();
    if (!Number.isFinite(Date.parse(start)) || !Number.isFinite(Date.parse(end))) throw new Error('Invalid report date range');
    return this.db.prepare('SELECT status,job_type,result FROM jobs WHERE datetime(created_at) BETWEEN datetime(?) AND datetime(?)').all(start, end) as JobRow[];
  }
  async generateMarkdownReport(config: ReportConfig): Promise<string> {
    const counts = new Map<string, number>();
    for (const row of this.rows(config)) {
      const key = `${row.job_type} | ${row.status}`;
      counts.set(key, (counts.get(key) || 0) + 1);
    }
    const text = `# Automation queue report\n\nPeriod: ${config.type}\n\n| Job type | Status | Count |\n| --- | --- | ---: |\n` +
      [...counts].map(([key, count]) => `| ${key} | ${count} |`).join('\n') +
      '\n\nSimulated runs are synthetic. Awaiting approval means artifacts need human review. Reviewed means the local review was recorded; it does not mean a PR was published or merged. Coverage improvement is not measured by this queue.\n';
    writeFileSync(config.outputPath, text);
    return text;
  }
  async generateNavigatorLayer(config: ReportConfig): Promise<unknown> {
    const counts = new Map<string, number>();
    for (const row of this.rows(config).filter(row => row.status === 'reviewed' && row.result)) {
      const result = JSON.parse(row.result!);
      if (result.mode !== 'live' || !Array.isArray(result.pipeline?.detections)) continue;
      for (const detection of result.pipeline.detections) {
        if (detection.status !== 'validated' || !/^T\d{4}(\.\d{3})?$/.test(detection.technique_id)) continue;
        counts.set(detection.technique_id, (counts.get(detection.technique_id) || 0) + 1);
      }
    }
    const layer = {
      name: `Human-reviewed automation results (${config.type})`, domain: 'enterprise-attack',
      versions: { navigator: '5.3.1', layer: '4.5' },
      description: 'Reported validated detections from live results reviewed by a human. No simulated work or deployment claims.',
      techniques: [...counts].map(([techniqueID, score]) => ({ techniqueID, score, enabled: true })),
    };
    const output = config.outputPath.endsWith('.md') ? config.outputPath.slice(0, -3) + '_navigator.json' : config.outputPath + '_navigator.json';
    writeFileSync(output, JSON.stringify(layer, null, 2));
    return layer;
  }
}
if (require.main === module) {
  async function main(): Promise<void> {
    const generator = new ReportGenerator(databasePath());
    try {
      const type = process.argv[2] || 'weekly';
      if (!['daily', 'weekly', 'monthly'].includes(type)) throw new Error('Report period must be daily, weekly, or monthly');
      const config: ReportConfig = { type: type as ReportConfig['type'], includeNavigator: true,
        outputPath: process.argv[3] || `./report_${type}_${Date.now()}.md` };
      await generator.generateMarkdownReport(config);
      if (config.includeNavigator) await generator.generateNavigatorLayer(config);
    } finally { generator.close(); }
  }
  main().catch(error => { console.error(error instanceof Error ? error.message : String(error)); process.exitCode = 1; });
}
