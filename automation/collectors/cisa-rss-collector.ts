import { databasePath } from '../db';
import { MultiSourceCollector } from './multi-source-collector';

export class CISARSSCollector extends MultiSourceCollector {
  async collectFeeds(): Promise<{ fetched: number; inserted: number }> { return this.collectAll(); }
}

if (require.main === module) {
  async function main(): Promise<void> {
    if ((process.argv[2] || 'once') !== 'once') throw new Error('Use once mode with an external scheduler for feed collection');
    const collector = new CISARSSCollector(databasePath());
    try { console.log(await collector.collectFeeds()); } finally { collector.close(); }
  }
  main().catch(error => { console.error(error instanceof Error ? error.message : String(error)); process.exitCode = 1; });
}
