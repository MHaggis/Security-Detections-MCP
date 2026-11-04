import Parser from 'rss-parser';
import { FeedStore, FeedItem, feedId } from './feed-store';

export interface FeedSource { id: string; name: string; type: 'rss' | 'kev' | 'github' | 'nvd'; url: string; enabled: boolean }
export const DEFAULT_SOURCES: FeedSource[] = [
  { id: 'cisa_alerts', name: 'CISA advisories', type: 'rss', url: 'https://www.cisa.gov/cybersecurity-advisories/all.xml', enabled: true },
  { id: 'cisa_kev', name: 'CISA KEV', type: 'kev', url: 'https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json', enabled: true },
  { id: 'mitre_attack', name: 'MITRE ATT&CK commits', type: 'github', url: 'https://api.github.com/repos/mitre/cti/commits', enabled: false },
];
function object(value: unknown): Record<string, unknown> {
  if (!value || typeof value !== 'object' || Array.isArray(value)) throw new Error('Invalid feed object');
  return value as Record<string, unknown>;
}
function string(value: unknown): string {
  if (typeof value !== 'string' || !value.trim()) throw new Error('Missing feed text field');
  return value;
}
function array(value: unknown): unknown[] {
  if (!Array.isArray(value)) throw new Error('Missing feed item array');
  return value;
}

/** Parses configured formats; malformed feeds fail instead of becoming empty success. */
export async function parseFeed(source: FeedSource, data: string): Promise<FeedItem[]> {
  let items: FeedItem[];
  if (source.type === 'rss') {
    const feed = await new Parser().parseString(data);
    items = feed.items.map(item => {
      const url = string(item.link);
      return { id: feedId(source.id, string(item.guid || url)), title: string(item.title),
        content: item.content || item.contentSnippet || item.summary || '', url,
        publishedAt: new Date(string(item.isoDate || item.pubDate)) };
    });
  } else {
    const json: unknown = JSON.parse(data);
    if (source.type === 'kev') {
      items = array(object(json).vulnerabilities).map(value => {
        const v = object(value);
        const id = string(v.cveID);
        return { id: feedId(source.id, id), title: `${id}: ${string(v.vulnerabilityName)}`,
          content: JSON.stringify(v), url: `https://www.cve.org/CVERecord?id=${encodeURIComponent(id)}`,
          publishedAt: new Date(string(v.dateAdded)) };
      });
    } else if (source.type === 'github') {
      items = array(json).map(value => {
        const entry = object(value);
        const commit = object(entry.commit);
        const message = string(commit.message);
        return { id: feedId(source.id, string(entry.sha)), title: message.split('\n')[0], content: message,
          url: string(entry.html_url), publishedAt: new Date(string(object(commit.author).date)) };
      });
    } else if (source.type === 'nvd') {
      items = array(object(json).vulnerabilities).map(value => {
        const cve = object(object(value).cve);
        const id = string(cve.id);
        return { id: feedId(source.id, id), title: id, content: JSON.stringify(cve),
          url: `https://nvd.nist.gov/vuln/detail/${encodeURIComponent(id)}`, publishedAt: new Date(string(cve.published)) };
      });
    } else throw new Error('Unsupported feed format');
  }
  if (items.some(i => !Number.isFinite(i.publishedAt.getTime()))) throw new Error('Invalid feed publication date');
  return items;
}

export async function fetchFeedText(url: string): Promise<string> {
  const response = await fetch(url, { signal: AbortSignal.timeout(30000), headers: { 'User-Agent': 'security-detections-automation/3.0' } });
  if (!response.ok) throw new Error(`Feed returned HTTP ${response.status}`);
  if (!response.body) throw new Error('Feed response has no body');
  const reader = response.body.getReader();
  let size = 0;
  const chunks: Buffer[] = [];
  try {
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      size += value.byteLength;
      if (size > 8 * 1024 * 1024) throw new Error('Feed exceeds 8 MiB limit');
      chunks.push(Buffer.from(value));
    }
  } finally { await reader.cancel(); }
  return Buffer.concat(chunks).toString('utf8');
}

export class MultiSourceCollector extends FeedStore {
  constructor(path: string, readonly sources = DEFAULT_SOURCES, private readonly fetchText = fetchFeedText) { super(path); }
  async collectAll(): Promise<{ fetched: number; inserted: number }> {
    let fetched = 0;
    let inserted = 0;
    const errors: Error[] = [];
    for (const source of this.sources.filter(s => s.enabled)) {
      try {
        const items = await parseFeed(source, await this.fetchText(source.url));
        fetched += items.length;
        for (const item of items) if (this.ingest(item, source.id)) inserted++;
      } catch (error) {
        errors.push(new Error(`Collection failed for ${source.id}: ${error instanceof Error ? error.message : 'unknown failure'}`));
      }
    }
    if (errors.length) throw new AggregateError(errors, errors.map(e => e.message).join('; '));
    return { fetched, inserted };
  }
}
