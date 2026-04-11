import { createClient } from '@supabase/supabase-js';
import { config } from 'dotenv';
import { join, dirname } from 'path';
import { fileURLToPath } from 'url';

const __dirname = dirname(fileURLToPath(import.meta.url));
config({ path: join(__dirname, '..', '.env.local') });

const sb = createClient(process.env.NEXT_PUBLIC_SUPABASE_URL!, process.env.SUPABASE_SERVICE_ROLE_KEY!);

async function main() {
  console.log('=== SUPABASE DATA AUDIT ===\n');

  // 1. Table counts
  const tables = ['detections', 'detection_techniques', 'technique_tactics', 'attack_techniques', 'attack_actors', 'attack_software', 'actor_techniques', 'software_techniques', 'procedure_reference', 'stories'];
  for (const table of tables) {
    const { count, error } = await sb.from(table).select('*', { count: 'exact', head: true });
    console.log(`  ${table}: ${error ? 'ERROR: ' + error.message : count}`);
  }

  // 2. Detection source breakdown
  console.log('\n--- Detection Sources ---');
  const { data: sources } = await sb.from('detections').select('source_type').limit(50000);
  const srcCounts: Record<string, number> = {};
  if (sources) {
    for (const s of sources) srcCounts[s.source_type] = (srcCounts[s.source_type] || 0) + 1;
  }
  // Note: this is limited by API max rows. Let's try RPC
  console.log('  Via API (may be limited):', srcCounts);

  // Try RPC
  const { data: srcRpc, error: srcErr } = await sb.rpc('get_source_counts');
  if (srcErr) {
    console.log('  RPC get_source_counts ERROR:', srcErr.message);
    console.log('  >>> You need to run migrations 005 and 006 in Supabase SQL Editor! <<<');
  } else {
    console.log('  Via RPC (accurate):', srcRpc);
  }

  // 3. APT29 specific
  console.log('\n--- APT29 Coverage ---');
  const { data: apt29 } = await sb.from('attack_actors').select('actor_id, name, aliases').ilike('name', '%APT29%').limit(1);
  if (apt29?.length) {
    console.log(`  Found: ${apt29[0].name} (${apt29[0].actor_id})`);
    console.log(`  Aliases: ${JSON.stringify(apt29[0].aliases)}`);

    // Get technique count
    const { count: techCount } = await sb.from('actor_techniques').select('*', { count: 'exact', head: true }).eq('actor_id', apt29[0].actor_id);
    console.log(`  Techniques: ${techCount}`);

    // Try the RPC
    const { data: actorIntel, error: actorErr } = await sb.rpc('get_actor_intelligence', { p_actor_name: 'APT29' });
    if (actorErr) {
      console.log('  RPC get_actor_intelligence ERROR:', actorErr.message);
    } else {
      console.log('  RPC result:', JSON.stringify(actorIntel, null, 2).substring(0, 500));
    }
  }

  // 4. T1059.001 specific
  console.log('\n--- T1059.001 Coverage ---');
  const { data: techIntel, error: techErr } = await sb.rpc('get_technique_intelligence', { p_technique_id: 'T1059.001' });
  if (techErr) {
    console.log('  RPC ERROR:', techErr.message);
  } else {
    console.log('  Result:', JSON.stringify(techIntel, null, 2).substring(0, 800));
  }

  // 5. Check detection_techniques completeness
  console.log('\n--- Detection-Technique Links ---');
  const { count: dtCount } = await sb.from('detection_techniques').select('*', { count: 'exact', head: true });
  console.log(`  Total links: ${dtCount}`);

  // Check a sample: how many detections have T1059.001
  const { count: t1059count } = await sb.from('detection_techniques').select('*', { count: 'exact', head: true }).eq('technique_id', 'T1059.001');
  console.log(`  T1059.001 detections: ${t1059count}`);

  // Check unique techniques in detection_techniques
  // Can't do DISTINCT via API easily, use count
  console.log('\n--- Coverage Summary RPC ---');
  const { data: summary, error: sumErr } = await sb.rpc('get_coverage_summary');
  if (sumErr) {
    console.log('  ERROR:', sumErr.message);
  } else {
    console.log('  ', JSON.stringify(summary, null, 2));
  }
}

main().catch(console.error);
