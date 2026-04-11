import { createClient } from '@supabase/supabase-js';
import { config } from 'dotenv';
import { join, dirname } from 'path';
import { fileURLToPath } from 'url';

const __dirname = dirname(fileURLToPath(import.meta.url));
config({ path: join(__dirname, '..', '.env.local') });

const sb = createClient(process.env.NEXT_PUBLIC_SUPABASE_URL!, process.env.SUPABASE_SERVICE_ROLE_KEY!);

async function main() {
  // Check tactic name format
  const { data: tactics } = await sb.from('technique_tactics').select('tactic_name').limit(30);
  const uniqueTactics = [...new Set(tactics?.map(t => t.tactic_name))];
  console.log('Sample tactic names:', uniqueTactics);
  console.log('');

  // Check actor_techniques count for Agrius
  const { data: agrius } = await sb.from('attack_actors').select('actor_id').ilike('name', '%Agrius%').limit(1);
  if (agrius?.length) {
    const { count } = await sb.from('actor_techniques').select('*', {count:'exact', head:true}).eq('actor_id', agrius[0].actor_id);
    console.log('Agrius actor_id:', agrius[0].actor_id, 'techniques:', count);
  }

  // Check total actor_techniques - how many unique actors have entries
  const { data: allActorTechs } = await sb.from('actor_techniques').select('actor_id');
  const actorCounts: Record<string, number> = {};
  if (allActorTechs) {
    for (const r of allActorTechs) {
      actorCounts[r.actor_id] = (actorCounts[r.actor_id] || 0) + 1;
    }
  }
  console.log('Unique actors with techniques:', Object.keys(actorCounts).length);
  console.log('Total actor_technique rows:', allActorTechs?.length);

  // Check the actor browse page query pattern
  const { data: browseActors } = await sb.from('attack_actors').select('actor_id, name').order('name').limit(5);
  const { data: techCounts } = await sb.from('actor_techniques').select('actor_id');
  const countMap: Record<string, number> = {};
  if (techCounts) {
    for (const row of techCounts) {
      countMap[row.actor_id] = (countMap[row.actor_id] || 0) + 1;
    }
  }
  console.log('\nFirst 5 actors with counts:');
  for (const a of browseActors || []) {
    console.log(`  ${a.name}: ${countMap[a.actor_id] || 0} techniques`);
  }
}
main();
