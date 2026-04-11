import { NextRequest, NextResponse } from 'next/server';
import { createClient } from '@supabase/supabase-js';

function getSupabase() {
  return createClient(
    process.env.NEXT_PUBLIC_SUPABASE_URL!,
    process.env.SUPABASE_SERVICE_ROLE_KEY!
  );
}

export async function GET(request: NextRequest) {
  const supabase = getSupabase();
  const { searchParams } = new URL(request.url);
  const q = searchParams.get('q') || '';
  const source = searchParams.get('source');
  const severity = searchParams.get('severity');
  const technique = searchParams.get('technique');
  const limit = Math.min(parseInt(searchParams.get('limit') || '50'), 100);
  const offset = parseInt(searchParams.get('offset') || '0');

  let query = supabase
    .from('detections')
    .select('id, name, description, source_type, severity, mitre_ids, detection_type, mitre_tactics', { count: 'exact' });

  if (q) {
    query = query.textSearch('search_vector', q.split(' ').join(' & '));
  }
  if (source) {
    query = query.eq('source_type', source);
  }
  if (severity) {
    query = query.eq('severity', severity);
  }
  if (technique) {
    // Use junction table via inner join
    const { data: detectionIds } = await supabase
      .from('detection_techniques')
      .select('detection_id')
      .eq('technique_id', technique);

    if (detectionIds && detectionIds.length > 0) {
      query = query.in('id', detectionIds.map(d => d.detection_id));
    } else {
      return NextResponse.json({ detections: [], total: 0 });
    }
  }

  const { data, count, error } = await query
    .order('name')
    .range(offset, offset + limit - 1);

  if (error) {
    return NextResponse.json({ error: error.message }, { status: 500 });
  }

  return NextResponse.json({
    detections: data,
    total: count ?? 0,
    limit,
    offset,
  });
}
