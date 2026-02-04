/**
 * Statistics and Analysis Types
 * Index statistics, source comparisons, and cached query results
 */

/**
 * Detection index statistics - summary counts and breakdowns
 */
export interface IndexStats {
  total: number;
  sigma: number;
  splunk_escu: number;
  elastic: number;
  kql: number;
  by_severity: Record<string, number>;
  by_logsource_product: Record<string, number>;
  mitre_coverage: number;
  cve_coverage: number;
  by_mitre_tactic: Record<string, number>;
  by_detection_type: Record<string, number>;
  stories_count: number;
  by_story_category: Record<string, number>;
  by_elastic_index: Record<string, number>;
}

/**
 * Source comparison result - comparing detection coverage across sources
 */
export interface SourceComparison {
  topic: string;
  total_found: number;
  by_source: {
    source: string;
    count: number;
    detections: Array<{ name: string; id: string; mitre: string[] }>;
  }[];
  by_tactic: {
    tactic: string;
    counts: Record<string, number>;
  }[];
  coverage_gaps: {
    tactic: string;
    sources_missing: string[];
  }[];
}

/**
 * Saved query result for caching expensive operations
 */
export interface SavedQuery {
  id: string;
  name: string;
  query_type: string;
  query_params: string;
  result_summary: string;
  created_at: string;
  expires_at: string | null;
}
