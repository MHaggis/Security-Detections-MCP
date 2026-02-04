/**
 * Analytic Story Types
 * Splunk analytic story and campaign grouping interfaces
 */

/**
 * Normalized Splunk Analytic Story structure
 * Stories group related detections into cohesive use cases
 */
export interface AnalyticStory {
  id: string;
  name: string;
  description: string;
  narrative: string;  // Detailed explanation - great for semantic search
  author: string | null;
  date: string | null;
  version: number | null;
  status: string | null;
  references: string[];
  category: string | null;    // Malware, Adversary Tactics, etc.
  usecase: string | null;     // Advanced Threat Detection, etc.
  detection_names: string[];  // Names of detections in this story (for linking)
}

/**
 * Raw Splunk story YAML structure as parsed from file
 */
export interface SplunkStoryYaml {
  name: string;
  id: string;
  version?: number;
  date?: string;
  author?: string;
  status?: string;
  description?: string;
  narrative?: string;
  references?: string[];
  tags?: {
    category?: string[];
    product?: string[];
    usecase?: string;
    [key: string]: unknown;
  };
}
