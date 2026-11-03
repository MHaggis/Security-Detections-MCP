import './isolated-db.js';
import { indexDetections } from '../dist/indexer.js';
import { initPatternsSchema, extractAllPatterns } from '../dist/db/patterns.js';

const paths = name => (process.env[name] || '').split(',').map(p => p.trim()).filter(Boolean);
if (!paths('SIGMA_PATHS').length || !paths('SPLUNK_PATHS').length || !paths('STORY_PATHS').length) {
  throw new Error('Content tests require SIGMA_PATHS, SPLUNK_PATHS and STORY_PATHS. See SETUP.md; tests build a disposable index from these sources.');
}
const result = indexDetections(
  paths('SIGMA_PATHS'), paths('SPLUNK_PATHS'), paths('STORY_PATHS'),
  paths('ELASTIC_PATHS'), paths('KQL_PATHS'), paths('SUBLIME_PATHS'),
  paths('CQL_HUB_PATHS'), paths('JAMF_PROTECT_PATHS'),
);
if (!result.sigma_indexed || !result.splunk_indexed || !result.stories_indexed) {
  throw new Error(`Required content was not indexed: ${JSON.stringify(result)}`);
}
initPatternsSchema();
extractAllPatterns();
