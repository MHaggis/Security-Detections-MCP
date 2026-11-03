import { homedir } from 'os';
import { dirname, join, resolve } from 'path';

// Both database entry points must use the same path. Tests and automation can
// select a disposable database without touching the user's detection cache.
export const DB_PATH = process.env.DETECTIONS_DB_PATH
  ? resolve(process.env.DETECTIONS_DB_PATH)
  : join(homedir(), '.cache', 'security-detections-mcp', 'detections.sqlite');
export const CACHE_DIR = dirname(DB_PATH);
