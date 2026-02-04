/**
 * Utility Helpers
 * 
 * Common utility functions used across the MCP codebase.
 */

/**
 * Safely parse JSON with a default fallback value.
 * Prevents crashes from malformed JSON in the database.
 * 
 * @param json - The JSON string to parse (can be null/undefined)
 * @param defaultValue - Value to return if parsing fails
 * @returns Parsed value or default
 */
export function safeJsonParse<T>(json: string | null | undefined, defaultValue: T): T {
  if (json === null || json === undefined || json === '') {
    return defaultValue;
  }
  
  try {
    return JSON.parse(json) as T;
  } catch (error) {
    console.error(`[utils] JSON parse error: ${error instanceof Error ? error.message : String(error)}`);
    return defaultValue;
  }
}

/**
 * Safely stringify an object to JSON.
 * Returns null on error instead of throwing.
 * 
 * @param value - The value to stringify
 * @returns JSON string or null on error
 */
export function safeJsonStringify(value: unknown): string | null {
  try {
    return JSON.stringify(value);
  } catch (error) {
    console.error(`[utils] JSON stringify error: ${error instanceof Error ? error.message : String(error)}`);
    return null;
  }
}

/**
 * Wrap a function with error handling.
 * Logs errors and optionally rethrows.
 * 
 * @param name - Name for logging
 * @param fn - Function to wrap
 * @param rethrow - Whether to rethrow errors (default: false)
 * @returns Wrapped function
 */
export function withErrorHandling<T extends (...args: unknown[]) => unknown>(
  name: string,
  fn: T,
  rethrow = false
): T {
  return ((...args: unknown[]) => {
    try {
      const result = fn(...args);
      
      // Handle promises
      if (result instanceof Promise) {
        return result.catch((error: unknown) => {
          const message = error instanceof Error ? error.message : String(error);
          console.error(`[${name}] Async error: ${message}`);
          if (rethrow) throw error;
          return null;
        });
      }
      
      return result;
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error);
      console.error(`[${name}] Error: ${message}`);
      if (rethrow) throw error;
      return null;
    }
  }) as T;
}

/**
 * Ensure a value is an array.
 * 
 * @param value - Value that might be an array
 * @returns Array (original if array, wrapped in array if single value, empty if null/undefined)
 */
export function ensureArray<T>(value: T | T[] | null | undefined): T[] {
  if (value === null || value === undefined) return [];
  return Array.isArray(value) ? value : [value];
}

/**
 * Truncate a string to a maximum length with ellipsis.
 * 
 * @param str - String to truncate
 * @param maxLength - Maximum length (including ellipsis)
 * @returns Truncated string
 */
export function truncate(str: string, maxLength: number): string {
  if (str.length <= maxLength) return str;
  return str.substring(0, maxLength - 3) + '...';
}

/**
 * Generate a unique ID.
 * 
 * @param prefix - Optional prefix for the ID
 * @returns Unique ID string
 */
export function generateId(prefix = ''): string {
  const timestamp = Date.now().toString(36);
  const random = Math.random().toString(36).substring(2, 11);
  return prefix ? `${prefix}_${timestamp}_${random}` : `${timestamp}_${random}`;
}

/**
 * Check if a value is a non-empty string.
 */
export function isNonEmptyString(value: unknown): value is string {
  return typeof value === 'string' && value.trim().length > 0;
}

/**
 * Check if a value is a valid MITRE technique ID.
 */
export function isValidMitreId(value: unknown): boolean {
  if (typeof value !== 'string') return false;
  return /^T\d{4}(\.\d{3})?$/.test(value);
}

/**
 * Format a date to ISO string safely.
 */
export function formatDate(date?: Date | string | number): string {
  try {
    const d = date ? new Date(date) : new Date();
    return d.toISOString();
  } catch {
    return new Date().toISOString();
  }
}
