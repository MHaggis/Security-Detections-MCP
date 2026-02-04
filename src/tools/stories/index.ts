// Story-related tools for the Security Detections MCP
// Extracted from monolith index.ts for modular architecture

import { defineTool } from '../registry.js';
import { searchStories, getStoryByName, listStories, listStoriesByCategory } from '../../db/stories.js';

export const storyTools = [
  defineTool({
    name: 'search_stories',
    description: 'Search analytic stories by narrative, description, or name. Stories provide rich context about threat campaigns and detection strategies.',
    inputSchema: {
      type: 'object',
      properties: {
        query: {
          type: 'string',
          description: 'Search query for stories (e.g., "ransomware encryption", "credential theft", "persistence")',
        },
        limit: {
          type: 'number',
          description: 'Max results to return (default 20)',
        },
      },
      required: ['query'],
    },
    handler: async (args) => {
      const query = args?.query as string;
      const limit = (args?.limit as number) || 20;
      
      if (!query) {
        throw new Error('query is required');
      }
      
      const results = searchStories(query, limit);
      if (results.length === 0) {
        return {
          message: 'No stories found. Stories are optional - set STORY_PATHS env var to index them.',
          results: [],
        };
      }
      return results;
    },
  }),

  defineTool({
    name: 'get_story',
    description: 'Get detailed information about a specific analytic story by name',
    inputSchema: {
      type: 'object',
      properties: {
        name: {
          type: 'string',
          description: 'Story name (e.g., "Ransomware", "Windows Persistence Techniques")',
        },
      },
      required: ['name'],
    },
    handler: async (args) => {
      const storyName = args?.name as string;
      
      if (!storyName) {
        throw new Error('name is required');
      }
      
      const story = getStoryByName(storyName);
      if (!story) {
        throw new Error(`Story not found: ${storyName}. Stories are optional - set STORY_PATHS env var to index them.`);
      }
      
      return story;
    },
  }),

  defineTool({
    name: 'list_stories',
    description: 'List all analytic stories with pagination',
    inputSchema: {
      type: 'object',
      properties: {
        limit: {
          type: 'number',
          description: 'Max results to return (default 100)',
        },
        offset: {
          type: 'number',
          description: 'Offset for pagination (default 0)',
        },
      },
    },
    handler: async (args) => {
      const limit = (args?.limit as number) || 100;
      const offset = (args?.offset as number) || 0;
      
      const results = listStories(limit, offset);
      if (results.length === 0) {
        return {
          message: 'No stories indexed. Stories are optional - set STORY_PATHS env var to index them.',
          results: [],
        };
      }
      return results;
    },
  }),

  defineTool({
    name: 'list_stories_by_category',
    description: 'List analytic stories by category (e.g., "Malware", "Adversary Tactics", "Abuse")',
    inputSchema: {
      type: 'object',
      properties: {
        category: {
          type: 'string',
          description: 'Story category (e.g., "Malware", "Adversary Tactics", "Abuse", "Cloud Security")',
        },
        limit: {
          type: 'number',
          description: 'Max results to return (default 100)',
        },
        offset: {
          type: 'number',
          description: 'Offset for pagination (default 0)',
        },
      },
      required: ['category'],
    },
    handler: async (args) => {
      const category = args?.category as string;
      const limit = (args?.limit as number) || 100;
      const offset = (args?.offset as number) || 0;
      
      if (!category) {
        throw new Error('category is required');
      }
      
      const results = listStoriesByCategory(category, limit, offset);
      return results;
    },
  }),
];
