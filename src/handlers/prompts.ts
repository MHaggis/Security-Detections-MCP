// Prompt definitions - expert workflow prompts
export interface PromptDefinition {
  name: string;
  description: string;
  arguments?: Array<{ name: string; description: string; required: boolean }>;
}

export const prompts: PromptDefinition[] = [
  {
    name: 'ransomware-readiness-assessment',
    description: 'Comprehensive ransomware detection coverage assessment',
    arguments: [
      { name: 'priority_focus', description: 'Focus area: "prevention", "detection", "response", or "all"', required: false },
    ],
  },
  {
    name: 'apt-threat-emulation',
    description: 'APT group threat emulation planning with detection mapping',
    arguments: [
      { name: 'threat_actor', description: 'APT group name (e.g., APT29, Lazarus Group, Volt Typhoon)', required: true },
      { name: 'include_test_plan', description: 'Generate atomic test recommendations', required: false },
    ],
  },
  {
    name: 'purple-team-exercise',
    description: 'Design a purple team exercise targeting specific tactics/techniques',
    arguments: [
      { name: 'scope', description: 'MITRE tactic or technique ID', required: true },
      { name: 'environment', description: 'Target environment: "windows", "linux", "cloud", "hybrid"', required: false },
    ],
  },
  {
    name: 'soc-investigation-assist',
    description: 'Help investigate an alert with relevant detections and context',
    arguments: [
      { name: 'indicator', description: 'Alert name, process name, technique, or IOC', required: true },
      { name: 'context', description: 'Additional context about the alert', required: false },
    ],
  },
  {
    name: 'detection-engineering-sprint',
    description: 'Plan a detection engineering sprint with prioritized work',
    arguments: [
      { name: 'sprint_capacity', description: 'Number of detections to target', required: false },
      { name: 'threat_focus', description: 'Focus: "ransomware", "apt", "insider", "cloud", or "balanced"', required: false },
    ],
  },
  {
    name: 'executive-security-briefing',
    description: 'Generate executive-level security posture summary',
    arguments: [
      { name: 'audience', description: 'Target audience: "board", "ciso", "cto"', required: false },
      { name: 'include_benchmarks', description: 'Include industry benchmark comparisons', required: false },
    ],
  },
  {
    name: 'cve-response-assessment',
    description: 'Assess detection coverage for a CVE or named vulnerability',
    arguments: [
      { name: 'cve_or_threat', description: 'CVE ID or threat name', required: true },
    ],
  },
  {
    name: 'data-source-gap-analysis',
    description: 'Analyze data source requirements vs available detections',
    arguments: [
      { name: 'target_coverage', description: 'Specific tactic, technique, or "comprehensive"', required: false },
    ],
  },
  {
    name: 'detection-quality-review',
    description: 'Review detection quality for a specific technique',
    arguments: [
      { name: 'technique_id', description: 'MITRE technique ID to review', required: true },
    ],
  },
  {
    name: 'threat-landscape-sync',
    description: 'Sync detection priorities with current threat landscape',
    arguments: [
      { name: 'industry', description: 'Your industry vertical for threat relevance', required: false },
    ],
  },
  {
    name: 'detection-coverage-diff',
    description: 'Compare your detection coverage against threats',
    arguments: [
      { name: 'compare_against', description: 'APT group name, threat profile, or "baseline"', required: true },
    ],
  },
];

export function listPrompts() {
  return { prompts };
}

export async function getPrompt(name: string, args: Record<string, string> = {}) {
  const prompt = prompts.find(p => p.name === name);
  if (!prompt) {
    throw new Error(`Prompt not found: ${name}`);
  }

  // Generate prompt messages based on the template
  const messages = generatePromptMessages(name, args);
  
  return {
    description: prompt.description,
    messages,
  };
}

function generatePromptMessages(name: string, args: Record<string, string>) {
  // Template-based prompt generation
  switch (name) {
    case 'ransomware-readiness-assessment':
      return [{ role: 'user', content: { type: 'text', text: `Perform a comprehensive ransomware detection readiness assessment.${args.priority_focus ? ` Focus on: ${args.priority_focus}.` : ''} Use identify_gaps("ransomware"), analyze_coverage(), and get_stats() to evaluate our posture. Provide specific recommendations for improving detection coverage.` } }];
    
    case 'apt-threat-emulation':
      return [{ role: 'user', content: { type: 'text', text: `Plan a threat emulation exercise for ${args.threat_actor}. Map their known TTPs to our detection coverage using analyze_threat_actor("${args.threat_actor}"). ${args.include_test_plan !== 'false' ? 'Include atomic test recommendations for validation.' : ''} Identify gaps and prioritize detection development.` } }];
    
    case 'purple-team-exercise':
      return [{ role: 'user', content: { type: 'text', text: `Design a purple team exercise targeting ${args.scope}. Environment: ${args.environment || 'hybrid'}. Use list_by_mitre("${args.scope}") or list_by_mitre_tactic("${args.scope}") to find relevant detections. Include attack simulation steps and expected detection points.` } }];
    
    case 'soc-investigation-assist':
      return [{ role: 'user', content: { type: 'text', text: `Help investigate this alert/indicator: ${args.indicator}. ${args.context ? `Context: ${args.context}.` : ''} Search for related detections, map to MITRE techniques, and suggest investigation steps.` } }];
    
    case 'detection-engineering-sprint':
      return [{ role: 'user', content: { type: 'text', text: `Plan a detection engineering sprint. Capacity: ${args.sprint_capacity || 5} detections. Focus: ${args.threat_focus || 'balanced'}. Use identify_gaps() and suggest_detections() to prioritize work. Provide specific detection specifications.` } }];
    
    case 'executive-security-briefing':
      return [{ role: 'user', content: { type: 'text', text: `Generate an executive security briefing for ${args.audience || 'CISO'}. Use get_stats() and analyze_coverage() to summarize our detection posture. ${args.include_benchmarks !== 'false' ? 'Include industry benchmark context.' : ''} Highlight key risks and recommended investments.` } }];
    
    case 'cve-response-assessment':
      return [{ role: 'user', content: { type: 'text', text: `Assess our detection coverage for ${args.cve_or_threat}. Use list_by_cve() or search() to find relevant detections. Identify exploitation techniques and map to MITRE ATT&CK. Recommend additional detections if gaps exist.` } }];
    
    case 'data-source-gap-analysis':
      return [{ role: 'user', content: { type: 'text', text: `Analyze data source requirements${args.target_coverage ? ` for ${args.target_coverage}` : ''}. Use get_stats() and analyze_coverage() to identify what data sources are needed for comprehensive coverage. Recommend data collection priorities.` } }];
    
    case 'detection-quality-review':
      return [{ role: 'user', content: { type: 'text', text: `Review detection quality for ${args.technique_id}. Use list_by_mitre("${args.technique_id}") and suggest_detections("${args.technique_id}") to evaluate coverage depth. Assess detection logic, false positive risk, and recommend improvements.` } }];
    
    case 'threat-landscape-sync':
      return [{ role: 'user', content: { type: 'text', text: `Sync detection priorities with current threat landscape${args.industry ? ` for ${args.industry} industry` : ''}. Identify trending threats, map to our detection coverage, and recommend priority adjustments based on active threat actor activity.` } }];
    
    case 'detection-coverage-diff':
      return [{ role: 'user', content: { type: 'text', text: `Compare our detection coverage against ${args.compare_against}. Use analyze_threat_actor() or identify_gaps() to find differences. Highlight critical gaps and provide a prioritized remediation plan.` } }];
    
    default:
      return [{ role: 'user', content: { type: 'text', text: `Execute the ${name} workflow.` } }];
  }
}
