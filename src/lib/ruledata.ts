export const ruleFilterTypeMap: Record<string, { color: string; icon: string }> = {
  Domain: { color: 'accent', icon: 'globe' },
  'Use Case': { color: 'primary', icon: 'launch' },
  'Data Source': { color: 'default', icon: 'database' },
  'Hunt Type': { color: 'default', icon: 'eye' },
  OS: { color: 'success', icon: 'compute' },
  Tactic: { color: 'warning', icon: 'bug' },
  Technique: { color: 'hollow', icon: 'tag' },
  'Rule Type': { color: 'hollow', icon: 'layers' },
  Language: { color: 'default', icon: 'menu' },
  SIEM: { color: 'primary', icon: 'logoSecurity' },
};

export const siemColorMap: Record<string, string> = {
  Elastic: '#00BFB3',
  Splunk: '#ED0080',
  'Microsoft Sentinel': '#0078D4',
  'Google Chronicle': '#4285F4',
  Sigma: '#F4A261',
  'Palo Alto Cortex': '#FA582D',
  Wazuh: '#005F73',
  OpenSearch: '#003B49',
  'Sumo Logic': '#000099',
};

export const siemIconMap: Record<string, string> = {
  Elastic: 'logoElastic',
  Splunk: 'logoSplunk',
  'Microsoft Sentinel': 'logoCloud',
  'Google Chronicle': 'logoGCP',
  Sigma: 'securitySignal',
  'Palo Alto Cortex': 'logoSecurity',
  Wazuh: 'logoSecurity',
  OpenSearch: 'logoElasticsearch',
  'Sumo Logic': 'logoCloud',
};
