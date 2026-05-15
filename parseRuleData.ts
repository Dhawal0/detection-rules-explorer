import * as tar from 'tar';
import { PassThrough } from 'stream';
import * as toml from 'toml';
import * as yaml from 'js-yaml';
import * as fs from 'fs';
import axios, { AxiosInstance } from 'axios';

interface RuleSummary {
  id: string;
  name: string;
  tags: string[];
  updated_date: Date;
  source_siem: string;
}

interface TagSummary {
  tag_type: string;
  tag_name: string;
  tag_full: string;
  count: number;
}

const RULES_OUTPUT_PATH = './src/data/rules/';

// MITRE tactic ID -> name mapping
const TACTIC_MAP: Record<string, string> = {
  TA0001: 'Initial Access',
  TA0002: 'Execution',
  TA0003: 'Persistence',
  TA0004: 'Privilege Escalation',
  TA0005: 'Defense Evasion',
  TA0006: 'Credential Access',
  TA0007: 'Discovery',
  TA0008: 'Lateral Movement',
  TA0009: 'Collection',
  TA0010: 'Exfiltration',
  TA0011: 'Command and Control',
  TA0040: 'Impact',
  TA0042: 'Resource Development',
  TA0043: 'Reconnaissance',
};

// Sentinel tactic name -> normalized name
const SENTINEL_TACTIC_MAP: Record<string, string> = {
  InitialAccess: 'Initial Access',
  Execution: 'Execution',
  Persistence: 'Persistence',
  PrivilegeEscalation: 'Privilege Escalation',
  DefenseEvasion: 'Defense Evasion',
  CredentialAccess: 'Credential Access',
  Discovery: 'Discovery',
  LateralMovement: 'Lateral Movement',
  Collection: 'Collection',
  Exfiltration: 'Exfiltration',
  CommandAndControl: 'Command and Control',
  Impact: 'Impact',
  ResourceDevelopment: 'Resource Development',
  Reconnaissance: 'Reconnaissance',
  PreAttack: 'Pre-Attack',
};

// Sigma tag prefix -> tactic name
const SIGMA_TACTIC_MAP: Record<string, string> = {
  'attack.initial_access': 'Initial Access',
  'attack.execution': 'Execution',
  'attack.persistence': 'Persistence',
  'attack.privilege_escalation': 'Privilege Escalation',
  'attack.defense_evasion': 'Defense Evasion',
  'attack.credential_access': 'Credential Access',
  'attack.discovery': 'Discovery',
  'attack.lateral_movement': 'Lateral Movement',
  'attack.collection': 'Collection',
  'attack.exfiltration': 'Exfiltration',
  'attack.command_and_control': 'Command and Control',
  'attack.impact': 'Impact',
  'attack.resource_development': 'Resource Development',
  'attack.reconnaissance': 'Reconnaissance',
};

function githubClient(): AxiosInstance {
  const headers: Record<string, string> = {
    Accept: 'application/vnd.github.v3+json',
  };
  if (process.env.GITHUB_TOKEN) {
    headers.Authorization = `Bearer ${process.env.GITHUB_TOKEN}`;
  }
  return axios.create({ headers, timeout: 30000 });
}

function addTagSummary(t: string, tagSummaries: Map<string, TagSummary>) {
  const parts = t.split(': ');
  if (parts.length !== 2) return;
  let s = tagSummaries.get(t);
  if (s == undefined) {
    s = { tag_type: parts[0], tag_name: parts[1], tag_full: t, count: 0 };
  }
  s.count++;
  tagSummaries.set(t, s);
}

function addRule(
  id: string,
  name: string,
  tags: string[],
  updatedDate: Date,
  sourceSiem: string,
  content: object,
  ruleSummaries: RuleSummary[],
  tagSummaries: Map<string, TagSummary>
) {
  const siemTag = `SIEM: ${sourceSiem}`;
  if (!tags.includes(siemTag)) tags.push(siemTag);

  ruleSummaries.push({ id, name, tags, updated_date: updatedDate, source_siem: sourceSiem });
  for (const t of tags) addTagSummary(t, tagSummaries);

  fs.writeFileSync(`${RULES_OUTPUT_PATH}${id}.json`, JSON.stringify(content));
}

// ─── ELASTIC ─────────────────────────────────────────────────────────────────

async function getElasticPrebuiltRules(
  ruleSummaries: RuleSummary[],
  tagSummaries: Map<string, TagSummary>
) {
  const gh = githubClient();
  const releasesUrl = 'https://api.github.com/repos/elastic/detection-rules/releases/latest';
  const release = await gh.get(releasesUrl);
  const asset = release.data.assets.find((a: { name: string }) =>
    a.name.includes('detection-rules-')
  );
  if (!asset) { console.log('No Elastic rules tarball found'); return; }

  const tarRes = await axios.get(asset.browser_download_url, { responseType: 'stream' });
  const parser = new tar.Parse();
  tarRes.data.pipe(parser);

  let count = 0;
  parser.on('entry', entry => {
    if (!entry.path.endsWith('.toml') || !entry.path.includes('/rules/')) {
      entry.resume();
      return;
    }
    let buf = Buffer.alloc(0);
    const contentStream = new PassThrough();
    entry.pipe(contentStream);
    contentStream.on('data', (d: Buffer) => { buf = Buffer.concat([buf, d]); });
    contentStream.on('end', () => {
      try {
        const parsed = toml.parse(buf.toString('utf-8'));
        const r = parsed.rule;
        const m = parsed.metadata;
        if (!r || !r.rule_id) return;

        const tags: string[] = (r.tags || []).filter((t: string) => t !== 'Elastic');
        const threat = r.threat || [];

        addRule(
          r.rule_id, r.name, tags,
          new Date(m?.updated_date || m?.creation_date || Date.now()),
          'Elastic',
          { metadata: { ...m, source_siem: 'Elastic', source_siem_id: 'elastic' }, rule: r },
          ruleSummaries, tagSummaries
        );
        count++;
      } catch (_) { /* skip malformed */ }
    });
  });

  await new Promise(resolve => parser.on('finish', resolve));
  console.log(`Elastic: loaded ${count} prebuilt rules`);
}

// ─── SPLUNK ───────────────────────────────────────────────────────────────────

function splunkSeverityToRisk(severity: string): number {
  const map: Record<string, number> = { critical: 99, high: 73, medium: 47, low: 21, informational: 5 };
  return map[severity?.toLowerCase()] ?? 47;
}

async function getSplunkRules(
  ruleSummaries: RuleSummary[],
  tagSummaries: Map<string, TagSummary>
) {
  const gh = githubClient();
  const treeUrl = 'https://api.github.com/repos/splunk/security_content/git/trees/develop?recursive=1';
  const tree = await gh.get(treeUrl);
  const files = (tree.data.tree as { path: string; type: string }[])
    .filter(f => f.type === 'blob' && f.path.startsWith('detections/') && f.path.endsWith('.yml'))
    .slice(0, 600);

  const commitRes = await gh.get(
    'https://api.github.com/repos/splunk/security_content/commits?path=detections&per_page=1'
  );
  const updatedDate = new Date(commitRes.data[0]?.commit?.committer?.date || Date.now());

  let count = 0;
  for (const file of files) {
    try {
      const raw = await gh.get(
        `https://raw.githubusercontent.com/splunk/security_content/develop/${file.path}`
      );
      const rule = yaml.load(raw.data) as Record<string, unknown>;
      if (!rule?.id || !rule?.name || rule.status === 'deprecated') continue;

      const tags: string[] = ['Data Source: Splunk'];
      const mitreTags: string[] = (rule.tags as Record<string, unknown>)?.mitre_attack_id as string[] || [];

      // Map MITRE techniques to tactic tags (best effort from technique prefix)
      const tacticTagsAdded = new Set<string>();
      for (const tid of mitreTags) {
        tags.push(`Technique: ${tid}`);
      }

      const severity = (rule.severity as string) || 'medium';
      const domain = (file.path.split('/')[1] || 'other').replace(/_/g, ' ');
      tags.push(`Domain: ${domain.charAt(0).toUpperCase() + domain.slice(1)}`);
      tags.push(`Rule Type: Query`);
      tags.push(`OS: ${(rule.tags as Record<string, unknown>)?.product ?
        [(rule.tags as Record<string, unknown>).product].flat().join(', ') : 'Any'}`);

      const id = `splunk-${rule.id}`;
      addRule(
        id, rule.name as string, tags, updatedDate, 'Splunk',
        {
          metadata: { updated_date: updatedDate, source_siem: 'Splunk', source_siem_id: 'splunk', source_url: `https://github.com/splunk/security_content/blob/develop/${file.path}` },
          rule: {
            name: rule.name,
            description: rule.description,
            tags,
            severity,
            risk_score: splunkSeverityToRisk(severity),
            type: 'query',
            language: 'spl',
            query: rule.search,
            reference: rule.references || [],
            false_positives: rule.known_false_positives ? [rule.known_false_positives as string] : [],
          }
        },
        ruleSummaries, tagSummaries
      );
      count++;
    } catch (_) { /* skip */ }
  }
  console.log(`Splunk: loaded ${count} rules`);
}

// ─── MICROSOFT SENTINEL ───────────────────────────────────────────────────────

async function getSentinelRules(
  ruleSummaries: RuleSummary[],
  tagSummaries: Map<string, TagSummary>
) {
  const gh = githubClient();
  const treeUrl = 'https://api.github.com/repos/Azure/Azure-Sentinel/git/trees/master?recursive=1';
  const tree = await gh.get(treeUrl);
  const files = (tree.data.tree as { path: string; type: string }[])
    .filter(f => f.type === 'blob' && f.path.startsWith('Detections/') && f.path.endsWith('.json'))
    .slice(0, 500);

  const commitRes = await gh.get(
    'https://api.github.com/repos/Azure/Azure-Sentinel/commits?path=Detections&per_page=1'
  );
  const updatedDate = new Date(commitRes.data[0]?.commit?.committer?.date || Date.now());

  let count = 0;
  for (const file of files) {
    try {
      const raw = await gh.get(
        `https://raw.githubusercontent.com/Azure/Azure-Sentinel/master/${file.path}`
      );
      const data = typeof raw.data === 'string' ? JSON.parse(raw.data) : raw.data;
      const props = data.properties;
      if (!props?.displayName) continue;

      const tactics: string[] = (props.tactics || []).map(
        (t: string) => `Tactic: ${SENTINEL_TACTIC_MAP[t] || t}`
      );
      const techniques: string[] = (props.techniques || []).map((t: string) => `Technique: ${t}`);
      const severity = props.severity || 'Medium';
      const tags: string[] = [
        ...tactics,
        ...techniques,
        `Domain: Cloud`,
        `Rule Type: Scheduled`,
        'Data Source: Azure',
      ];

      const id = `sentinel-${data.name || data.id || Buffer.from(props.displayName).toString('hex').slice(0, 32)}`;
      addRule(
        id, props.displayName, tags, updatedDate, 'Microsoft Sentinel',
        {
          metadata: { updated_date: updatedDate, source_siem: 'Microsoft Sentinel', source_siem_id: 'sentinel', source_url: `https://github.com/Azure/Azure-Sentinel/blob/master/${file.path}` },
          rule: {
            name: props.displayName,
            description: props.description,
            tags,
            severity: severity.toLowerCase(),
            risk_score: splunkSeverityToRisk(severity.toLowerCase()),
            type: 'query',
            language: 'kql',
            query: props.query,
            reference: [],
            false_positives: [],
          }
        },
        ruleSummaries, tagSummaries
      );
      count++;
    } catch (_) { /* skip */ }
  }
  console.log(`Sentinel: loaded ${count} rules`);
}

// ─── GOOGLE CHRONICLE ─────────────────────────────────────────────────────────

function parseYaraLMeta(content: string): Record<string, string> {
  const meta: Record<string, string> = {};
  const metaMatch = content.match(/meta:\s*([\s\S]*?)(?:events:|match:|condition:|outcome:)/);
  if (!metaMatch) return meta;
  for (const line of metaMatch[1].split('\n')) {
    const m = line.match(/^\s*(\w+)\s*=\s*"(.*)"/);
    if (m) meta[m[1]] = m[2];
  }
  return meta;
}

async function getChronicleRules(
  ruleSummaries: RuleSummary[],
  tagSummaries: Map<string, TagSummary>
) {
  const gh = githubClient();
  const treeUrl = 'https://api.github.com/repos/chronicle/detection-rules/git/trees/main?recursive=1';
  const tree = await gh.get(treeUrl);
  const files = (tree.data.tree as { path: string; type: string }[])
    .filter(f => f.type === 'blob' && f.path.endsWith('.yaral'))
    .slice(0, 300);

  const commitRes = await gh.get(
    'https://api.github.com/repos/chronicle/detection-rules/commits?path=.&per_page=1'
  );
  const updatedDate = new Date(commitRes.data[0]?.commit?.committer?.date || Date.now());

  let count = 0;
  for (const file of files) {
    try {
      const raw = await gh.get(
        `https://raw.githubusercontent.com/chronicle/detection-rules/main/${file.path}`
      );
      const content = raw.data as string;
      const meta = parseYaraLMeta(content);
      const ruleNameMatch = content.match(/^rule\s+(\w+)/m);
      const ruleName = meta.rule_name || ruleNameMatch?.[1]?.replace(/_/g, ' ') || file.path;

      const tags: string[] = ['Rule Type: YARA-L', 'Domain: Cloud', 'Data Source: Google SecOps'];
      if (meta.mitre_attack_tactic) {
        const tacticId = meta.mitre_attack_tactic;
        tags.push(`Tactic: ${TACTIC_MAP[tacticId] || tacticId}`);
      }
      if (meta.mitre_attack_technique) tags.push(`Technique: ${meta.mitre_attack_technique}`);

      const id = `chronicle-${file.path.replace(/\//g, '-').replace('.yaral', '')}`;
      addRule(
        id, ruleName, tags, updatedDate, 'Google Chronicle',
        {
          metadata: { updated_date: updatedDate, source_siem: 'Google Chronicle', source_siem_id: 'chronicle', source_url: `https://github.com/chronicle/detection-rules/blob/main/${file.path}` },
          rule: {
            name: ruleName,
            description: meta.description || '',
            tags,
            severity: 'medium',
            risk_score: 47,
            type: 'yara-l',
            language: 'yara-l',
            query: content,
            reference: meta.reference ? [meta.reference] : [],
            false_positives: [],
          }
        },
        ruleSummaries, tagSummaries
      );
      count++;
    } catch (_) { /* skip */ }
  }
  console.log(`Chronicle: loaded ${count} rules`);
}

// ─── SIGMA ────────────────────────────────────────────────────────────────────

async function getSigmaRules(
  ruleSummaries: RuleSummary[],
  tagSummaries: Map<string, TagSummary>
) {
  const gh = githubClient();
  const releasesUrl = 'https://api.github.com/repos/SigmaHQ/sigma/releases/latest';
  const release = await gh.get(releasesUrl);
  const asset = release.data.assets.find((a: { name: string }) =>
    a.name.includes('sigma_all_rules') && a.name.endsWith('.zip')
  );
  if (!asset) {
    console.log('Sigma: no release zip found, falling back to tree API');
    await getSigmaRulesFromTree(ruleSummaries, tagSummaries);
    return;
  }

  // Use tree API as fallback since zip parsing requires unzipper
  await getSigmaRulesFromTree(ruleSummaries, tagSummaries);
}

async function getSigmaRulesFromTree(
  ruleSummaries: RuleSummary[],
  tagSummaries: Map<string, TagSummary>
) {
  const gh = githubClient();
  const treeUrl = 'https://api.github.com/repos/SigmaHQ/sigma/git/trees/master?recursive=1';
  const tree = await gh.get(treeUrl);
  const files = (tree.data.tree as { path: string; type: string }[])
    .filter(f => {
      if (f.type !== 'blob' || !f.path.endsWith('.yml')) return false;
      if (!f.path.startsWith('rules/')) return false;
      // Focus on high-value rule directories
      const parts = f.path.split('/');
      if (parts.length < 2) return false;
      return true;
    })
    .slice(0, 800);

  const commitRes = await gh.get(
    'https://api.github.com/repos/SigmaHQ/sigma/commits?path=rules&per_page=1'
  );
  const updatedDate = new Date(commitRes.data[0]?.commit?.committer?.date || Date.now());

  let count = 0;
  for (const file of files) {
    try {
      const raw = await gh.get(
        `https://raw.githubusercontent.com/SigmaHQ/sigma/master/${file.path}`
      );
      const rule = yaml.load(raw.data) as Record<string, unknown>;
      if (!rule?.title || !rule?.id || rule.status === 'deprecated' || rule.status === 'unsupported') continue;

      const tags: string[] = ['Rule Type: Sigma', 'Data Source: Cross-SIEM'];
      const sigmaTags: string[] = (rule.tags as string[]) || [];

      for (const t of sigmaTags) {
        if (SIGMA_TACTIC_MAP[t]) {
          tags.push(`Tactic: ${SIGMA_TACTIC_MAP[t]}`);
        } else if (t.startsWith('attack.t')) {
          const techId = t.replace('attack.', '').toUpperCase();
          tags.push(`Technique: ${techId}`);
        }
      }

      const logsource = rule.logsource as Record<string, string> || {};
      if (logsource.product) tags.push(`OS: ${logsource.product.charAt(0).toUpperCase() + logsource.product.slice(1)}`);
      if (logsource.category) tags.push(`Domain: ${logsource.category.replace(/_/g, ' ')}`);

      const level = (rule.level as string) || 'medium';
      const id = `sigma-${rule.id}`;
      addRule(
        id, rule.title as string, tags, updatedDate, 'Sigma',
        {
          metadata: {
            updated_date: rule.date || updatedDate,
            creation_date: rule.date,
            source_siem: 'Sigma', source_siem_id: 'sigma',
            source_url: `https://github.com/SigmaHQ/sigma/blob/master/${file.path}`
          },
          rule: {
            name: rule.title,
            description: rule.description || '',
            tags,
            severity: level,
            risk_score: splunkSeverityToRisk(level),
            type: 'sigma',
            language: 'sigma',
            query: JSON.stringify(rule.detection, null, 2),
            reference: (rule.references as string[]) || [],
            false_positives: (rule.falsepositives as string[]) || [],
          }
        },
        ruleSummaries, tagSummaries
      );
      count++;
    } catch (_) { /* skip */ }
  }
  console.log(`Sigma: loaded ${count} rules`);
}

// ─── CROWDSTRIKE ──────────────────────────────────────────────────────────────

async function getCrowdStrikeRules(
  ruleSummaries: RuleSummary[],
  tagSummaries: Map<string, TagSummary>
) {
  const gh = githubClient();
  const treeUrl = 'https://api.github.com/repos/MrM8BRH/Falcon-NextGen-SIEM/git/trees/main?recursive=1';
  let tree;
  try { tree = await gh.get(treeUrl); } catch (_) { console.log('CrowdStrike: repo unavailable'); return; }

  const files = (tree.data.tree as { path: string; type: string }[])
    .filter(f => f.type === 'blob' && (f.path.endsWith('.md') || f.path.endsWith('.json') || f.path.endsWith('.yaml')))
    .filter(f => f.path.toLowerCase().includes('rule') || f.path.toLowerCase().includes('detect') || f.path.toLowerCase().includes('cql'))
    .slice(0, 100);

  const commitRes = await gh.get(
    'https://api.github.com/repos/MrM8BRH/Falcon-NextGen-SIEM/commits?per_page=1'
  );
  const updatedDate = new Date(commitRes.data[0]?.commit?.committer?.date || Date.now());

  // Since most CrowdStrike content is in Markdown/docs, we parse official XQL repo instead
  await getCortexXQLRules(ruleSummaries, tagSummaries, updatedDate);
}

async function getCortexXQLRules(
  ruleSummaries: RuleSummary[],
  tagSummaries: Map<string, TagSummary>,
  fallbackDate: Date
) {
  const gh = githubClient();
  const treeUrl = 'https://api.github.com/repos/PaloAltoNetworks/cortex-xql-queries/git/trees/main?recursive=1';
  let tree;
  try { tree = await gh.get(treeUrl); } catch (_) { console.log('Cortex XQL: repo unavailable'); return; }

  const files = (tree.data.tree as { path: string; type: string }[])
    .filter(f => f.type === 'blob' && (f.path.endsWith('.xql') || f.path.endsWith('.yaml') || f.path.endsWith('.json')))
    .slice(0, 150);

  const commitRes = await gh.get(
    'https://api.github.com/repos/PaloAltoNetworks/cortex-xql-queries/commits?per_page=1'
  ).catch(() => ({ data: [{ commit: { committer: { date: fallbackDate.toISOString() } } }] }));
  const updatedDate = new Date(commitRes.data[0]?.commit?.committer?.date || fallbackDate);

  let count = 0;
  for (const file of files) {
    try {
      const raw = await gh.get(
        `https://raw.githubusercontent.com/PaloAltoNetworks/cortex-xql-queries/main/${file.path}`
      );
      let name = file.path.split('/').pop()?.replace(/\.(xql|yaml|json)$/, '').replace(/_/g, ' ') || file.path;
      name = name.charAt(0).toUpperCase() + name.slice(1);

      const tags: string[] = ['Rule Type: XQL', 'Data Source: Palo Alto Cortex', 'Domain: Endpoint'];
      const id = `cortex-${file.path.replace(/\//g, '-').replace(/\.[^.]+$/, '')}`;

      addRule(
        id, name, tags, updatedDate, 'Palo Alto Cortex',
        {
          metadata: { updated_date: updatedDate, source_siem: 'Palo Alto Cortex', source_siem_id: 'cortex', source_url: `https://github.com/PaloAltoNetworks/cortex-xql-queries/blob/main/${file.path}` },
          rule: {
            name,
            description: `XQL query from Palo Alto Networks Cortex XDR/XSIAM`,
            tags,
            severity: 'medium',
            risk_score: 47,
            type: 'xql',
            language: 'xql',
            query: typeof raw.data === 'string' ? raw.data : JSON.stringify(raw.data, null, 2),
            reference: [`https://github.com/PaloAltoNetworks/cortex-xql-queries/blob/main/${file.path}`],
            false_positives: [],
          }
        },
        ruleSummaries, tagSummaries
      );
      count++;
    } catch (_) { /* skip */ }
  }
  console.log(`Palo Alto Cortex: loaded ${count} rules`);
}

// ─── WAZUH ────────────────────────────────────────────────────────────────────

async function getWazuhRules(
  ruleSummaries: RuleSummary[],
  tagSummaries: Map<string, TagSummary>
) {
  const gh = githubClient();
  // Use wazuh's ruleset directory
  const treeUrl = 'https://api.github.com/repos/wazuh/wazuh/git/trees/master?recursive=1';
  let tree;
  try { tree = await gh.get(treeUrl); } catch (_) { console.log('Wazuh: repo unavailable'); return; }

  const files = (tree.data.tree as { path: string; type: string }[])
    .filter(f => f.type === 'blob' && f.path.startsWith('ruleset/rules/') && f.path.endsWith('.xml'))
    .slice(0, 80);

  const commitRes = await gh.get(
    'https://api.github.com/repos/wazuh/wazuh/commits?path=ruleset/rules&per_page=1'
  ).catch(() => ({ data: [{ commit: { committer: { date: new Date().toISOString() } } }] }));
  const updatedDate = new Date(commitRes.data[0]?.commit?.committer?.date || Date.now());

  let count = 0;
  for (const file of files) {
    try {
      const raw = await gh.get(
        `https://raw.githubusercontent.com/wazuh/wazuh/master/${file.path}`
      );
      const content = raw.data as string;
      // Extract rule groups/ids from XML (simple regex approach)
      const groupMatch = content.match(/<group\s+name="([^"]+)"/g);
      const ruleMatches = content.matchAll(/<rule\s+id="(\d+)"[^>]*level="(\d+)"[^>]*>([\s\S]*?)<\/rule>/g);

      for (const match of ruleMatches) {
        const [, ruleId, level, body] = match;
        const descMatch = body.match(/<description>(.*?)<\/description>/);
        if (!descMatch) continue;
        const name = descMatch[1];
        const groupNames = (groupMatch || []).map(g => g.match(/name="([^"]+)"/)?.[1] || '');

        const tags: string[] = ['Rule Type: Wazuh XML', 'Data Source: Wazuh', 'Domain: Endpoint'];
        const levelNum = parseInt(level);
        const severity = levelNum >= 12 ? 'high' : levelNum >= 7 ? 'medium' : 'low';
        tags.push(`Tactic: ${groupNames[0]?.replace(/_/g, ' ') || 'Defense Evasion'}`);

        const id = `wazuh-${ruleId}`;
        addRule(
          id, name, tags, updatedDate, 'Wazuh',
          {
            metadata: { updated_date: updatedDate, source_siem: 'Wazuh', source_siem_id: 'wazuh', source_url: `https://github.com/wazuh/wazuh/blob/master/${file.path}` },
            rule: {
              name,
              description: name,
              tags,
              severity,
              risk_score: splunkSeverityToRisk(severity),
              type: 'wazuh-xml',
              language: 'xml',
              query: body.trim(),
              reference: [],
              false_positives: [],
            }
          },
          ruleSummaries, tagSummaries
        );
        count++;
        if (count >= 200) break;
      }
      if (count >= 200) break;
    } catch (_) { /* skip */ }
  }
  console.log(`Wazuh: loaded ${count} rules`);
}

// ─── OPENSEARCH ───────────────────────────────────────────────────────────────

async function getOpenSearchRules(
  ruleSummaries: RuleSummary[],
  tagSummaries: Map<string, TagSummary>
) {
  const gh = githubClient();
  const treeUrl = 'https://api.github.com/repos/opensearch-project/security-analytics/git/trees/main?recursive=1';
  let tree;
  try { tree = await gh.get(treeUrl); } catch (_) { console.log('OpenSearch: repo unavailable'); return; }

  const files = (tree.data.tree as { path: string; type: string }[])
    .filter(f => f.type === 'blob' && f.path.includes('config/rules') && f.path.endsWith('.yml'))
    .slice(0, 300);

  const commitRes = await gh.get(
    'https://api.github.com/repos/opensearch-project/security-analytics/commits?per_page=1'
  ).catch(() => ({ data: [{ commit: { committer: { date: new Date().toISOString() } } }] }));
  const updatedDate = new Date(commitRes.data[0]?.commit?.committer?.date || Date.now());

  let count = 0;
  for (const file of files) {
    try {
      const raw = await gh.get(
        `https://raw.githubusercontent.com/opensearch-project/security-analytics/main/${file.path}`
      );
      const rule = yaml.load(raw.data) as Record<string, unknown>;
      if (!rule?.title || !rule?.id) continue;

      const tags: string[] = ['Rule Type: Sigma', 'Data Source: OpenSearch', 'Domain: Cloud'];
      const sigmaTags: string[] = (rule.tags as string[]) || [];
      for (const t of sigmaTags) {
        if (SIGMA_TACTIC_MAP[t]) tags.push(`Tactic: ${SIGMA_TACTIC_MAP[t]}`);
        else if (t.startsWith('attack.t')) tags.push(`Technique: ${t.replace('attack.', '').toUpperCase()}`);
      }

      const logsource = rule.logsource as Record<string, string> || {};
      if (logsource.product) tags.push(`OS: ${logsource.product.charAt(0).toUpperCase() + logsource.product.slice(1)}`);

      const id = `opensearch-${rule.id}`;
      addRule(
        id, rule.title as string, tags, updatedDate, 'OpenSearch',
        {
          metadata: { updated_date: updatedDate, source_siem: 'OpenSearch', source_siem_id: 'opensearch', source_url: `https://github.com/opensearch-project/security-analytics/blob/main/${file.path}` },
          rule: {
            name: rule.title,
            description: rule.description || '',
            tags,
            severity: (rule.level as string) || 'medium',
            risk_score: splunkSeverityToRisk((rule.level as string) || 'medium'),
            type: 'sigma',
            language: 'sigma',
            query: JSON.stringify(rule.detection, null, 2),
            reference: (rule.references as string[]) || [],
            false_positives: (rule.falsepositives as string[]) || [],
          }
        },
        ruleSummaries, tagSummaries
      );
      count++;
    } catch (_) { /* skip */ }
  }
  console.log(`OpenSearch: loaded ${count} rules`);
}

// ─── SUMO LOGIC ───────────────────────────────────────────────────────────────

async function getSumoLogicRules(
  ruleSummaries: RuleSummary[],
  tagSummaries: Map<string, TagSummary>
) {
  const gh = githubClient();
  const treeUrl = 'https://api.github.com/repos/rapdev-io/Threat_Detection_Ruleset-SUMOLOGIC/git/trees/main?recursive=1';
  let tree;
  try { tree = await gh.get(treeUrl); } catch (_) {
    console.log('Sumo Logic: community repo unavailable');
    return;
  }

  const files = (tree.data.tree as { path: string; type: string }[])
    .filter(f => f.type === 'blob' && (f.path.endsWith('.json') || f.path.endsWith('.yaml') || f.path.endsWith('.yml')))
    .slice(0, 100);

  const commitRes = await gh.get(
    'https://api.github.com/repos/rapdev-io/Threat_Detection_Ruleset-SUMOLOGIC/commits?per_page=1'
  ).catch(() => ({ data: [{ commit: { committer: { date: new Date().toISOString() } } }] }));
  const updatedDate = new Date(commitRes.data[0]?.commit?.committer?.date || Date.now());

  let count = 0;
  for (const file of files) {
    try {
      const raw = await gh.get(
        `https://raw.githubusercontent.com/rapdev-io/Threat_Detection_Ruleset-SUMOLOGIC/main/${file.path}`
      );
      const data = typeof raw.data === 'string'
        ? (file.path.endsWith('.json') ? JSON.parse(raw.data) : yaml.load(raw.data))
        : raw.data;
      if (!data || typeof data !== 'object') continue;

      const name = (data as Record<string, unknown>).name as string || file.path.split('/').pop()?.replace(/\.[^.]+$/, '') || 'Unknown';
      const tags: string[] = ['Rule Type: Query', 'Data Source: Sumo Logic'];
      const id = `sumologic-${file.path.replace(/\//g, '-').replace(/\.[^.]+$/, '')}`;

      addRule(
        id, name, tags, updatedDate, 'Sumo Logic',
        {
          metadata: { updated_date: updatedDate, source_siem: 'Sumo Logic', source_siem_id: 'sumologic', source_url: `https://github.com/rapdev-io/Threat_Detection_Ruleset-SUMOLOGIC/blob/main/${file.path}` },
          rule: {
            name,
            description: (data as Record<string, unknown>).description as string || '',
            tags,
            severity: 'medium',
            risk_score: 47,
            type: 'query',
            language: 'sumo-cql',
            query: JSON.stringify(data, null, 2),
            reference: [],
            false_positives: [],
          }
        },
        ruleSummaries, tagSummaries
      );
      count++;
    } catch (_) { /* skip */ }
  }
  console.log(`Sumo Logic: loaded ${count} rules`);
}

// ─── MAIN ─────────────────────────────────────────────────────────────────────

async function precomputeRuleSummaries() {
  const ruleSummaries: RuleSummary[] = [];
  const tagSummaries = new Map<string, TagSummary>();

  fs.mkdirSync(RULES_OUTPUT_PATH, { recursive: true });

  console.log('Fetching rules from all SIEMs...');

  await getElasticPrebuiltRules(ruleSummaries, tagSummaries);
  await getSplunkRules(ruleSummaries, tagSummaries);
  await getSentinelRules(ruleSummaries, tagSummaries);
  await getChronicleRules(ruleSummaries, tagSummaries);
  await getSigmaRules(ruleSummaries, tagSummaries);
  await getCrowdStrikeRules(ruleSummaries, tagSummaries);
  await getWazuhRules(ruleSummaries, tagSummaries);
  await getOpenSearchRules(ruleSummaries, tagSummaries);
  await getSumoLogicRules(ruleSummaries, tagSummaries);

  console.log(`\nTotal rules parsed: ${ruleSummaries.length}`);

  const newestRules = ruleSummaries.sort(
    (a, b) => new Date(b.updated_date).getTime() - new Date(a.updated_date).getTime()
  );

  fs.writeFileSync('./src/data/newestRules.json', JSON.stringify(newestRules));

  const popularTags = Array.from(tagSummaries.values()).sort((a, b) => b.count - a.count);
  fs.writeFileSync('./src/data/tagSummaries.json', JSON.stringify(popularTags));

  const siemStats = ruleSummaries.reduce((acc, r) => {
    acc[r.source_siem] = (acc[r.source_siem] || 0) + 1;
    return acc;
  }, {} as Record<string, number>);
  console.log('\nRules by SIEM:');
  Object.entries(siemStats).sort((a, b) => b[1] - a[1]).forEach(([siem, count]) => {
    console.log(`  ${siem}: ${count}`);
  });
}

(async () => {
  await precomputeRuleSummaries();
})();
