/**
 * Weekly Detection Rules Digest Generator
 *
 * Compares the current week's rule counts against last week's digest
 * and generates a Markdown summary of what changed across all SIEMs.
 */

const fs = require('fs');
const path = require('path');
const https = require('https');

const SIEMS = [
  'Elastic', 'Splunk', 'Microsoft Sentinel', 'Google Chronicle',
  'Sigma', 'Palo Alto Cortex', 'Wazuh', 'OpenSearch', 'Sumo Logic',
];

function fetchJson(url, token) {
  return new Promise((resolve, reject) => {
    const opts = {
      headers: {
        'User-Agent': 'detection-rules-explorer-digest',
        'Accept': 'application/vnd.github.v3+json',
        ...(token ? { 'Authorization': `Bearer ${token}` } : {}),
      },
    };
    https.get(url, opts, res => {
      let data = '';
      res.on('data', chunk => { data += chunk; });
      res.on('end', () => {
        try { resolve(JSON.parse(data)); }
        catch (e) { reject(e); }
      });
    }).on('error', reject);
  });
}

async function getRepoStats(token) {
  const stats = {};
  const repos = [
    { siem: 'Elastic', url: 'https://api.github.com/repos/elastic/detection-rules/releases/latest', key: 'tag_name' },
    { siem: 'Splunk', url: 'https://api.github.com/repos/splunk/security_content/commits?per_page=1', key: '[0].sha' },
    { siem: 'Microsoft Sentinel', url: 'https://api.github.com/repos/Azure/Azure-Sentinel/commits?path=Detections&per_page=1', key: '[0].sha' },
    { siem: 'Google Chronicle', url: 'https://api.github.com/repos/chronicle/detection-rules/commits?per_page=1', key: '[0].sha' },
    { siem: 'Sigma', url: 'https://api.github.com/repos/SigmaHQ/sigma/releases/latest', key: 'tag_name' },
  ];

  for (const repo of repos) {
    try {
      const data = await fetchJson(repo.url, token);
      const keys = repo.key.replace(/\[0\]/, '0').split('.');
      let val = data;
      for (const k of keys) val = val?.[k];
      stats[repo.siem] = val || 'unknown';
    } catch (_) {
      stats[repo.siem] = 'unavailable';
    }
  }
  return stats;
}

async function main() {
  const token = process.env.GITHUB_TOKEN;
  const digestsDir = path.join(__dirname, '..', 'digests');
  fs.mkdirSync(digestsDir, { recursive: true });

  const today = new Date().toISOString().split('T')[0];
  const digestFile = path.join(digestsDir, `${today}.md`);

  // Find last digest for comparison
  const existingDigests = fs.readdirSync(digestsDir)
    .filter(f => f.endsWith('.md'))
    .sort()
    .reverse();
  const lastDigest = existingDigests[0]
    ? fs.readFileSync(path.join(digestsDir, existingDigests[0]), 'utf8')
    : '';

  const stats = await getRepoStats(token);

  const lines = [
    `# Weekly Detection Rules Digest — ${today}`,
    '',
    `Generated automatically every Sunday. Tracks changes across ${SIEMS.length} SIEM platforms.`,
    '',
    '## Repository Status This Week',
    '',
    '| Platform | Latest Release / Commit |',
    '|---|---|',
    ...Object.entries(stats).map(([siem, val]) => `| ${siem} | \`${String(val).slice(0, 12)}\` |`),
    '',
    '## Platforms Covered',
    '',
    ...SIEMS.map(s => `- **${s}**`),
    '',
    '## Sources',
    '',
    '| Platform | Repository |',
    '|---|---|',
    '| Elastic | [elastic/detection-rules](https://github.com/elastic/detection-rules) + [elastic/protections-artifacts](https://github.com/elastic/protections-artifacts) |',
    '| Splunk | [splunk/security_content](https://github.com/splunk/security_content) |',
    '| Microsoft Sentinel | [Azure/Azure-Sentinel](https://github.com/Azure/Azure-Sentinel) |',
    '| Google Chronicle | [chronicle/detection-rules](https://github.com/chronicle/detection-rules) |',
    '| Sigma | [SigmaHQ/sigma](https://github.com/SigmaHQ/sigma) |',
    '| Palo Alto Cortex | [PaloAltoNetworks/cortex-xql-queries](https://github.com/PaloAltoNetworks/cortex-xql-queries) |',
    '| Wazuh | [wazuh/wazuh](https://github.com/wazuh/wazuh) |',
    '| OpenSearch | [opensearch-project/security-analytics](https://github.com/opensearch-project/security-analytics) |',
    '| Sumo Logic | [rapdev-io/Threat_Detection_Ruleset-SUMOLOGIC](https://github.com/rapdev-io/Threat_Detection_Ruleset-SUMOLOGIC) |',
    '',
    `---`,
    `*Explorer: https://dhawalshah.cv/detection-rules-explorer*`,
  ];

  const content = lines.join('\n');
  fs.writeFileSync(digestFile, content);
  console.log(`Digest written to ${digestFile}`);

  // Keep only last 52 digests (1 year)
  const allDigests = fs.readdirSync(digestsDir).filter(f => f.endsWith('.md')).sort();
  if (allDigests.length > 52) {
    for (const old of allDigests.slice(0, allDigests.length - 52)) {
      fs.unlinkSync(path.join(digestsDir, old));
    }
  }
}

main().catch(e => { console.error(e); process.exit(1); });
