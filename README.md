# Multi-SIEM Detection Rules Explorer

A unified web explorer for detection rules across **9 major security platforms**, hosted at [dhawal0.github.io/detection-rules-explorer](https://dhawal0.github.io/detection-rules-explorer).

## Platforms Covered

| Platform | Source Repository | Rule Format |
|---|---|---|
| **Elastic** | [elastic/detection-rules](https://github.com/elastic/detection-rules) + [elastic/protections-artifacts](https://github.com/elastic/protections-artifacts) | KQL / EQL / TOML |
| **Splunk** | [splunk/security_content](https://github.com/splunk/security_content) | SPL / YAML |
| **Microsoft Sentinel** | [Azure/Azure-Sentinel](https://github.com/Azure/Azure-Sentinel) | KQL / JSON |
| **Google Chronicle** | [chronicle/detection-rules](https://github.com/chronicle/detection-rules) | YARA-L 2.0 |
| **Sigma** | [SigmaHQ/sigma](https://github.com/SigmaHQ/sigma) | Sigma / YAML |
| **Palo Alto Cortex** | [PaloAltoNetworks/cortex-xql-queries](https://github.com/PaloAltoNetworks/cortex-xql-queries) | XQL |
| **Wazuh** | [wazuh/wazuh](https://github.com/wazuh/wazuh) | XML |
| **OpenSearch** | [opensearch-project/security-analytics](https://github.com/opensearch-project/security-analytics) | Sigma / YAML |
| **Sumo Logic** | [rapdev-io/Threat_Detection_Ruleset-SUMOLOGIC](https://github.com/rapdev-io/Threat_Detection_Ruleset-SUMOLOGIC) | JSON |

## Automation

- **GitHub Action** (`gh-pages.yml`): Runs every **Sunday at 05:00 UTC** — fetches fresh rules from all source repos, builds the Next.js site, deploys to `gh-pages` branch.
- **Weekly Digest** (`weekly-digest.yml`): Runs every **Sunday at 06:30 UTC** — generates a Markdown digest in `/digests/` summarizing repo status.

## Tech Stack

- **Next.js** + **Elastic EUI** (same stack as [elastic/detection-rules-explorer](https://github.com/elastic/detection-rules-explorer))
- **TypeScript** throughout
- Static export to GitHub Pages

## Local Development

```bash
npm ci
# Set GITHUB_TOKEN for API auth during data fetch
export GITHUB_TOKEN=your_token_here
npm run prebuild   # fetches rules from all SIEMs
npm run dev        # start dev server
```

## Adding a New SIEM

1. Add a fetcher function in `parseRuleData.ts` (follow the pattern of existing fetchers)
2. Add color/icon mappings in `src/lib/ruledata.ts`
3. Add the SIEM name to `ALL_SIEMS` in `src/components/home/home_hero.tsx`
4. Submit a PR — the next Sunday's build will include the new source
