import { FunctionComponent, useState, useRef, ReactNode } from 'react';
import {
  EuiFlexGroup,
  EuiFlexItem,
  EuiTitle,
  EuiText,
  EuiSpacer,
  EuiLink,
  EuiPanel,
  EuiFlexGrid,
  EuiFieldSearch,
  EuiFormRow,
  EuiBadge,
} from '@elastic/eui';
import { homeHeroStyles } from './home_hero.styles';
import { useEuiTheme } from '@elastic/eui';

import RuleFilter from './rule_filter';
import SiemFilter from './siem_filter';

import { RuleSummary, TagSummary } from '../../types';
import { siemColorMap } from '../../lib/ruledata';

interface HomeHeroProps {
  rules: RuleSummary[];
  tagSummaries: TagSummary[];
  searchFilter: string;
  tagFilter: string[];
  siemFilter: string[];
  onSearchChange: (v: string) => void;
  onTagChange: (type: string, selected: string[]) => void;
  onSiemChange: (siems: string[]) => void;
  children?: ReactNode;
}

const ALL_SIEMS = [
  'Elastic',
  'Splunk',
  'Microsoft Sentinel',
  'Google Chronicle',
  'Sigma',
  'Palo Alto Cortex',
  'Wazuh',
  'OpenSearch',
  'Sumo Logic',
];

const HomeHero: FunctionComponent<HomeHeroProps> = ({
  rules,
  tagSummaries,
  tagFilter,
  siemFilter,
  onSearchChange,
  onTagChange,
  onSiemChange,
}) => {
  const { euiTheme } = useEuiTheme();
  const styles = homeHeroStyles(euiTheme);
  const [displaySearchTerm, setDisplaySearchTerm] = useState('');
  const searchUpdateTimeout = useRef(null);

  const onSearchBoxChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    setDisplaySearchTerm(e.target.value);
    if (searchUpdateTimeout.current) clearTimeout(searchUpdateTimeout.current);
    searchUpdateTimeout.current = setTimeout(() => onSearchChange(e.target.value), 100);
  };

  const toggleSiem = (siem: string) => {
    if (siemFilter.includes(siem)) {
      onSiemChange(siemFilter.filter(s => s !== siem));
    } else {
      onSiemChange([...siemFilter, siem]);
    }
  };

  return (
    <EuiFlexGroup alignItems="center" css={styles.container}>
      <EuiFlexItem>
        <EuiTitle size="l" css={styles.title}>
          <h1>Multi-SIEM Detection Rules Explorer</h1>
        </EuiTitle>

        <EuiSpacer size="m" />

        <EuiText css={styles.description}>
          <p>
            A unified explorer for detection rules across{' '}
            <strong>{ALL_SIEMS.length} major security platforms</strong> — Elastic, Splunk,
            Microsoft Sentinel, Google Chronicle, Sigma, Palo Alto Cortex, Wazuh, OpenSearch,
            and Sumo Logic. Rules are fetched weekly from their official public repositories and
            normalized for easy browsing.
          </p>
        </EuiText>

        <EuiSpacer size="l" />

        <EuiText size="s" css={styles.description}>
          <p><strong>Filter by Platform:</strong></p>
        </EuiText>
        <EuiSpacer size="s" />
        <div css={styles.siemRow}>
          {ALL_SIEMS.map(siem => {
            const active = siemFilter.length === 0 || siemFilter.includes(siem);
            const isFiltered = siemFilter.includes(siem);
            const siemCount = rules.filter(r => r.source_siem === siem).length;
            return (
              <EuiBadge
                key={siem}
                color={isFiltered ? siemColorMap[siem] || 'primary' : 'hollow'}
                onClick={() => toggleSiem(siem)}
                onClickAriaLabel={`Filter by ${siem}`}
                css={styles.siemBadge}>
                {siem} ({siemCount})
              </EuiBadge>
            );
          })}
        </div>

        <EuiSpacer size="l" />

        <EuiFormRow fullWidth css={styles.search}>
          <EuiPanel>
            <EuiFieldSearch
              placeholder={`Search ${rules.length} rules by name`}
              value={displaySearchTerm}
              onChange={e => onSearchBoxChange(e)}
              fullWidth
            />
          </EuiPanel>
        </EuiFormRow>

        <EuiSpacer size="m" />

        <EuiFlexGrid columns={3} css={styles.grid}>
          <RuleFilter
            displayName="Tactics"
            icon="bug"
            tagList={tagSummaries.filter(x => x.tag_type === 'Tactic')}
            tagFilter={tagFilter}
            onTagChange={onTagChange}
          />
          <RuleFilter
            displayName="Platforms / Data Sources"
            icon="database"
            tagList={tagSummaries.filter(x => x.tag_type === 'Data Source')}
            tagFilter={tagFilter}
            onTagChange={onTagChange}
          />
          <RuleFilter
            displayName="Rule Language"
            icon="layers"
            tagList={tagSummaries.filter(x => x.tag_type === 'Rule Type')}
            tagFilter={tagFilter}
            onTagChange={onTagChange}
          />
          <RuleFilter
            displayName="Domains"
            icon="globe"
            tagList={tagSummaries.filter(x => x.tag_type === 'Domain')}
            tagFilter={tagFilter}
            onTagChange={onTagChange}
          />
          <RuleFilter
            displayName="Operating Systems"
            icon="compute"
            tagList={tagSummaries.filter(x => x.tag_type === 'OS')}
            tagFilter={tagFilter}
            onTagChange={onTagChange}
          />
          <RuleFilter
            displayName="Techniques"
            icon="tag"
            tagList={tagSummaries.filter(x => x.tag_type === 'Technique').slice(0, 50)}
            tagFilter={tagFilter}
            onTagChange={onTagChange}
          />
        </EuiFlexGrid>
      </EuiFlexItem>
    </EuiFlexGroup>
  );
};

export default HomeHero;
