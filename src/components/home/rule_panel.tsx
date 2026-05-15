import { FunctionComponent, ReactNode } from 'react';
import { EuiBadge, EuiFlexItem, EuiPanel, EuiText, EuiSpacer, EuiLink } from '@elastic/eui';
import Link from 'next/link';
import LazyLoad from 'react-lazy-load';
import { rulePanelStyles } from './rule_panel.styles';
import moment from 'moment';
import { RuleSummary } from '../../types';
import { ruleFilterTypeMap, siemColorMap } from '../../lib/ruledata';

interface RulePanelProps {
  rule: RuleSummary;
  children?: ReactNode;
}

const RulePanel: FunctionComponent<RulePanelProps> = ({ rule }) => {
  const styles = rulePanelStyles();

  return (
    <EuiFlexItem css={styles.item}>
      <EuiPanel>
        <EuiBadge
          color={siemColorMap[rule.source_siem] || 'hollow'}
          css={styles.siemBadge}>
          {rule.source_siem}
        </EuiBadge>
        <EuiSpacer size="xs" />
        <EuiText>
          <Link href={`/rules/${rule.id}`} passHref>
            <EuiLink color="text" css={styles.link}>
              {rule.name}
            </EuiLink>
          </Link>
        </EuiText>
        <LazyLoad>
          <>
            <EuiSpacer size="xs" />
            {rule.tags
              .filter(t => !t.startsWith('SIEM:') && !t.startsWith('Resources'))
              .slice(0, 4)
              .map((t, i) => {
                const badgeTheme = ruleFilterTypeMap[t.split(': ')[0]] || { color: 'hollow', icon: '' };
                return (
                  <EuiBadge
                    iconType={badgeTheme.icon}
                    color={badgeTheme.color}
                    css={styles.badge}
                    key={i}>
                    {t}
                  </EuiBadge>
                );
              })}
            <EuiSpacer size="xs" />
            <EuiText size="xs">
              <p><em>Updated {moment(rule.updated_date).fromNow()}</em></p>
            </EuiText>
          </>
        </LazyLoad>
      </EuiPanel>
    </EuiFlexItem>
  );
};

export default RulePanel;
