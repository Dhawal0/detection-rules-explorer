import { FunctionComponent, useMemo, ReactNode } from 'react';
import { EuiFlexGrid, EuiCallOut } from '@elastic/eui';
import { ruleListStyles } from './rule_list.styles';
import { useEuiTheme } from '@elastic/eui';
import RulePanel from './rule_panel';
import { RuleSummary } from '../../types';

interface RuleListProps {
  rules: RuleSummary[];
  children?: ReactNode;
}

const MAX_RULES = 120;

const RuleList: FunctionComponent<RuleListProps> = ({ rules }) => {
  const { euiTheme } = useEuiTheme();
  const styles = ruleListStyles(euiTheme);
  const ruleSlice = useMemo(() => rules.slice(0, MAX_RULES), [rules]);

  return (
    <>
      <EuiFlexGrid columns={4} css={styles.grid}>
        {ruleSlice.map((r, i) => <RulePanel key={i} rule={r} />)}
      </EuiFlexGrid>
      <EuiCallOut
        size="s"
        title={`Showing up to ${MAX_RULES} of ${rules.length} rules matching your filters. Use the filters above to narrow down.`}
        iconType="filter"
        css={styles.callout}
      />
    </>
  );
};

export default RuleList;
