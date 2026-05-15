import { InferGetStaticPropsType, GetStaticProps, GetStaticPaths } from 'next';
import Head from 'next/head';
import {
  EuiSpacer,
  EuiText,
  EuiDescriptionList,
  EuiFlexGroup,
  EuiFlexItem,
  EuiTitle,
  EuiBadge,
  EuiPanel,
  EuiCodeBlock,
  EuiLink,
  EuiHealth,
  EuiCallOut,
} from '@elastic/eui';
import { useEuiTheme } from '@elastic/eui';
import moment from 'moment';
import * as fs from 'fs';
import * as path from 'path';

import Wrapper from '../../components/home/wrapper';
import { ruleDetailsStyles } from '../../components/details/rule_details.styles';
import { ruleFilterTypeMap, siemColorMap, siemIconMap } from '../../lib/ruledata';

const RULES_OUTPUT_PATH = '../../../../src/data/rules/';

export const getStaticPaths: GetStaticPaths = async () => {
  const ids = fs.readdirSync(path.join(__dirname, RULES_OUTPUT_PATH));
  return {
    paths: ids.map(x => ({ params: { id: path.parse(x).name } })),
    fallback: false,
  };
};

export const getStaticProps: GetStaticProps<{ rule: any }> = ({ params }) => {
  const res = JSON.parse(
    fs.readFileSync(path.join(__dirname, `${RULES_OUTPUT_PATH}${params.id}.json`), 'utf8')
  );
  return { props: { rule: res } };
};

export default function RuleDetails({ rule }: InferGetStaticPropsType<typeof getStaticProps>) {
  const { euiTheme } = useEuiTheme();
  const styles = ruleDetailsStyles(euiTheme);

  const sourceSiem = rule.metadata?.source_siem || 'Unknown';
  const sourceUrl = rule.metadata?.source_url;
  const creationDate = rule.metadata?.creation_date && moment(rule.metadata.creation_date.replace(/\//g, '-'));
  const updatedDate = rule.metadata?.updated_date && moment(String(rule.metadata.updated_date).replace(/\//g, '-'));

  const severity = rule.rule?.severity || 'medium';
  const severityColor = severity === 'high' || severity === 'critical' ? 'danger' : severity === 'medium' ? 'warning' : 'subdued';

  const aboutItems = [
    {
      title: 'Platform',
      description: (
        <EuiBadge color={siemColorMap[sourceSiem] || 'hollow'} iconType={siemIconMap[sourceSiem]}>
          {sourceSiem}
        </EuiBadge>
      ),
    },
    {
      title: 'Tags',
      description: (
        <>
          {(rule.rule?.tags || [])
            .filter((t: string) => !t.startsWith('Resources') && !t.startsWith('SIEM:'))
            .map((t: string, i: number) => {
              const badgeTheme = ruleFilterTypeMap[t.split(': ')[0]] || { color: 'hollow', icon: '' };
              return (
                <EuiBadge iconType={badgeTheme.icon} color={badgeTheme.color} css={styles.badge} key={i}>
                  {t}
                </EuiBadge>
              );
            })}
        </>
      ),
    },
    rule.rule?.severity && {
      title: 'Severity',
      description: <EuiHealth color={severityColor}>{severity}</EuiHealth>,
    },
    rule.rule?.risk_score != null && {
      title: 'Risk Score',
      description: rule.rule.risk_score,
    },
    rule.rule?.reference?.length && {
      title: 'References',
      description: rule.rule.reference.map((x: string, i: number) => (
        <EuiLink key={i} target="_blank" href={x}>{x}</EuiLink>
      )),
    },
    rule.rule?.false_positives?.length && {
      title: 'False Positives',
      description: rule.rule.false_positives.join('; '),
    },
    sourceUrl && {
      title: 'Source',
      description: <EuiLink target="_blank" href={sourceUrl}>View on GitHub</EuiLink>,
    },
  ].filter(Boolean);

  const definitionItems = [
    rule.rule?.language && {
      title: 'Rule Language',
      description: (
        <EuiBadge color="hollow">{rule.rule.language.toUpperCase()}</EuiBadge>
      ),
    },
    rule.rule?.type && {
      title: 'Rule Type',
      description: rule.rule.type,
    },
    rule.rule?.index?.length && {
      title: 'Index Patterns',
      description: rule.rule.index.map((x: string, i: number) => (
        <EuiBadge key={i} color="hollow">{x}</EuiBadge>
      )),
    },
    { title: 'Query / Detection Logic', description: '' },
  ].filter(Boolean);

  return (
    <>
      <Head>
        <title>{rule.rule?.name} — Multi-SIEM Detection Rules Explorer</title>
      </Head>
      <Wrapper>
        <EuiFlexGroup gutterSize="l" css={styles.container}>
          <EuiFlexItem>
            <EuiPanel>
              <EuiBadge color={siemColorMap[sourceSiem] || 'hollow'} iconType={siemIconMap[sourceSiem]}>
                {sourceSiem}
              </EuiBadge>
              <EuiSpacer size="s" />
              <EuiTitle size="m"><h1>{rule.rule?.name}</h1></EuiTitle>
              <EuiSpacer size="s" />
              {updatedDate && (
                <EuiText color="subdued" size="s">
                  Last updated {updatedDate.fromNow()} on {updatedDate.format('YYYY-MM-DD')}
                </EuiText>
              )}
              {creationDate && (
                <EuiText color="subdued" size="s">
                  Created {creationDate.fromNow()} on {creationDate.format('YYYY-MM-DD')}
                </EuiText>
              )}
            </EuiPanel>
          </EuiFlexItem>
        </EuiFlexGroup>

        <EuiFlexGroup gutterSize="l" css={styles.container}>
          <EuiFlexItem>
            <EuiPanel>
              <EuiTitle size="m"><h1>About</h1></EuiTitle>
              <EuiSpacer size="l" />
              <EuiText>{rule.rule?.description}</EuiText>
              <EuiSpacer size="l" />
              <EuiDescriptionList type="column" listItems={aboutItems} css={styles.list} />
            </EuiPanel>
          </EuiFlexItem>

          <EuiFlexItem>
            <EuiPanel>
              <EuiTitle size="m"><h1>Definition</h1></EuiTitle>
              <EuiSpacer size="l" />
              <EuiDescriptionList type="column" listItems={definitionItems.filter(i => i.title !== 'Query / Detection Logic')} css={styles.list} />
              <EuiSpacer size="m" />
              {rule.rule?.query && (
                <EuiCodeBlock language={rule.rule?.language || 'text'} isCopyable overflowHeight={400}>
                  {rule.rule.query}
                </EuiCodeBlock>
              )}
            </EuiPanel>
          </EuiFlexItem>
        </EuiFlexGroup>

        {sourceUrl && (
          <EuiCallOut
            size="m"
            title={`View this rule on ${sourceSiem}`}
            iconType={siemIconMap[sourceSiem] || 'logoGithub'}
            css={styles.callout}>
            <EuiSpacer size="s" />
            <p>
              This rule was sourced from the official {sourceSiem} public repository.{' '}
              <EuiLink target="_blank" href={sourceUrl}>View the original rule on GitHub</EuiLink>.
            </p>
          </EuiCallOut>
        )}
      </Wrapper>
    </>
  );
}
