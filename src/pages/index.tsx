import { FunctionComponent, useState, useMemo } from 'react';
import Head from 'next/head';
import HomeHero from '../components/home/home_hero';
import Wrapper from '../components/home/wrapper';
import RuleList from '../components/home/rule_list';

import newestRules from '../data/newestRules.json';
import tagSummaries from '../data/tagSummaries.json';

import { TagSummary } from '../types';

const Index: FunctionComponent = () => {
  const [searchFilter, setSearchFilter] = useState('');
  const [tagFilter, setTagFilter] = useState<string[]>([]);
  const [siemFilter, setSiemFilter] = useState<string[]>([]);

  const rules = useMemo(() => {
    return newestRules.filter(r => {
      if (searchFilter && !r.name.toLowerCase().includes(searchFilter.toLowerCase())) return false;
      if (tagFilter.length > 0 && !tagFilter.every(t => r.tags.includes(t))) return false;
      if (siemFilter.length > 0 && !siemFilter.includes(r.source_siem)) return false;
      return true;
    });
  }, [searchFilter, tagFilter, siemFilter]);

  const filteredTagSummaries = useMemo(() => {
    const tagSummariesMap = new Map<string, TagSummary>();
    for (const t of tagSummaries) {
      tagSummariesMap.set(t.tag_full, { ...t, count: 0 });
    }
    for (const r of rules) {
      for (const t of r.tags) {
        const parts = t.split(': ');
        const s = tagSummariesMap.get(t);
        if (parts.length !== 2 || s == undefined) continue;
        s.count++;
        tagSummariesMap.set(t, s);
      }
    }
    return Array.from(tagSummariesMap.values());
  }, [rules]);

  const updateTagFilter = (type: string, selected: string[]) => {
    setTagFilter(tagFilter.filter(x => !x.startsWith(type + ':')).concat(selected));
  };

  return (
    <>
      <Head>
        <title>Multi-SIEM Detection Rules Explorer</title>
      </Head>
      <Wrapper>
        <HomeHero
          rules={rules}
          tagSummaries={filteredTagSummaries}
          searchFilter={searchFilter}
          tagFilter={tagFilter}
          siemFilter={siemFilter}
          onSearchChange={setSearchFilter}
          onTagChange={updateTagFilter}
          onSiemChange={setSiemFilter}
        />
        <RuleList rules={rules} />
      </Wrapper>
    </>
  );
};

export default Index;
