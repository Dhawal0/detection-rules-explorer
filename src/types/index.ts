export interface TagSummary {
  tag_type: string;
  tag_name: string;
  tag_full: string;
  count: number;
}

export interface RuleSummary {
  id: string;
  name: string;
  tags: string[];
  updated_date: string;
  source_siem: string;
}
