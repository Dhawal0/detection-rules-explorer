import { css } from '@emotion/react';

export const homeHeroStyles = (euiTheme: any) => ({
  container: css`
    max-width: 1100px;
    margin: auto !important;
    text-align: center;
  `,
  title: css`
    padding-top: ${euiTheme.size.base};
  `,
  description: css`
    max-width: 800px;
    margin: auto;
  `,
  siemRow: css`
    display: flex;
    flex-wrap: wrap;
    gap: 8px;
    justify-content: center;
    max-width: 900px;
    margin: auto;
  `,
  siemBadge: css`
    cursor: pointer;
    font-size: 0.8em;
  `,
  search: css`
    width: 500px;
    margin: auto;
  `,
  grid: css`
    justify-content: center;
    justify-items: center;
  `,
});
