import React, { ReactElement } from 'react';
import Document, { Head, Html, Main, NextScript } from 'next/document';
import { defaultTheme, Theme, themeConfig } from '../lib/theme';

const pathPrefix = process.env.PATH_PREFIX;

function themeLink(theme: Theme): ReactElement {
  let disabledProps = {};
  if (theme.id !== defaultTheme) {
    disabledProps = { disabled: true, 'aria-disabled': true };
  }
  return (
    <link
      rel="stylesheet"
      href={`${pathPrefix}/${theme.publicPath}`}
      data-name="eui-theme"
      data-theme-name={theme.name}
      data-theme={theme.id}
      key={theme.id}
      {...disabledProps}
    />
  );
}

export default class MyDocument extends Document {
  render(): ReactElement {
    return (
      <Html lang="en">
        <Head>
          <meta name="description" content="A unified explorer for detection rules across Elastic, Splunk, Microsoft Sentinel, Google Chronicle, Sigma, Palo Alto Cortex, Wazuh, OpenSearch, and Sumo Logic." />
          <meta property="og:title" content="Multi-SIEM Detection Rules Explorer" />
          <meta property="og:description" content="Browse 5000+ detection rules across all major security platforms." />
          <meta property="og:url" content="https://dhawalshah.cv/detection-rules-explorer" />
          <meta name="eui-styles" />
          <meta name="eui-styles-utility" />
          {themeConfig.availableThemes.map(each => themeLink(each))}
        </Head>
        <body className="guideBody">
          <Main />
          <NextScript />
        </body>
      </Html>
    );
  }
}
