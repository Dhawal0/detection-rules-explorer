/* eslint-disable @typescript-eslint/no-var-requires */
const crypto = require('crypto');
const fs = require('fs');
const glob = require('glob');
const path = require('path');
const iniparser = require('iniparser');

const withBundleAnalyzer = require('@next/bundle-analyzer');
const CopyWebpackPlugin = require('copy-webpack-plugin');
const { IgnorePlugin } = require('webpack');

const usePathPrefix = process.env.PATH_PREFIX === 'true';
const pathPrefix = usePathPrefix ? derivePathPrefix() : '';
const themeConfig = buildThemeConfig();

const nextConfig = {
  compiler: { emotion: true },
  poweredByHeader: false,
  basePath: pathPrefix,
  images: { loader: 'custom' },
  env: {
    PATH_PREFIX: pathPrefix,
    THEME_CONFIG: JSON.stringify(themeConfig),
  },
  webpack(config, { isServer }) {
    if (isServer) {
      config.externals = config.externals.map(eachExternal => {
        if (typeof eachExternal !== 'function') return eachExternal;
        return (context, callback) => {
          if (context.request.indexOf('@elastic/eui') > -1) return callback();
          return eachExternal(context, callback);
        };
      });
      const definePluginId = config.plugins.findIndex(p => p.constructor.name === 'DefinePlugin');
      config.plugins[definePluginId].definitions = {
        ...config.plugins[definePluginId].definitions,
        HTMLElement: function () {},
      };
    }
    if (Array.isArray(themeConfig.copyConfig) && themeConfig.copyConfig.length > 0) {
      config.plugins.push(new CopyWebpackPlugin({ patterns: themeConfig.copyConfig }));
    }
    config.plugins.push(
      new IgnorePlugin({ resourceRegExp: /^\.\/locale$/, contextRegExp: /moment$/ })
    );
    config.resolve.mainFields = ['module', 'main'];
    return config;
  },
};

module.exports = withBundleAnalyzer({ enabled: process.env.ANALYZE === 'true' })(nextConfig);

function buildThemeConfig() {
  const themeFiles = glob.sync(
    path.join(__dirname, 'node_modules', '@elastic', 'eui', 'dist', 'eui_theme_*.min.css')
  );
  const themeConfig = { availableThemes: [], copyConfig: [] };
  for (const each of themeFiles) {
    const basename = path.basename(each, '.min.css');
    const themeId = basename.replace(/^eui_theme_/, '');
    const themeName = themeId[0].toUpperCase() + themeId.slice(1).replace(/_/g, ' ');
    const publicPath = `themes/${basename}.${hashFile(each)}.min.css`;
    const toPath = path.join(__dirname, 'public', 'themes', `${basename}.${hashFile(each)}.min.css`);
    themeConfig.availableThemes.push({ id: themeId, name: themeName, publicPath });
    themeConfig.copyConfig.push({ from: each, to: toPath });
  }
  return themeConfig;
}

function hashFile(filePath) {
  const hash = crypto.createHash('sha256');
  const fileData = fs.readFileSync(filePath);
  hash.update(fileData);
  return hash.digest('hex').substr(0, 20);
}

function derivePathPrefix() {
  const gitConfigPath = path.join(__dirname, '.git', 'config');
  if (fs.existsSync(gitConfigPath)) {
    const gitConfig = iniparser.parseSync(gitConfigPath);
    if (gitConfig['remote "origin"'] != null) {
      const originUrl = gitConfig['remote "origin"'].url;
      return '/' + originUrl.split('/').pop().replace(/\.git$/, '');
    }
  }
  const packageJsonPath = path.join(__dirname, 'package.json');
  if (fs.existsSync(packageJsonPath)) {
    const { name } = require(packageJsonPath);
    return '/' + name.split('/').pop();
  }
  throw new Error("Can't derive path prefix");
}
