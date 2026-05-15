import { FunctionComponent, ReactNode } from 'react';
import { EuiProvider, EuiThemeColorMode } from '@elastic/eui';
import { useTheme } from '../theme';
import createCache from '@emotion/cache';

interface ChromeProps { children: ReactNode; }

const Chrome: FunctionComponent<ChromeProps> = ({ children }) => {
  const { colorMode } = useTheme();
  const defaultCache = createCache({
    key: 'eui',
    container: typeof document !== 'undefined'
      ? document.querySelector('meta[name="eui-styles"]') : null,
  });
  const utilityCache = createCache({
    key: 'util',
    container: typeof document !== 'undefined'
      ? document.querySelector('meta[name="eui-styles-utility"]') : null,
  });
  return (
    <EuiProvider
      colorMode={colorMode as EuiThemeColorMode}
      cache={{ default: defaultCache, utility: utilityCache }}>
      {children}
    </EuiProvider>
  );
};

export default Chrome;
