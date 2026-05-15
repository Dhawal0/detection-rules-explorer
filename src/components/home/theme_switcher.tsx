import { FunctionComponent } from 'react';
import { EuiHeaderSectionItemButton, EuiIcon, EuiToolTip } from '@elastic/eui';
import { useTheme } from '../theme';

const ThemeSwitcher: FunctionComponent = () => {
  const { colorMode, setColorMode } = useTheme();
  const isDarkTheme = colorMode === 'dark';
  return (
    <EuiToolTip content={`Switch to ${isDarkTheme ? 'light' : 'dark'} theme`} key="theme-switch">
      <EuiHeaderSectionItemButton
        aria-label="Change theme"
        onClick={() => setColorMode(isDarkTheme ? 'light' : 'dark')}>
        <EuiIcon type={isDarkTheme ? 'sun' : 'moon'} aria-hidden="true" />
      </EuiHeaderSectionItemButton>
    </EuiToolTip>
  );
};

export default ThemeSwitcher;
