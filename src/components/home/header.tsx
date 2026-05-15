import Link from 'next/link';
import {
  EuiHeader,
  EuiTitle,
  EuiHeaderSectionItemButton,
  useEuiTheme,
  EuiToolTip,
  EuiIcon,
} from '@elastic/eui';
import ThemeSwitcher from './theme_switcher';
import { headerStyles } from './header.styles';

const Header = () => {
  const { euiTheme } = useEuiTheme();
  const href = 'https://github.com/Dhawal0/detection-rules-explorer';
  const styles = headerStyles(euiTheme);

  return (
    <EuiHeader
      position="fixed"
      sections={[
        {
          items: [
            <Link key="logo" href="/" passHref>
              <a css={styles.logo}>
                <EuiIcon type="securitySignal" size="l" />
                <EuiTitle size="xxs" css={styles.title}>
                  <span>Multi-SIEM Detection Rules Explorer</span>
                </EuiTitle>
              </a>
            </Link>,
          ],
        },
        {
          items: [
            <ThemeSwitcher key="theme-switcher" />,
            <EuiToolTip content="GitHub" key="github">
              <EuiHeaderSectionItemButton aria-label="GitHub" href={href}>
                <EuiIcon type="logoGithub" aria-hidden="true" />
              </EuiHeaderSectionItemButton>
            </EuiToolTip>,
          ],
        },
      ]}
    />
  );
};

export default Header;
