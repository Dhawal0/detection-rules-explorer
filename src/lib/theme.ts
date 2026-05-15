const selector = 'link[data-name="eui-theme"]';
export const defaultTheme = 'light';

function getAllThemes(): HTMLLinkElement[] {
  return [...document.querySelectorAll(selector)] as HTMLLinkElement[];
}

export function enableTheme(newThemeName: string): void {
  const oldThemeName = getTheme();
  localStorage.setItem('theme', newThemeName);
  for (const themeLink of getAllThemes()) {
    themeLink.disabled = themeLink.dataset.theme !== newThemeName;
    (themeLink as any)['aria-disabled'] = themeLink.dataset.theme !== newThemeName;
  }
  if (document.body.classList.contains(`appTheme-${oldThemeName}`)) {
    document.body.classList.replace(`appTheme-${oldThemeName}`, `appTheme-${newThemeName}`);
  } else {
    document.body.classList.add(`appTheme-${newThemeName}`);
  }
}

export function getTheme(): string {
  return localStorage.getItem('theme') || defaultTheme;
}

export interface Theme {
  id: string;
  name: string;
  publicPath: string;
}

export interface ThemeConfig {
  availableThemes: Array<Theme>;
  copyConfig: Array<{ from: string; to: string }>;
}

export const themeConfig: ThemeConfig = JSON.parse(process.env.THEME_CONFIG!);
