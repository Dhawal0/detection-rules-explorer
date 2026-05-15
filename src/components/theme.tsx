import { FunctionComponent, createContext, useContext, useState, useEffect, ReactNode } from 'react';
import { getTheme, enableTheme } from '../lib/theme';

export const GlobalProvider = createContext<{
  colorMode?: string;
  setColorMode?: (_value: string) => void;
}>({});

interface ThemeProps { children: ReactNode; }

export const Theme: FunctionComponent<ThemeProps> = ({ children }) => {
  const [colorMode, setColorMode] = useState('light');
  useEffect(() => { setColorMode(getTheme()); }, []);
  useEffect(() => enableTheme(colorMode), [colorMode]);
  return (
    <GlobalProvider.Provider value={{ colorMode, setColorMode }}>
      {children}
    </GlobalProvider.Provider>
  );
};

export const useTheme = () => useContext(GlobalProvider);
