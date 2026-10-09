import React, { createContext, useContext, useState, useEffect } from 'react';
import { User } from '../types';
import { api } from '../services/api';

interface AuthContextType {
  user: User | null;
  loading: boolean;
  login: (token: string, user: User) => void;
  logout: () => void;
  wafMode: string;
  setWafMode: (mode: string) => void;
}

const AuthContext = createContext<AuthContextType | undefined>(undefined);

export const AuthProvider: React.FC<{ children: React.ReactNode }> = ({ children }) => {
  const [user, setUser] = useState<User | null>(null);
  const [loading, setLoading] = useState(true);
  const [wafMode, setWafModeState] = useState<string>('PREVENTION');

  useEffect(() => {
    const token = localStorage.getItem('sentinel_token');
    if (token) {
      api.getMe()
        .then((res) => {
          setUser(res.user);
          // Fetch initial WAF mode once authenticated
          api.getSettings()
            .then((settingsRes) => {
              if (settingsRes.settings && settingsRes.settings.WAF_MODE) {
                setWafModeState(settingsRes.settings.WAF_MODE);
              }
            })
            .catch(() => {});
        })
        .catch(() => {
          localStorage.removeItem('sentinel_token');
          setUser(null);
        })
        .finally(() => setLoading(false));
    } else {
      setLoading(false);
    }
  }, []);

  const login = (token: string, userData: User) => {
    localStorage.setItem('sentinel_token', token);
    setUser(userData);
  };

  const logout = () => {
    api.logout().catch(() => {});
    localStorage.removeItem('sentinel_token');
    setUser(null);
  };

  const setWafMode = async (mode: string) => {
    try {
      await api.updateSetting('WAF_MODE', mode);
      setWafModeState(mode);
    } catch (err: any) {
      alert(err.message || 'Failed to update WAF Mode');
    }
  };

  return (
    <AuthContext.Provider value={{ user, loading, login, logout, wafMode, setWafMode }}>
      {children}
    </AuthContext.Provider>
  );
};

export const useAuth = () => {
  const context = useContext(AuthContext);
  if (!context) throw new Error('useAuth must be used within AuthProvider');
  return context;
};
