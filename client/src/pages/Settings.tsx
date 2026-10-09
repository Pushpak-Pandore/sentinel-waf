import React, { useEffect, useState } from 'react';
import { useAuth } from '../context/AuthContext';
import { api } from '../services/api';
import { Settings as SettingsIcon, ShieldAlert, Activity, ShieldOff, Check } from 'lucide-react';

export const Settings: React.FC = () => {
  const { wafMode, setWafMode } = useAuth();
  const [securityHeaders, setSecurityHeaders] = useState('true');
  const [savedMsg, setSavedMsg] = useState(false);

  useEffect(() => {
    api.getSettings()
      .then((res) => {
        if (res.settings && res.settings.DEFAULT_SECURITY_HEADERS) {
          setSecurityHeaders(res.settings.DEFAULT_SECURITY_HEADERS);
        }
      })
      .catch(console.error);
  }, []);

  const handleModeChange = (mode: string) => {
    setWafMode(mode);
    setSavedMsg(true);
    setTimeout(() => setSavedMsg(false), 3000);
  };

  const handleHeaderToggle = async (val: string) => {
    try {
      await api.updateSetting('DEFAULT_SECURITY_HEADERS', val);
      setSecurityHeaders(val);
      setSavedMsg(true);
      setTimeout(() => setSavedMsg(false), 3000);
    } catch (err: any) {
      alert(err.message || 'Failed to update setting');
    }
  };

  return (
    <div className="p-6 space-y-6 max-w-4xl">
      <div>
        <h1 className="text-xl font-bold text-slate-100 uppercase tracking-tight flex items-center gap-2">
          <SettingsIcon className="w-5 h-5 text-cyan-400" />
          Global WAF System Configuration
        </h1>
        <p className="text-xs text-slate-400">Configure Enforcement Modes, Security Headers, and Perimeter Controls</p>
      </div>

      {savedMsg && (
        <div className="p-3 rounded bg-emerald-950/80 border border-emerald-800 text-emerald-300 text-xs font-mono flex items-center gap-2">
          <Check className="w-4 h-4" /> Configuration setting updated and persisted to database.
        </div>
      )}

      {/* Global WAF Operating Mode Card */}
      <div className="bg-dark-800 border border-dark-700 rounded-lg p-5 space-y-4 shadow-lg">
        <h3 className="text-xs uppercase font-mono font-bold text-slate-300">WAF Global Operating Mode</h3>
        
        <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
          <button
            onClick={() => handleModeChange('PREVENTION')}
            className={`p-4 rounded-lg border text-left space-y-2 transition-all ${
              wafMode === 'PREVENTION'
                ? 'bg-red-950/90 border-red-800 text-red-300 shadow-md ring-1 ring-red-500'
                : 'bg-dark-900 border-dark-700 text-slate-400 hover:text-slate-200'
            }`}
          >
            <div className="flex items-center space-x-2">
              <ShieldAlert className="w-5 h-5 text-red-400" />
              <span className="font-bold text-sm">PREVENTION MODE</span>
            </div>
            <p className="text-xs font-sans text-slate-300">
              Actively inspects and BLOCKS requests matching malicious signatures or blacklists.
            </p>
          </button>

          <button
            onClick={() => handleModeChange('DETECTION')}
            className={`p-4 rounded-lg border text-left space-y-2 transition-all ${
              wafMode === 'DETECTION'
                ? 'bg-amber-950/90 border-amber-800 text-amber-300 shadow-md ring-1 ring-amber-500'
                : 'bg-dark-900 border-dark-700 text-slate-400 hover:text-slate-200'
            }`}
          >
            <div className="flex items-center space-x-2">
              <Activity className="w-5 h-5 text-amber-400" />
              <span className="font-bold text-sm">DETECTION MODE</span>
            </div>
            <p className="text-xs font-sans text-slate-300">
              Inspects traffic and LOGS matching events without blocking requests.
            </p>
          </button>

          <button
            onClick={() => handleModeChange('DISABLED')}
            className={`p-4 rounded-lg border text-left space-y-2 transition-all ${
              wafMode === 'DISABLED'
                ? 'bg-slate-800 border-slate-600 text-slate-200 shadow-md ring-1 ring-slate-500'
                : 'bg-dark-900 border-dark-700 text-slate-400 hover:text-slate-200'
            }`}
          >
            <div className="flex items-center space-x-2">
              <ShieldOff className="w-5 h-5 text-slate-400" />
              <span className="font-bold text-sm">DISABLED MODE</span>
            </div>
            <p className="text-xs font-sans text-slate-300">
              Bypasses WAF signature inspection completely. Warning: perimeter defense inactive.
            </p>
          </button>
        </div>
      </div>

      {/* Security Headers Toggle */}
      <div className="bg-dark-800 border border-dark-700 rounded-lg p-5 space-y-3">
        <h3 className="text-xs uppercase font-mono font-bold text-slate-300">Security Response Headers</h3>
        <p className="text-xs text-slate-400">Inject protective HTTP headers e.g. X-Sentinel-WAF, X-Request-ID, HSTS, X-Frame-Options.</p>
        
        <div className="flex items-center space-x-4 pt-2 font-mono text-xs">
          <button
            onClick={() => handleHeaderToggle('true')}
            className={`px-4 py-2 rounded font-bold border ${
              securityHeaders === 'true'
                ? 'bg-cyan-950 text-cyan-400 border-cyan-800'
                : 'bg-dark-900 text-slate-500 border-dark-700'
            }`}
          >
            ENABLED (INJECT HEADERS)
          </button>
          <button
            onClick={() => handleHeaderToggle('false')}
            className={`px-4 py-2 rounded font-bold border ${
              securityHeaders === 'false'
                ? 'bg-slate-800 text-slate-200 border-slate-600'
                : 'bg-dark-900 text-slate-500 border-dark-700'
            }`}
          >
            DISABLED
          </button>
        </div>
      </div>
    </div>
  );
};
