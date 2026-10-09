import React from 'react';
import { ShieldCheck, ShieldAlert, ShieldOff, User as UserIcon, LogOut, Activity } from 'lucide-react';
import { useAuth } from '../context/AuthContext';

export const Navbar: React.FC = () => {
  const { user, logout, wafMode, setWafMode } = useAuth();

  return (
    <header className="h-16 border-b border-dark-700 bg-dark-800/90 backdrop-blur sticky top-0 z-40 px-6 flex items-center justify-between">
      {/* Brand Logo & Wordmark */}
      <div className="flex items-center space-x-3">
        <div className="w-9 h-9 rounded-lg bg-cyan-950 border border-cyan-800 flex items-center justify-center text-cyan-400">
          <ShieldCheck className="w-5 h-5" />
        </div>
        <div>
          <span className="text-lg font-bold text-slate-100 tracking-tight flex items-center gap-2">
            SENTINEL <span className="text-xs px-2 py-0.5 rounded bg-cyan-950 text-cyan-400 border border-cyan-800 font-mono">WAF v1.0</span>
          </span>
          <p className="text-xs text-slate-400 font-mono">Enterprise Security Pipeline</p>
        </div>
      </div>

      {/* Global WAF Operating Mode Selector */}
      <div className="flex items-center space-x-6">
        <div className="flex items-center space-x-2 bg-dark-900/80 p-1.5 rounded-lg border border-dark-700">
          <span className="text-xs text-slate-400 font-mono px-2 uppercase tracking-wider">Mode:</span>
          
          <button
            onClick={() => setWafMode('PREVENTION')}
            className={`px-3 py-1 rounded text-xs font-semibold flex items-center gap-1.5 transition-all ${
              wafMode === 'PREVENTION'
                ? 'bg-red-950 text-red-400 border border-red-800 shadow-sm'
                : 'text-slate-400 hover:text-slate-200'
            }`}
          >
            <ShieldAlert className="w-3.5 h-3.5" />
            Prevention
          </button>

          <button
            onClick={() => setWafMode('DETECTION')}
            className={`px-3 py-1 rounded text-xs font-semibold flex items-center gap-1.5 transition-all ${
              wafMode === 'DETECTION'
                ? 'bg-amber-950 text-amber-400 border border-amber-800 shadow-sm'
                : 'text-slate-400 hover:text-slate-200'
            }`}
          >
            <Activity className="w-3.5 h-3.5" />
            Detection
          </button>

          <button
            onClick={() => setWafMode('DISABLED')}
            className={`px-3 py-1 rounded text-xs font-semibold flex items-center gap-1.5 transition-all ${
              wafMode === 'DISABLED'
                ? 'bg-slate-800 text-slate-300 border border-slate-600 shadow-sm'
                : 'text-slate-400 hover:text-slate-200'
            }`}
          >
            <ShieldOff className="w-3.5 h-3.5" />
            Disabled
          </button>
        </div>

        {/* User Info & Logout */}
        {user && (
          <div className="flex items-center space-x-3 border-l border-dark-700 pl-4">
            <div className="w-8 h-8 rounded-full bg-slate-800 border border-slate-700 flex items-center justify-center text-cyan-400 font-bold text-xs">
              {user.name.charAt(0)}
            </div>
            <div className="hidden md:block">
              <p className="text-xs font-semibold text-slate-200">{user.name}</p>
              <p className="text-[10px] text-slate-400 uppercase font-mono">{user.role}</p>
            </div>
            <button
              onClick={logout}
              title="Logout"
              className="p-1.5 rounded text-slate-400 hover:text-red-400 hover:bg-red-950/50 transition-colors"
            >
              <LogOut className="w-4 h-4" />
            </button>
          </div>
        )}
      </div>
    </header>
  );
};
