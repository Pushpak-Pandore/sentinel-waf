import React from 'react';
import { NavLink } from 'react-router-dom';
import {
  LayoutDashboard,
  Radio,
  ShieldAlert,
  BarChart3,
  Sliders,
  Network,
  Gauge,
  AppWindow,
  Terminal,
  FileCheck,
  HeartPulse,
  Settings as SettingsIcon,
  ShieldCheck,
  Zap,
  Send,
} from 'lucide-react';

const NAV_ITEMS = [
  { path: '/', label: 'Overview', icon: LayoutDashboard },
  { path: '/traffic', label: 'Live Traffic', icon: Radio },
  { path: '/events', label: 'Security Events', icon: ShieldAlert },
  { path: '/analytics', label: 'Attack Analytics', icon: BarChart3 },
  { path: '/rules', label: 'WAF Rules', icon: Sliders },
  { path: '/exceptions', label: 'Rule Exceptions', icon: ShieldCheck },
  { path: '/virtual-patches', label: 'Virtual Patches', icon: Zap },
  { path: '/siem', label: 'SIEM Webhooks', icon: Send },
  { path: '/ip-access', label: 'IP Access Control', icon: Network },
  { path: '/rate-limiting', label: 'Rate Limiting', icon: Gauge },
  { path: '/apps', label: 'Protected Apps', icon: AppWindow },
  { path: '/inspector', label: 'Request Inspector', icon: Terminal },
  { path: '/audit', label: 'Audit Logs', icon: FileCheck },
  { path: '/health', label: 'System Health', icon: HeartPulse },
  { path: '/settings', label: 'Settings', icon: SettingsIcon },
];

export const Sidebar: React.FC = () => {
  return (
    <aside className="w-64 bg-dark-800 border-r border-dark-700 flex flex-col flex-shrink-0 min-h-[calc(100vh-4rem)]">
      <div className="p-4 uppercase text-[10px] font-mono font-bold text-slate-500 tracking-wider">
        Navigation Console
      </div>
      <nav className="flex-1 px-3 space-y-1">
        {NAV_ITEMS.map((item) => {
          const Icon = item.icon;
          return (
            <NavLink
              key={item.path}
              to={item.path}
              end={item.path === '/'}
              className={({ isActive }) =>
                `flex items-center space-x-3 px-3 py-2.5 rounded-lg text-xs font-medium transition-all ${
                  isActive
                    ? 'bg-cyan-950/80 text-cyan-400 border border-cyan-800/80 shadow-sm'
                    : 'text-slate-400 hover:text-slate-200 hover:bg-dark-700/50'
                }`
              }
            >
              <Icon className="w-4 h-4 flex-shrink-0" />
              <span>{item.label}</span>
            </NavLink>
          );
        })}
      </nav>

      {/* Footer System Status Banner */}
      <div className="p-4 border-t border-dark-700 bg-dark-900/60 m-3 rounded-lg border">
        <div className="flex items-center justify-between text-xs mb-1">
          <span className="text-slate-400">Engine Status</span>
          <span className="text-emerald-400 font-bold font-mono">ONLINE</span>
        </div>
        <div className="w-full bg-dark-700 h-1.5 rounded-full overflow-hidden">
          <div className="bg-emerald-500 h-full w-full animate-pulse"></div>
        </div>
      </div>
    </aside>
  );
};
