import React, { useEffect, useState } from 'react';
import { SystemHealth as SystemHealthType } from '../types';
import { api } from '../services/api';
import { HeartPulse, CheckCircle2, AlertTriangle, RefreshCw } from 'lucide-react';

export const SystemHealth: React.FC = () => {
  const [health, setHealth] = useState<SystemHealthType | null>(null);
  const [loading, setLoading] = useState(true);

  const fetchHealth = () => {
    setLoading(true);
    api.getHealth()
      .then(setHealth)
      .catch(console.error)
      .finally(() => setLoading(false));
  };

  useEffect(() => {
    fetchHealth();
  }, []);

  return (
    <div className="p-6 space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-xl font-bold text-slate-100 uppercase tracking-tight flex items-center gap-2">
            <HeartPulse className="w-5 h-5 text-emerald-400" />
            System Health & Infrastructure Diagnostics
          </h1>
          <p className="text-xs text-slate-400">WAF Engine Liveness, Database Connection Metrics, and Resource Consumption</p>
        </div>

        <button
          onClick={fetchHealth}
          className="px-3 py-1.5 rounded-lg bg-dark-800 border border-dark-700 text-xs text-slate-300 hover:text-white flex items-center gap-2"
        >
          <RefreshCw className={`w-3.5 h-3.5 ${loading ? 'animate-spin' : ''}`} />
          Run Health Diagnostics
        </button>
      </div>

      {health && (
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
          <div className="bg-dark-800 border border-dark-700 rounded-lg p-5 space-y-3">
            <span className="text-[10px] font-mono text-slate-500 uppercase font-bold">WAF ENGINE CORE</span>
            <div className="flex items-center justify-between">
              <span className="text-lg font-bold text-slate-100 font-mono">{health.wafEngineStatus}</span>
              <CheckCircle2 className="w-6 h-6 text-emerald-400" />
            </div>
            <p className="text-xs text-slate-400">Node runtime: {health.nodeVersion}</p>
            <p className="text-xs text-slate-400">System Uptime: {Math.floor(health.uptimeSeconds / 60)} minutes</p>
          </div>

          <div className="bg-dark-800 border border-dark-700 rounded-lg p-5 space-y-3">
            <span className="text-[10px] font-mono text-slate-500 uppercase font-bold">DATABASE PERSISTENCE</span>
            <div className="flex items-center justify-between">
              <span className="text-lg font-bold text-slate-100 font-mono">{health.databaseStatus}</span>
              <CheckCircle2 className="w-6 h-6 text-emerald-400" />
            </div>
            <p className="text-xs text-slate-400">Query Latency: {health.databaseLatencyMs} ms</p>
            <p className="text-xs text-slate-400">Prisma ORM SQLite / PostgreSQL</p>
          </div>

          <div className="bg-dark-800 border border-dark-700 rounded-lg p-5 space-y-3">
            <span className="text-[10px] font-mono text-slate-500 uppercase font-bold">UPSTREAM REVERSE PROXY</span>
            <div className="flex items-center justify-between">
              <span className="text-lg font-bold text-slate-100 font-mono">{health.upstreamHealth}</span>
              <CheckCircle2 className="w-6 h-6 text-emerald-400" />
            </div>
            <p className="text-xs text-slate-400">Registered Targets: {health.protectedAppsCount} Apps</p>
          </div>

          <div className="bg-dark-800 border border-dark-700 rounded-lg p-5 col-span-full space-y-3">
            <h3 className="text-xs uppercase font-mono font-bold text-slate-300">Process Memory Usage (Node.js)</h3>
            <div className="grid grid-cols-3 gap-4 text-xs font-mono">
              <div className="p-3 rounded bg-dark-900 border border-dark-700">
                <span className="text-slate-500 text-[10px] uppercase block">RSS Memory</span>
                <span className="text-cyan-400 font-bold text-base">{health.memoryUsageMB.rss} MB</span>
              </div>
              <div className="p-3 rounded bg-dark-900 border border-dark-700">
                <span className="text-slate-500 text-[10px] uppercase block">Heap Total</span>
                <span className="text-slate-200 font-bold text-base">{health.memoryUsageMB.heapTotal} MB</span>
              </div>
              <div className="p-3 rounded bg-dark-900 border border-dark-700">
                <span className="text-slate-500 text-[10px] uppercase block">Heap Used</span>
                <span className="text-emerald-400 font-bold text-base">{health.memoryUsageMB.heapUsed} MB</span>
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
