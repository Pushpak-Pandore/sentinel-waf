import React, { useEffect, useState } from 'react';
import { ProtectedApp } from '../types';
import { api } from '../services/api';
import { AppWindow, Plus, Activity, Trash2, CheckCircle2, AlertTriangle, XCircle, X } from 'lucide-react';

export const ProtectedApps: React.FC = () => {
  const [apps, setApps] = useState<ProtectedApp[]>([]);
  const [loading, setLoading] = useState(true);

  const [isAddOpen, setIsAddOpen] = useState(false);
  const [newApp, setNewApp] = useState({
    appId: 'app-web-store',
    name: 'E-Commerce Production Target',
    host: 'localhost',
    upstreamUrl: 'http://localhost:5001',
    enabled: true,
    wafMode: 'INHERIT' as 'INHERIT' | 'PREVENTION' | 'DETECTION' | 'DISABLED',
    requestLimit: 200,
  });

  const fetchApps = () => {
    setLoading(true);
    api.getApps()
      .then(setApps)
      .catch(console.error)
      .finally(() => setLoading(false));
  };

  useEffect(() => {
    fetchApps();
  }, []);

  const handleCheckHealth = async (id: string) => {
    try {
      await api.checkAppHealth(id);
      fetchApps();
    } catch (err: any) {
      alert(err.message || 'Health check failed');
    }
  };

  const handleDelete = async (id: string) => {
    if (!confirm('Unregister this protected application?')) return;
    try {
      await api.deleteApp(id);
      fetchApps();
    } catch (err: any) {
      alert(err.message || 'Delete failed');
    }
  };

  const handleAddSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    try {
      await api.createApp(newApp);
      setIsAddOpen(false);
      fetchApps();
    } catch (err: any) {
      alert(err.message || 'Failed to register app');
    }
  };

  return (
    <div className="p-6 space-y-6">
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4">
        <div>
          <h1 className="text-xl font-bold text-slate-100 uppercase tracking-tight flex items-center gap-2">
            <AppWindow className="w-5 h-5 text-cyan-400" />
            Protected Applications & Reverse Proxy Targets
          </h1>
          <p className="text-xs text-slate-400">Upstream Origin Targets, Host Domain Routing, and SSRF Perimeter Controls</p>
        </div>

        <button
          onClick={() => setIsAddOpen(true)}
          className="px-4 py-2 rounded-lg bg-cyan-950 text-cyan-400 border border-cyan-800 text-xs font-semibold flex items-center gap-2 hover:bg-cyan-900/60"
        >
          <Plus className="w-4 h-4" /> Register Target Application
        </button>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
        {apps.map((app) => (
          <div key={app.id} className="bg-dark-800 border border-dark-700 rounded-lg p-5 space-y-4 shadow-lg relative">
            <div className="flex items-start justify-between">
              <div>
                <span className="text-[10px] font-mono uppercase text-slate-500 font-bold">{app.appId}</span>
                <h3 className="text-base font-bold text-slate-100 font-sans">{app.name}</h3>
              </div>
              <span className={`px-2 py-0.5 rounded text-[10px] font-mono font-bold border ${
                app.healthStatus === 'HEALTHY'
                  ? 'bg-emerald-950 text-emerald-400 border-emerald-800'
                  : 'bg-red-950 text-red-400 border-red-800'
              }`}>
                {app.healthStatus}
              </span>
            </div>

            <div className="space-y-2 text-xs font-mono">
              <div className="p-2 rounded bg-dark-900 border border-dark-700">
                <span className="text-slate-500 block text-[10px]">HOST / DOMAIN</span>
                <span className="text-slate-200 font-bold">{app.host}</span>
              </div>
              <div className="p-2 rounded bg-dark-900 border border-dark-700">
                <span className="text-slate-500 block text-[10px]">UPSTREAM ORIGIN URL</span>
                <span className="text-cyan-400 font-bold truncate block">{app.upstreamUrl}</span>
              </div>
              <div className="flex justify-between p-2 rounded bg-dark-900">
                <span className="text-slate-500">WAF Mode:</span>
                <span className="text-amber-400 font-bold">{app.wafMode}</span>
              </div>
            </div>

            <div className="pt-2 flex items-center justify-between border-t border-dark-700">
              <button
                onClick={() => handleCheckHealth(app.id)}
                className="px-3 py-1 rounded bg-dark-700 hover:bg-dark-600 text-xs text-cyan-400 font-semibold flex items-center gap-1.5"
              >
                <Activity className="w-3.5 h-3.5" /> Check Upstream Health
              </button>
              <button
                onClick={() => handleDelete(app.id)}
                className="p-1.5 rounded text-slate-400 hover:text-red-400 transition-colors"
              >
                <Trash2 className="w-4 h-4" />
              </button>
            </div>
          </div>
        ))}
      </div>

      {isAddOpen && (
        <div className="fixed inset-0 bg-black/70 backdrop-blur-sm z-50 flex items-center justify-center p-4">
          <div className="bg-dark-800 border border-dark-700 rounded-lg max-w-md w-full p-6 space-y-4 shadow-2xl">
            <div className="flex items-center justify-between border-b border-dark-700 pb-3">
              <h3 className="text-sm font-bold text-slate-100 uppercase tracking-tight font-mono">
                Register Target Application
              </h3>
              <button onClick={() => setIsAddOpen(false)} className="text-slate-400 hover:text-white">
                <X className="w-5 h-5" />
              </button>
            </div>

            <form onSubmit={handleAddSubmit} className="space-y-3 text-xs font-mono">
              <div>
                <label className="block text-slate-400 mb-1">Application Identifier (App ID)</label>
                <input
                  type="text"
                  required
                  value={newApp.appId}
                  onChange={(e) => setNewApp({ ...newApp, appId: e.target.value })}
                  className="w-full bg-dark-900 border border-dark-700 rounded p-2 text-cyan-400 font-bold"
                />
              </div>

              <div>
                <label className="block text-slate-400 mb-1">Display Name</label>
                <input
                  type="text"
                  required
                  value={newApp.name}
                  onChange={(e) => setNewApp({ ...newApp, name: e.target.value })}
                  className="w-full bg-dark-900 border border-dark-700 rounded p-2 text-slate-200 font-sans"
                />
              </div>

              <div>
                <label className="block text-slate-400 mb-1">Upstream Origin Target URL</label>
                <input
                  type="text"
                  required
                  value={newApp.upstreamUrl}
                  onChange={(e) => setNewApp({ ...newApp, upstreamUrl: e.target.value })}
                  className="w-full bg-dark-900 border border-dark-700 rounded p-2 text-cyan-400"
                />
              </div>

              <div className="pt-3 flex justify-end space-x-3">
                <button
                  type="button"
                  onClick={() => setIsAddOpen(false)}
                  className="px-4 py-1.5 rounded bg-dark-700 text-slate-300 hover:bg-dark-600"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  className="px-4 py-1.5 rounded bg-cyan-950 text-cyan-400 border border-cyan-800 font-bold hover:bg-cyan-900"
                >
                  Register App
                </button>
              </div>
            </form>
          </div>
        </div>
      )}
    </div>
  );
};
