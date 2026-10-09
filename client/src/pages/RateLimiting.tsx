import React, { useEffect, useState } from 'react';
import { RateLimitPolicy } from '../types';
import { api } from '../services/api';
import { Gauge, Plus, Trash2, X } from 'lucide-react';

export const RateLimiting: React.FC = () => {
  const [policies, setPolicies] = useState<RateLimitPolicy[]>([]);
  const [loading, setLoading] = useState(true);

  const [isAddOpen, setIsAddOpen] = useState(false);
  const [newPolicy, setNewPolicy] = useState({
    name: 'Login Rate Limit Policy',
    scope: 'ROUTE' as 'GLOBAL' | 'IP' | 'APP' | 'ROUTE',
    pathPattern: '/api/login',
    windowMs: 60000,
    maxRequests: 10,
    burstLimit: 3,
    action: 'RATE_LIMIT' as 'RATE_LIMIT' | 'BLOCK',
    enabled: true,
  });

  const fetchPolicies = () => {
    setLoading(true);
    api.getRateLimitPolicies()
      .then(setPolicies)
      .catch(console.error)
      .finally(() => setLoading(false));
  };

  useEffect(() => {
    fetchPolicies();
  }, []);

  const handleDelete = async (id: string) => {
    if (!confirm('Delete this rate limit policy?')) return;
    try {
      await api.deleteRateLimitPolicy(id);
      fetchPolicies();
    } catch (err: any) {
      alert(err.message || 'Delete failed');
    }
  };

  const handleAddSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    try {
      await api.createRateLimitPolicy(newPolicy);
      setIsAddOpen(false);
      fetchPolicies();
    } catch (err: any) {
      alert(err.message || 'Failed to create policy');
    }
  };

  return (
    <div className="p-6 space-y-6">
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4">
        <div>
          <h1 className="text-xl font-bold text-slate-100 uppercase tracking-tight flex items-center gap-2">
            <Gauge className="w-5 h-5 text-purple-400" />
            Rate Limiting & Flooding Controls
          </h1>
          <p className="text-xs text-slate-400">Sliding Window Application Layer Throttling & HTTP 429 Policies</p>
        </div>

        <button
          onClick={() => setIsAddOpen(true)}
          className="px-4 py-2 rounded-lg bg-purple-950 text-purple-400 border border-purple-800 text-xs font-semibold flex items-center gap-2 hover:bg-purple-900/60"
        >
          <Plus className="w-4 h-4" /> Add Rate Limit Policy
        </button>
      </div>

      <div className="bg-dark-800 border border-dark-700 rounded-lg overflow-hidden">
        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs font-mono">
            <thead className="bg-dark-900 text-slate-400 uppercase border-b border-dark-700">
              <tr>
                <th className="p-3">Policy Name</th>
                <th className="p-3">Scope</th>
                <th className="p-3">Path Pattern</th>
                <th className="p-3">Window (ms)</th>
                <th className="p-3">Max Requests</th>
                <th className="p-3">Burst Limit</th>
                <th className="p-3">Enforcement</th>
                <th className="p-3 text-right">Actions</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-dark-700/50">
              {policies.length > 0 ? (
                policies.map((policy) => (
                  <tr key={policy.id} className="hover:bg-dark-700/30">
                    <td className="p-3 font-bold text-slate-200 font-sans">{policy.name}</td>
                    <td className="p-3 text-purple-400 font-bold">{policy.scope}</td>
                    <td className="p-3 text-amber-300">{policy.pathPattern}</td>
                    <td className="p-3 text-slate-400">{policy.windowMs / 1000}s</td>
                    <td className="p-3 font-bold text-cyan-400">{policy.maxRequests} req</td>
                    <td className="p-3 text-slate-400">{policy.burstLimit}</td>
                    <td className="p-3">
                      <span className="px-2 py-0.5 rounded text-[10px] bg-purple-950 text-purple-400 border border-purple-800 font-bold">
                        {policy.action}
                      </span>
                    </td>
                    <td className="p-3 text-right">
                      <button
                        onClick={() => handleDelete(policy.id)}
                        className="p-1 rounded text-slate-400 hover:text-red-400 transition-colors"
                      >
                        <Trash2 className="w-4 h-4" />
                      </button>
                    </td>
                  </tr>
                ))
              ) : (
                <tr>
                  <td colSpan={8} className="p-8 text-center text-slate-500 font-mono">
                    No rate limiting policies defined.
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      </div>

      {isAddOpen && (
        <div className="fixed inset-0 bg-black/70 backdrop-blur-sm z-50 flex items-center justify-center p-4">
          <div className="bg-dark-800 border border-dark-700 rounded-lg max-w-md w-full p-6 space-y-4 shadow-2xl">
            <div className="flex items-center justify-between border-b border-dark-700 pb-3">
              <h3 className="text-sm font-bold text-slate-100 uppercase tracking-tight font-mono">
                Create Rate Limit Policy
              </h3>
              <button onClick={() => setIsAddOpen(false)} className="text-slate-400 hover:text-white">
                <X className="w-5 h-5" />
              </button>
            </div>

            <form onSubmit={handleAddSubmit} className="space-y-3 text-xs font-mono">
              <div>
                <label className="block text-slate-400 mb-1">Policy Name</label>
                <input
                  type="text"
                  required
                  value={newPolicy.name}
                  onChange={(e) => setNewPolicy({ ...newPolicy, name: e.target.value })}
                  className="w-full bg-dark-900 border border-dark-700 rounded p-2 text-slate-200 font-sans"
                />
              </div>

              <div className="grid grid-cols-2 gap-3">
                <div>
                  <label className="block text-slate-400 mb-1">Scope</label>
                  <select
                    value={newPolicy.scope}
                    onChange={(e) => setNewPolicy({ ...newPolicy, scope: e.target.value as any })}
                    className="w-full bg-dark-900 border border-dark-700 rounded p-2 text-slate-200"
                  >
                    <option value="GLOBAL">GLOBAL</option>
                    <option value="IP">PER IP</option>
                    <option value="APP">PER APP</option>
                    <option value="ROUTE">PER ROUTE</option>
                  </select>
                </div>

                <div>
                  <label className="block text-slate-400 mb-1">Path Pattern</label>
                  <input
                    type="text"
                    value={newPolicy.pathPattern}
                    onChange={(e) => setNewPolicy({ ...newPolicy, pathPattern: e.target.value })}
                    className="w-full bg-dark-900 border border-dark-700 rounded p-2 text-amber-300"
                  />
                </div>
              </div>

              <div className="grid grid-cols-2 gap-3">
                <div>
                  <label className="block text-slate-400 mb-1">Window (ms)</label>
                  <input
                    type="number"
                    value={newPolicy.windowMs}
                    onChange={(e) => setNewPolicy({ ...newPolicy, windowMs: Number(e.target.value) })}
                    className="w-full bg-dark-900 border border-dark-700 rounded p-2 text-slate-200"
                  />
                </div>

                <div>
                  <label className="block text-slate-400 mb-1">Max Requests</label>
                  <input
                    type="number"
                    value={newPolicy.maxRequests}
                    onChange={(e) => setNewPolicy({ ...newPolicy, maxRequests: Number(e.target.value) })}
                    className="w-full bg-dark-900 border border-dark-700 rounded p-2 text-cyan-400 font-bold"
                  />
                </div>
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
                  className="px-4 py-1.5 rounded bg-purple-950 text-purple-400 border border-purple-800 font-bold hover:bg-purple-900"
                >
                  Create Policy
                </button>
              </div>
            </form>
          </div>
        </div>
      )}
    </div>
  );
};
