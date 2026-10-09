import React, { useEffect, useState } from 'react';
import { api } from '../services/api';
import { Zap, Plus, Trash2, X } from 'lucide-react';

export const VirtualPatches: React.FC = () => {
  const [patches, setPatches] = useState<any[]>([]);
  const [loading, setLoading] = useState(true);

  const [isAddOpen, setIsAddOpen] = useState(false);
  const [newPatch, setNewPatch] = useState({
    patchId: 'PATCH-2026-001',
    name: 'Emergency Hotfix for Zero-Day Route',
    appId: '*',
    pathPattern: '/api/v1/orders/*',
    method: 'POST',
    targetField: 'BODY',
    pattern: '(?i)(__proto__|constructor\\.prototype)',
    action: 'BLOCK',
    enabled: true,
  });

  const fetchPatches = () => {
    setLoading(true);
    api.getVirtualPatches()
      .then(setPatches)
      .catch(console.error)
      .finally(() => setLoading(false));
  };

  useEffect(() => {
    fetchPatches();
  }, []);

  const handleDelete = async (id: string) => {
    if (!confirm('Remove this virtual patch policy?')) return;
    try {
      await api.deleteVirtualPatch(id);
      fetchPatches();
    } catch (err: any) {
      alert(err.message || 'Delete failed');
    }
  };

  const handleAddSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    try {
      await api.createVirtualPatch(newPatch);
      setIsAddOpen(false);
      fetchPatches();
    } catch (err: any) {
      alert(err.message || 'Failed to create virtual patch');
    }
  };

  return (
    <div className="p-6 space-y-6">
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4">
        <div>
          <h1 className="text-xl font-bold text-slate-100 uppercase tracking-tight flex items-center gap-2">
            <Zap className="w-5 h-5 text-amber-400" />
            Route-Specific Virtual Patching Policies
          </h1>
          <p className="text-xs text-slate-400">Instant Perimeter Security Patches Applied Without Modifying Upstream Code</p>
        </div>

        <button
          onClick={() => setIsAddOpen(true)}
          className="px-4 py-2 rounded-lg bg-amber-950 text-amber-400 border border-amber-800 text-xs font-semibold flex items-center gap-2 hover:bg-amber-900/60"
        >
          <Plus className="w-4 h-4" /> Deploy Virtual Patch
        </button>
      </div>

      <div className="bg-dark-800 border border-dark-700 rounded-lg overflow-hidden">
        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs font-mono">
            <thead className="bg-dark-900 text-slate-400 uppercase border-b border-dark-700">
              <tr>
                <th className="p-3">Patch ID</th>
                <th className="p-3">Name</th>
                <th className="p-3">Path Pattern</th>
                <th className="p-3">Method</th>
                <th className="p-3">Target Field</th>
                <th className="p-3">Pattern Signature</th>
                <th className="p-3 text-right">Actions</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-dark-700/50">
              {patches.length > 0 ? (
                patches.map((patch) => (
                  <tr key={patch.id} className="hover:bg-dark-700/30">
                    <td className="p-3 font-bold text-amber-400">{patch.patchId}</td>
                    <td className="p-3 font-semibold text-slate-200 font-sans">{patch.name}</td>
                    <td className="p-3 text-cyan-400">{patch.pathPattern}</td>
                    <td className="p-3 text-slate-300">{patch.method}</td>
                    <td className="p-3 text-slate-400">{patch.targetField}</td>
                    <td className="p-3 text-red-300 max-w-[200px] truncate">{patch.pattern}</td>
                    <td className="p-3 text-right">
                      <button
                        onClick={() => handleDelete(patch.id)}
                        className="p-1 rounded text-slate-400 hover:text-red-400 transition-colors"
                      >
                        <Trash2 className="w-4 h-4" />
                      </button>
                    </td>
                  </tr>
                ))
              ) : (
                <tr>
                  <td colSpan={7} className="p-8 text-center text-slate-500 font-mono">
                    No active virtual patching policies deployed.
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
                Deploy Virtual Patch
              </h3>
              <button onClick={() => setIsAddOpen(false)} className="text-slate-400 hover:text-white">
                <X className="w-5 h-5" />
              </button>
            </div>

            <form onSubmit={handleAddSubmit} className="space-y-3 text-xs font-mono">
              <div>
                <label className="block text-slate-400 mb-1">Patch ID</label>
                <input
                  type="text"
                  required
                  value={newPatch.patchId}
                  onChange={(e) => setNewPatch({ ...newPatch, patchId: e.target.value })}
                  className="w-full bg-dark-900 border border-dark-700 rounded p-2 text-amber-400 font-bold"
                />
              </div>

              <div>
                <label className="block text-slate-400 mb-1">Patch Name</label>
                <input
                  type="text"
                  required
                  value={newPatch.name}
                  onChange={(e) => setNewPatch({ ...newPatch, name: e.target.value })}
                  className="w-full bg-dark-900 border border-dark-700 rounded p-2 text-slate-200 font-sans"
                />
              </div>

              <div>
                <label className="block text-slate-400 mb-1">Target Route Path Pattern</label>
                <input
                  type="text"
                  required
                  value={newPatch.pathPattern}
                  onChange={(e) => setNewPatch({ ...newPatch, pathPattern: e.target.value })}
                  className="w-full bg-dark-900 border border-dark-700 rounded p-2 text-cyan-400"
                />
              </div>

              <div>
                <label className="block text-slate-400 mb-1">Regex Pattern Signature</label>
                <input
                  type="text"
                  required
                  value={newPatch.pattern}
                  onChange={(e) => setNewPatch({ ...newPatch, pattern: e.target.value })}
                  className="w-full bg-dark-900 border border-dark-700 rounded p-2 text-red-300"
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
                  className="px-4 py-1.5 rounded bg-amber-950 text-amber-400 border border-amber-800 font-bold hover:bg-amber-900"
                >
                  Deploy Patch
                </button>
              </div>
            </form>
          </div>
        </div>
      )}
    </div>
  );
};
