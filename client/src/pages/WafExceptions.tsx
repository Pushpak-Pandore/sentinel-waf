import React, { useEffect, useState } from 'react';
import { api } from '../services/api';
import { ShieldCheck, Plus, Trash2, X } from 'lucide-react';

export const WafExceptions: React.FC = () => {
  const [exceptions, setExceptions] = useState<any[]>([]);
  const [loading, setLoading] = useState(true);

  const [isAddOpen, setIsAddOpen] = useState(false);
  const [newExc, setNewExc] = useState({
    appId: '*',
    pathPattern: '/api/comments',
    method: 'POST',
    ruleId: 'R-XSS-002',
    justification: 'Rich HTML WYSIWYG editor input permitted on comments route',
    expiresInDays: 30,
  });

  const fetchExceptions = () => {
    setLoading(true);
    api.getExceptions()
      .then(setExceptions)
      .catch(console.error)
      .finally(() => setLoading(false));
  };

  useEffect(() => {
    fetchExceptions();
  }, []);

  const handleDelete = async (id: string) => {
    if (!confirm('Remove this false positive exception?')) return;
    try {
      await api.deleteException(id);
      fetchExceptions();
    } catch (err: any) {
      alert(err.message || 'Delete failed');
    }
  };

  const handleAddSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    try {
      await api.createException(newExc);
      setIsAddOpen(false);
      fetchExceptions();
    } catch (err: any) {
      alert(err.message || 'Failed to create exception');
    }
  };

  return (
    <div className="p-6 space-y-6">
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4">
        <div>
          <h1 className="text-xl font-bold text-slate-100 uppercase tracking-tight flex items-center gap-2">
            <ShieldCheck className="w-5 h-5 text-emerald-400" />
            False-Positive Exception Management
          </h1>
          <p className="text-xs text-slate-400">Scoped, Route & Rule Specific Bypass Exceptions with Expiration and Audit History</p>
        </div>

        <button
          onClick={() => setIsAddOpen(true)}
          className="px-4 py-2 rounded-lg bg-emerald-950 text-emerald-400 border border-emerald-800 text-xs font-semibold flex items-center gap-2 hover:bg-emerald-900/60"
        >
          <Plus className="w-4 h-4" /> Create Rule Exception
        </button>
      </div>

      <div className="bg-dark-800 border border-dark-700 rounded-lg overflow-hidden">
        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs font-mono">
            <thead className="bg-dark-900 text-slate-400 uppercase border-b border-dark-700">
              <tr>
                <th className="p-3">Rule ID</th>
                <th className="p-3">Target Path</th>
                <th className="p-3">Method</th>
                <th className="p-3">App ID</th>
                <th className="p-3">Justification</th>
                <th className="p-3">Expiration</th>
                <th className="p-3 text-right">Actions</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-dark-700/50">
              {exceptions.length > 0 ? (
                exceptions.map((exc) => (
                  <tr key={exc.id} className="hover:bg-dark-700/30">
                    <td className="p-3 font-bold text-amber-400">{exc.ruleId}</td>
                    <td className="p-3 text-cyan-400">{exc.pathPattern}</td>
                    <td className="p-3 text-slate-300">{exc.method}</td>
                    <td className="p-3 text-slate-400">{exc.appId}</td>
                    <td className="p-3 text-slate-200 font-sans">{exc.justification}</td>
                    <td className="p-3 text-slate-400">
                      {exc.expiresAt ? new Date(exc.expiresAt).toLocaleDateString() : 'Permanent'}
                    </td>
                    <td className="p-3 text-right">
                      <button
                        onClick={() => handleDelete(exc.id)}
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
                    No false positive exceptions configured.
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
                Create Scoped Rule Exception
              </h3>
              <button onClick={() => setIsAddOpen(false)} className="text-slate-400 hover:text-white">
                <X className="w-5 h-5" />
              </button>
            </div>

            <form onSubmit={handleAddSubmit} className="space-y-3 text-xs font-mono">
              <div>
                <label className="block text-slate-400 mb-1">Target Rule ID to Bypass</label>
                <input
                  type="text"
                  required
                  value={newExc.ruleId}
                  onChange={(e) => setNewExc({ ...newExc, ruleId: e.target.value })}
                  className="w-full bg-dark-900 border border-dark-700 rounded p-2 text-amber-400 font-bold"
                />
              </div>

              <div>
                <label className="block text-slate-400 mb-1">Target Path Pattern</label>
                <input
                  type="text"
                  required
                  value={newExc.pathPattern}
                  onChange={(e) => setNewExc({ ...newExc, pathPattern: e.target.value })}
                  className="w-full bg-dark-900 border border-dark-700 rounded p-2 text-cyan-400"
                />
              </div>

              <div>
                <label className="block text-slate-400 mb-1">HTTP Method</label>
                <input
                  type="text"
                  value={newExc.method}
                  onChange={(e) => setNewExc({ ...newExc, method: e.target.value })}
                  className="w-full bg-dark-900 border border-dark-700 rounded p-2 text-slate-200"
                />
              </div>

              <div>
                <label className="block text-slate-400 mb-1">Security Justification</label>
                <textarea
                  required
                  rows={2}
                  value={newExc.justification}
                  onChange={(e) => setNewExc({ ...newExc, justification: e.target.value })}
                  className="w-full bg-dark-900 border border-dark-700 rounded p-2 text-slate-200 font-sans"
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
                  className="px-4 py-1.5 rounded bg-emerald-950 text-emerald-400 border border-emerald-800 font-bold hover:bg-emerald-900"
                >
                  Save Exception
                </button>
              </div>
            </form>
          </div>
        </div>
      )}
    </div>
  );
};
