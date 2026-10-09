import React, { useEffect, useState } from 'react';
import { api } from '../services/api';
import { Send, Plus, Trash2, TestTube, X, CheckCircle2 } from 'lucide-react';

export const SiemConfig: React.FC = () => {
  const [webhooks, setWebhooks] = useState<any[]>([]);
  const [loading, setLoading] = useState(true);

  const [isAddOpen, setIsAddOpen] = useState(false);
  const [newHook, setNewHook] = useState({
    name: 'Splunk Enterprise SIEM Webhook',
    url: 'http://localhost:5000/api/v1/siem/mock-receiver',
    secret: 'siem-secret-key-999',
    enabled: true,
    minSeverity: 'MEDIUM',
  });

  const [testResult, setTestResult] = useState<any>(null);

  const fetchWebhooks = () => {
    setLoading(true);
    api.getSiemWebhooks()
      .then(setWebhooks)
      .catch(console.error)
      .finally(() => setLoading(false));
  };

  useEffect(() => {
    fetchWebhooks();
  }, []);

  const handleDelete = async (id: string) => {
    if (!confirm('Delete this SIEM webhook configuration?')) return;
    try {
      await api.deleteSiemWebhook(id);
      fetchWebhooks();
    } catch (err: any) {
      alert(err.message || 'Delete failed');
    }
  };

  const handleTest = async (id: string) => {
    setTestResult(null);
    try {
      const res = await api.testSiemWebhook(id);
      setTestResult(res);
      fetchWebhooks();
    } catch (err: any) {
      alert(err.message || 'SIEM test failed');
    }
  };

  const handleAddSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    try {
      await api.createSiemWebhook(newHook);
      setIsAddOpen(false);
      fetchWebhooks();
    } catch (err: any) {
      alert(err.message || 'Failed to create webhook');
    }
  };

  return (
    <div className="p-6 space-y-6">
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4">
        <div>
          <h1 className="text-xl font-bold text-slate-100 uppercase tracking-tight flex items-center gap-2">
            <Send className="w-5 h-5 text-blue-400" />
            SIEM Log Forwarding & Webhook Destinations
          </h1>
          <p className="text-xs text-slate-400">Stream Security Events to External Enterprise SIEM Platforms (Splunk, Datadog, Elastic)</p>
        </div>

        <button
          onClick={() => setIsAddOpen(true)}
          className="px-4 py-2 rounded-lg bg-blue-950 text-blue-400 border border-blue-800 text-xs font-semibold flex items-center gap-2 hover:bg-blue-900/60"
        >
          <Plus className="w-4 h-4" /> Add SIEM Webhook
        </button>
      </div>

      {testResult && (
        <div className="p-4 rounded-lg bg-dark-800 border border-dark-700 space-y-2 text-xs font-mono">
          <div className="flex items-center gap-2 text-emerald-400 font-bold">
            <CheckCircle2 className="w-4 h-4" /> SIEM Test Event Dispatched
          </div>
          <p className="text-slate-300">{testResult.message}</p>
        </div>
      )}

      <div className="bg-dark-800 border border-dark-700 rounded-lg overflow-hidden">
        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs font-mono">
            <thead className="bg-dark-900 text-slate-400 uppercase border-b border-dark-700">
              <tr>
                <th className="p-3">Webhook Name</th>
                <th className="p-3">Target Endpoint URL</th>
                <th className="p-3">Min Severity</th>
                <th className="p-3">Successes</th>
                <th className="p-3">Failures</th>
                <th className="p-3 text-right">Actions</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-dark-700/50">
              {webhooks.length > 0 ? (
                webhooks.map((hook) => (
                  <tr key={hook.id} className="hover:bg-dark-700/30">
                    <td className="p-3 font-bold text-slate-200 font-sans">{hook.name}</td>
                    <td className="p-3 text-blue-400 truncate max-w-[250px]">{hook.url}</td>
                    <td className="p-3 text-slate-400">{hook.minSeverity}</td>
                    <td className="p-3 text-emerald-400 font-bold">{hook.successCount}</td>
                    <td className="p-3 text-red-400 font-bold">{hook.failureCount}</td>
                    <td className="p-3 text-right space-x-2">
                      <button
                        onClick={() => handleTest(hook.id)}
                        className="px-2 py-1 rounded bg-dark-700 hover:bg-dark-600 text-blue-400 font-semibold inline-flex items-center gap-1 text-[11px]"
                      >
                        <TestTube className="w-3 h-3" /> Test Delivery
                      </button>
                      <button
                        onClick={() => handleDelete(hook.id)}
                        className="p-1 rounded text-slate-400 hover:text-red-400 transition-colors"
                      >
                        <Trash2 className="w-4 h-4" />
                      </button>
                    </td>
                  </tr>
                ))
              ) : (
                <tr>
                  <td colSpan={6} className="p-8 text-center text-slate-500 font-mono">
                    No SIEM webhooks configured.
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
                Add SIEM Webhook Destination
              </h3>
              <button onClick={() => setIsAddOpen(false)} className="text-slate-400 hover:text-white">
                <X className="w-5 h-5" />
              </button>
            </div>

            <form onSubmit={handleAddSubmit} className="space-y-3 text-xs font-mono">
              <div>
                <label className="block text-slate-400 mb-1">Webhook Name</label>
                <input
                  type="text"
                  required
                  value={newHook.name}
                  onChange={(e) => setNewHook({ ...newHook, name: e.target.value })}
                  className="w-full bg-dark-900 border border-dark-700 rounded p-2 text-slate-200 font-sans"
                />
              </div>

              <div>
                <label className="block text-slate-400 mb-1">SIEM Endpoint URL</label>
                <input
                  type="url"
                  required
                  value={newHook.url}
                  onChange={(e) => setNewHook({ ...newHook, url: e.target.value })}
                  className="w-full bg-dark-900 border border-dark-700 rounded p-2 text-blue-400"
                />
              </div>

              <div>
                <label className="block text-slate-400 mb-1">Secret Signature Key</label>
                <input
                  type="text"
                  value={newHook.secret}
                  onChange={(e) => setNewHook({ ...newHook, secret: e.target.value })}
                  className="w-full bg-dark-900 border border-dark-700 rounded p-2 text-slate-200"
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
                  className="px-4 py-1.5 rounded bg-blue-950 text-blue-400 border border-blue-800 font-bold hover:bg-blue-900"
                >
                  Add Destination
                </button>
              </div>
            </form>
          </div>
        </div>
      )}
    </div>
  );
};
