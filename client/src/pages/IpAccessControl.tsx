import React, { useEffect, useState } from 'react';
import { IpAccessRule } from '../types';
import { api } from '../services/api';
import { Network, Plus, Trash2, CheckCircle, XCircle, Search, X } from 'lucide-react';

export const IpAccessControl: React.FC = () => {
  const [rules, setRules] = useState<IpAccessRule[]>([]);
  const [loading, setLoading] = useState(true);
  
  // Add IP Modal
  const [isAddOpen, setIsAddOpen] = useState(false);
  const [newRule, setNewRule] = useState({
    ipOrCidr: '198.51.100.0/24',
    type: 'BLOCK' as 'ALLOW' | 'BLOCK',
    description: 'Malicious threat subnet',
    reason: 'Automated brute force attempts',
    expiresInDays: 30,
  });

  // CIDR Tester Tool
  const [testIp, setTestIp] = useState('198.51.100.45');
  const [testCidr, setTestCidr] = useState('198.51.100.0/24');
  const [cidrResult, setCidrResult] = useState<any>(null);

  const fetchIpRules = () => {
    setLoading(true);
    api.getIpRules()
      .then(setRules)
      .catch(console.error)
      .finally(() => setLoading(false));
  };

  useEffect(() => {
    fetchIpRules();
  }, []);

  const handleDelete = async (id: string) => {
    if (!confirm('Are you sure you want to remove this IP access rule?')) return;
    try {
      await api.deleteIpRule(id);
      fetchIpRules();
    } catch (err: any) {
      alert(err.message || 'Delete failed');
    }
  };

  const handleAddSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    try {
      await api.createIpRule(newRule);
      setIsAddOpen(false);
      fetchIpRules();
    } catch (err: any) {
      alert(err.message || 'Failed to add IP rule');
    }
  };

  const handleTestCidr = async () => {
    try {
      const res = await api.checkCidr({ testIp, rulePattern: testCidr });
      setCidrResult(res);
    } catch (err: any) {
      alert(err.message || 'CIDR check failed');
    }
  };

  return (
    <div className="p-6 space-y-6">
      {/* Title & Actions */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4">
        <div>
          <h1 className="text-xl font-bold text-slate-100 uppercase tracking-tight flex items-center gap-2">
            <Network className="w-5 h-5 text-cyan-400" />
            IP Whitelisting & Blacklisting Control
          </h1>
          <p className="text-xs text-slate-400">Manage IPv4, IPv6, and CIDR Subnet Access Rules with Strict Precedence</p>
        </div>

        <button
          onClick={() => setIsAddOpen(true)}
          className="px-4 py-2 rounded-lg bg-cyan-950 text-cyan-400 border border-cyan-800 text-xs font-semibold flex items-center gap-2 hover:bg-cyan-900/60"
        >
          <Plus className="w-4 h-4" /> Add IP / CIDR Entry
        </button>
      </div>

      {/* Interactive CIDR Tester Tool */}
      <div className="bg-dark-800 border border-dark-700 rounded-lg p-5 space-y-3">
        <h3 className="text-xs uppercase font-mono font-bold text-slate-300">CIDR Boundary & Subnet Tester</h3>
        <div className="grid grid-cols-1 md:grid-cols-3 gap-3 text-xs font-mono">
          <input
            type="text"
            placeholder="Target IP e.g. 192.168.1.50"
            value={testIp}
            onChange={(e) => setTestIp(e.target.value)}
            className="bg-dark-900 border border-dark-700 rounded p-2 text-slate-200"
          />
          <input
            type="text"
            placeholder="CIDR Range e.g. 192.168.1.0/24"
            value={testCidr}
            onChange={(e) => setTestCidr(e.target.value)}
            className="bg-dark-900 border border-dark-700 rounded p-2 text-slate-200"
          />
          <button
            onClick={handleTestCidr}
            className="px-4 py-2 rounded bg-cyan-950 text-cyan-400 border border-cyan-800 font-bold hover:bg-cyan-900"
          >
            Check CIDR Match
          </button>
        </div>

        {cidrResult && (
          <div className={`p-3 rounded border text-xs font-mono ${
            cidrResult.isMatch ? 'bg-emerald-950/80 border-emerald-800 text-emerald-300' : 'bg-red-950/80 border-red-800 text-red-300'
          }`}>
            <p className="font-bold">{cidrResult.explanation}</p>
            <p className="text-[11px] text-slate-300 mt-1">
              Normalized: {cidrResult.normalizedIp} ({cidrResult.ipVersion})
            </p>
          </div>
        )}
      </div>

      {/* Rules Table */}
      <div className="bg-dark-800 border border-dark-700 rounded-lg overflow-hidden">
        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs font-mono">
            <thead className="bg-dark-900 text-slate-400 uppercase border-b border-dark-700">
              <tr>
                <th className="p-3">Policy Type</th>
                <th className="p-3">IP / CIDR Block</th>
                <th className="p-3">Version</th>
                <th className="p-3">Description</th>
                <th className="p-3">Reason</th>
                <th className="p-3">Expiration</th>
                <th className="p-3 text-right">Actions</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-dark-700/50">
              {rules.length > 0 ? (
                rules.map((rule) => (
                  <tr key={rule.id} className="hover:bg-dark-700/30">
                    <td className="p-3">
                      <span className={`px-2.5 py-0.5 rounded text-[10px] font-bold border uppercase ${
                        rule.type === 'ALLOW'
                          ? 'bg-emerald-950 text-emerald-400 border-emerald-800'
                          : 'bg-red-950 text-red-400 border-red-800'
                      }`}>
                        {rule.type}
                      </span>
                    </td>
                    <td className="p-3 font-bold text-cyan-400">{rule.ipOrCidr}</td>
                    <td className="p-3 text-slate-400">{rule.ipVersion}</td>
                    <td className="p-3 text-slate-200 font-sans">{rule.description || 'N/A'}</td>
                    <td className="p-3 text-slate-400 font-sans">{rule.reason || 'N/A'}</td>
                    <td className="p-3 text-slate-400">
                      {rule.expiresAt ? new Date(rule.expiresAt).toLocaleDateString() : 'Permanent'}
                    </td>
                    <td className="p-3 text-right">
                      <button
                        onClick={() => handleDelete(rule.id)}
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
                    No IP access control entries configured.
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      </div>

      {/* Add IP Modal */}
      {isAddOpen && (
        <div className="fixed inset-0 bg-black/70 backdrop-blur-sm z-50 flex items-center justify-center p-4">
          <div className="bg-dark-800 border border-dark-700 rounded-lg max-w-md w-full p-6 space-y-4 shadow-2xl">
            <div className="flex items-center justify-between border-b border-dark-700 pb-3">
              <h3 className="text-sm font-bold text-slate-100 uppercase tracking-tight font-mono">
                Add IP / CIDR Policy Entry
              </h3>
              <button onClick={() => setIsAddOpen(false)} className="text-slate-400 hover:text-white">
                <X className="w-5 h-5" />
              </button>
            </div>

            <form onSubmit={handleAddSubmit} className="space-y-3 text-xs font-mono">
              <div>
                <label className="block text-slate-400 mb-1">Target IP or CIDR Subnet</label>
                <input
                  type="text"
                  required
                  placeholder="e.g. 192.168.1.100 or 10.0.0.0/8"
                  value={newRule.ipOrCidr}
                  onChange={(e) => setNewRule({ ...newRule, ipOrCidr: e.target.value })}
                  className="w-full bg-dark-900 border border-dark-700 rounded p-2 text-cyan-400 font-bold"
                />
              </div>

              <div>
                <label className="block text-slate-400 mb-1">Policy Type</label>
                <select
                  value={newRule.type}
                  onChange={(e) => setNewRule({ ...newRule, type: e.target.value as 'ALLOW' | 'BLOCK' })}
                  className="w-full bg-dark-900 border border-dark-700 rounded p-2 text-slate-200"
                >
                  <option value="BLOCK">BLOCK (Blacklist)</option>
                  <option value="ALLOW">ALLOW (Whitelist)</option>
                </select>
              </div>

              <div>
                <label className="block text-slate-400 mb-1">Description</label>
                <input
                  type="text"
                  value={newRule.description}
                  onChange={(e) => setNewRule({ ...newRule, description: e.target.value })}
                  className="w-full bg-dark-900 border border-dark-700 rounded p-2 text-slate-200 font-sans"
                />
              </div>

              <div>
                <label className="block text-slate-400 mb-1">Reason</label>
                <input
                  type="text"
                  value={newRule.reason}
                  onChange={(e) => setNewRule({ ...newRule, reason: e.target.value })}
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
                  className="px-4 py-1.5 rounded bg-cyan-950 text-cyan-400 border border-cyan-800 font-bold hover:bg-cyan-900"
                >
                  Save Entry
                </button>
              </div>
            </form>
          </div>
        </div>
      )}
    </div>
  );
};
