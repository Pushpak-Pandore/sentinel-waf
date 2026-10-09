import React, { useEffect, useState } from 'react';
import { WafRule, AttackCategory, ThreatSeverity, WafDecision } from '../types';
import { api } from '../services/api';
import { ThreatBadge } from '../components/ThreatBadge';
import { Sliders, Plus, ToggleLeft, ToggleRight, Trash2, TestTube, CheckCircle, XCircle, X } from 'lucide-react';

export const WafRules: React.FC = () => {
  const [rules, setRules] = useState<WafRule[]>([]);
  const [loading, setLoading] = useState(true);
  const [filterCategory, setFilterCategory] = useState('');
  
  // Create Rule Modal
  const [isCreateOpen, setIsCreateOpen] = useState(false);
  const [newRule, setNewRule] = useState({
    ruleId: 'R-CUSTOM-001',
    name: 'Custom WAF Protection Rule',
    description: 'Custom threat signature rule',
    category: 'SQLI' as AttackCategory,
    severity: 'HIGH' as ThreatSeverity,
    enabled: true,
    action: 'BLOCK' as WafDecision,
    matchType: 'REGEX',
    targetField: 'FULL_URL',
    pattern: '(?i)(select.*from|eval\\()',
  });

  // Test Rule Modal
  const [testModalRule, setTestModalRule] = useState<WafRule | null>(null);
  const [testPayload, setTestPayload] = useState("1' UNION SELECT username FROM users--");
  const [testResult, setTestResult] = useState<any>(null);

  const fetchRules = () => {
    setLoading(true);
    api.getRules(filterCategory)
      .then(setRules)
      .catch(console.error)
      .finally(() => setLoading(false));
  };

  useEffect(() => {
    fetchRules();
  }, [filterCategory]);

  const handleToggle = async (id: string) => {
    try {
      await api.toggleRule(id);
      fetchRules();
    } catch (err: any) {
      alert(err.message || 'Toggle failed');
    }
  };

  const handleDelete = async (id: string) => {
    if (!confirm('Are you sure you want to delete this rule?')) return;
    try {
      await api.deleteRule(id);
      fetchRules();
    } catch (err: any) {
      alert(err.message || 'Delete failed');
    }
  };

  const handleCreateSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    try {
      await api.createRule(newRule);
      setIsCreateOpen(false);
      fetchRules();
    } catch (err: any) {
      alert(err.message || 'Failed to create rule');
    }
  };

  const handleRunTest = async () => {
    if (!testModalRule) return;
    try {
      const res = await api.testRule({
        matchType: testModalRule.matchType,
        pattern: testModalRule.pattern,
        testInput: testPayload,
      });
      setTestResult(res);
    } catch (err: any) {
      alert(err.message || 'Test execution failed');
    }
  };

  return (
    <div className="p-6 space-y-6">
      {/* Title & Actions */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4">
        <div>
          <h1 className="text-xl font-bold text-slate-100 uppercase tracking-tight flex items-center gap-2">
            <Sliders className="w-5 h-5 text-cyan-400" />
            WAF Rule Management & Policy Engine
          </h1>
          <p className="text-xs text-slate-400">Manage Core Security Detection Signatures, Regex Patterns, and Actions</p>
        </div>

        <button
          onClick={() => setIsCreateOpen(true)}
          className="px-4 py-2 rounded-lg bg-cyan-950 text-cyan-400 border border-cyan-800 text-xs font-semibold flex items-center gap-2 hover:bg-cyan-900/60"
        >
          <Plus className="w-4 h-4" /> Create Custom Rule
        </button>
      </div>

      {/* Category Filter Bar */}
      <div className="bg-dark-800 p-4 rounded-lg border border-dark-700 flex items-center space-x-3">
        <span className="text-xs text-slate-400 font-mono">Category Filter:</span>
        <select
          value={filterCategory}
          onChange={(e) => setFilterCategory(e.target.value)}
          className="bg-dark-900 border border-dark-700 text-xs text-slate-300 rounded-lg px-3 py-1.5 focus:outline-none font-mono"
        >
          <option value="">All Categories</option>
          <option value="SQLI">SQL Injection</option>
          <option value="XSS">Cross-Site Scripting</option>
          <option value="CSRF">CSRF</option>
          <option value="LFI">Local File Inclusion</option>
          <option value="REMOTE_ACCESS">Unauthorized Admin Access</option>
          <option value="MALFORMED">Command Injection</option>
          <option value="BOT">Bot Heuristics</option>
        </select>
      </div>

      {/* Rules Table */}
      <div className="bg-dark-800 border border-dark-700 rounded-lg overflow-hidden">
        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs font-mono">
            <thead className="bg-dark-900 text-slate-400 uppercase border-b border-dark-700">
              <tr>
                <th className="p-3">Status</th>
                <th className="p-3">Rule ID</th>
                <th className="p-3">Name</th>
                <th className="p-3">Category</th>
                <th className="p-3">Severity</th>
                <th className="p-3">Action</th>
                <th className="p-3">Target Field</th>
                <th className="p-3">Pattern</th>
                <th className="p-3 text-right">Actions</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-dark-700/50">
              {rules.length > 0 ? (
                rules.map((rule) => (
                  <tr key={rule.id} className="hover:bg-dark-700/30">
                    <td className="p-3">
                      <button onClick={() => handleToggle(rule.id)} className="focus:outline-none">
                        {rule.enabled ? (
                          <ToggleRight className="w-6 h-6 text-emerald-400" />
                        ) : (
                          <ToggleLeft className="w-6 h-6 text-slate-600" />
                        )}
                      </button>
                    </td>
                    <td className="p-3 font-bold text-cyan-400">{rule.ruleId}</td>
                    <td className="p-3 text-slate-200 font-sans font-semibold">{rule.name}</td>
                    <td className="p-3"><ThreatBadge type="category" value={rule.category} /></td>
                    <td className="p-3"><ThreatBadge type="severity" value={rule.severity} /></td>
                    <td className="p-3"><ThreatBadge type="decision" value={rule.action} /></td>
                    <td className="p-3 text-slate-400">{rule.targetField}</td>
                    <td className="p-3 text-amber-300 max-w-[200px] truncate">{rule.pattern}</td>
                    <td className="p-3 text-right space-x-2">
                      <button
                        onClick={() => { setTestModalRule(rule); setTestResult(null); }}
                        className="px-2 py-1 rounded bg-dark-700 hover:bg-dark-600 text-cyan-400 font-semibold inline-flex items-center gap-1 text-[11px]"
                      >
                        <TestTube className="w-3 h-3" /> Test
                      </button>
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
                  <td colSpan={9} className="p-8 text-center text-slate-500 font-mono">
                    No WAF rules found.
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      </div>

      {/* Create Custom Rule Modal */}
      {isCreateOpen && (
        <div className="fixed inset-0 bg-black/70 backdrop-blur-sm z-50 flex items-center justify-center p-4">
          <div className="bg-dark-800 border border-dark-700 rounded-lg max-w-lg w-full p-6 space-y-4 shadow-2xl">
            <div className="flex items-center justify-between border-b border-dark-700 pb-3">
              <h3 className="text-sm font-bold text-slate-100 uppercase tracking-tight font-mono">
                Create WAF Security Rule
              </h3>
              <button onClick={() => setIsCreateOpen(false)} className="text-slate-400 hover:text-white">
                <X className="w-5 h-5" />
              </button>
            </div>

            <form onSubmit={handleCreateSubmit} className="space-y-3 text-xs font-mono">
              <div>
                <label className="block text-slate-400 mb-1">Rule ID</label>
                <input
                  type="text"
                  required
                  value={newRule.ruleId}
                  onChange={(e) => setNewRule({ ...newRule, ruleId: e.target.value })}
                  className="w-full bg-dark-900 border border-dark-700 rounded p-2 text-slate-200"
                />
              </div>

              <div>
                <label className="block text-slate-400 mb-1">Rule Name</label>
                <input
                  type="text"
                  required
                  value={newRule.name}
                  onChange={(e) => setNewRule({ ...newRule, name: e.target.value })}
                  className="w-full bg-dark-900 border border-dark-700 rounded p-2 text-slate-200 font-sans"
                />
              </div>

              <div className="grid grid-cols-2 gap-3">
                <div>
                  <label className="block text-slate-400 mb-1">Category</label>
                  <select
                    value={newRule.category}
                    onChange={(e) => setNewRule({ ...newRule, category: e.target.value as AttackCategory })}
                    className="w-full bg-dark-900 border border-dark-700 rounded p-2 text-slate-200"
                  >
                    <option value="SQLI">SQLI</option>
                    <option value="XSS">XSS</option>
                    <option value="CSRF">CSRF</option>
                    <option value="LFI">LFI</option>
                    <option value="REMOTE_ACCESS">REMOTE_ACCESS</option>
                    <option value="MALFORMED">MALFORMED</option>
                    <option value="BOT">BOT</option>
                  </select>
                </div>

                <div>
                  <label className="block text-slate-400 mb-1">Severity</label>
                  <select
                    value={newRule.severity}
                    onChange={(e) => setNewRule({ ...newRule, severity: e.target.value as ThreatSeverity })}
                    className="w-full bg-dark-900 border border-dark-700 rounded p-2 text-slate-200"
                  >
                    <option value="CRITICAL">CRITICAL</option>
                    <option value="HIGH">HIGH</option>
                    <option value="MEDIUM">MEDIUM</option>
                    <option value="LOW">LOW</option>
                  </select>
                </div>
              </div>

              <div className="grid grid-cols-2 gap-3">
                <div>
                  <label className="block text-slate-400 mb-1">Enforcement Action</label>
                  <select
                    value={newRule.action}
                    onChange={(e) => setNewRule({ ...newRule, action: e.target.value as WafDecision })}
                    className="w-full bg-dark-900 border border-dark-700 rounded p-2 text-slate-200"
                  >
                    <option value="BLOCK">BLOCK</option>
                    <option value="LOG">LOG</option>
                    <option value="ALLOW">ALLOW</option>
                  </select>
                </div>

                <div>
                  <label className="block text-slate-400 mb-1">Target Field</label>
                  <select
                    value={newRule.targetField}
                    onChange={(e) => setNewRule({ ...newRule, targetField: e.target.value as any })}
                    className="w-full bg-dark-900 border border-dark-700 rounded p-2 text-slate-200"
                  >
                    <option value="FULL_URL">FULL_URL</option>
                    <option value="PATH">PATH</option>
                    <option value="QUERY">QUERY</option>
                    <option value="BODY">BODY</option>
                    <option value="HEADER">HEADER</option>
                  </select>
                </div>
              </div>

              <div>
                <label className="block text-slate-400 mb-1">Regex Pattern Signature</label>
                <input
                  type="text"
                  required
                  value={newRule.pattern}
                  onChange={(e) => setNewRule({ ...newRule, pattern: e.target.value })}
                  className="w-full bg-dark-900 border border-dark-700 rounded p-2 text-amber-300"
                />
              </div>

              <div className="pt-3 flex justify-end space-x-3">
                <button
                  type="button"
                  onClick={() => setIsCreateOpen(false)}
                  className="px-4 py-1.5 rounded bg-dark-700 text-slate-300 hover:bg-dark-600"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  className="px-4 py-1.5 rounded bg-cyan-950 text-cyan-400 border border-cyan-800 font-bold hover:bg-cyan-900"
                >
                  Create Rule
                </button>
              </div>
            </form>
          </div>
        </div>
      )}

      {/* Test Rule Modal */}
      {testModalRule && (
        <div className="fixed inset-0 bg-black/70 backdrop-blur-sm z-50 flex items-center justify-center p-4">
          <div className="bg-dark-800 border border-dark-700 rounded-lg max-w-md w-full p-6 space-y-4 shadow-2xl">
            <div className="flex items-center justify-between border-b border-dark-700 pb-3">
              <h3 className="text-sm font-bold text-slate-100 uppercase tracking-tight font-mono">
                Test Signature ({testModalRule.ruleId})
              </h3>
              <button onClick={() => setTestModalRule(null)} className="text-slate-400 hover:text-white">
                <X className="w-5 h-5" />
              </button>
            </div>

            <div className="space-y-3 text-xs font-mono">
              <div className="p-2.5 rounded bg-dark-900 border border-dark-700">
                <p className="text-slate-500 text-[10px] uppercase">Pattern Signature</p>
                <p className="text-amber-300 font-bold">{testModalRule.pattern}</p>
              </div>

              <div>
                <label className="block text-slate-400 mb-1">Test Payload Input</label>
                <textarea
                  rows={3}
                  value={testPayload}
                  onChange={(e) => setTestPayload(e.target.value)}
                  className="w-full bg-dark-900 border border-dark-700 rounded p-2 text-slate-200"
                />
              </div>

              {testResult && (
                <div className={`p-3 rounded border flex items-start gap-2 ${
                  testResult.isMatch ? 'bg-red-950/80 border-red-800 text-red-300' : 'bg-emerald-950/80 border-emerald-800 text-emerald-300'
                }`}>
                  {testResult.isMatch ? <XCircle className="w-4 h-4 shrink-0 mt-0.5" /> : <CheckCircle className="w-4 h-4 shrink-0 mt-0.5" />}
                  <div>
                    <p className="font-bold">{testResult.isMatch ? 'MATCH DETECTED (TRIGGERED)' : 'NO MATCH'}</p>
                    <p className="text-[11px] text-slate-300 mt-1">{testResult.explanation}</p>
                  </div>
                </div>
              )}

              <div className="pt-2 flex justify-end space-x-3">
                <button
                  onClick={handleRunTest}
                  className="px-4 py-1.5 rounded bg-cyan-950 text-cyan-400 border border-cyan-800 font-bold hover:bg-cyan-900"
                >
                  Run Match Test
                </button>
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
