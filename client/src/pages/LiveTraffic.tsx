import React, { useEffect, useState } from 'react';
import { TrafficLog } from '../types';
import { api } from '../services/api';
import { ThreatBadge } from '../components/ThreatBadge';
import { Download, Search, Radio, Pause, Play, RefreshCw, X } from 'lucide-react';

export const LiveTraffic: React.FC = () => {
  const [logs, setLogs] = useState<TrafficLog[]>([]);
  const [search, setSearch] = useState('');
  const [filterDecision, setFilterDecision] = useState('');
  const [isStreaming, setIsStreaming] = useState(true);
  const [selectedLog, setSelectedLog] = useState<TrafficLog | null>(null);

  const fetchTraffic = () => {
    let query = `limit=50`;
    if (search) query += `&search=${encodeURIComponent(search)}`;
    if (filterDecision) query += `&decision=${filterDecision}`;

    api.getTraffic(query)
      .then((res) => setLogs(res.logs))
      .catch(console.error);
  };

  useEffect(() => {
    fetchTraffic();
  }, [search, filterDecision]);

  useEffect(() => {
    if (!isStreaming) return;

    // Connect to Server-Sent Events (SSE) Live Feed
    const token = localStorage.getItem('sentinel_token');
    const eventSource = new EventSource(`/api/v1/traffic/stream?token=${token}`);

    eventSource.onmessage = (event) => {
      try {
        const payload = JSON.parse(event.data);
        if (payload.type === 'TRAFFIC_LOG') {
          setLogs((prev) => [payload.data, ...prev.slice(0, 49)]);
        }
      } catch (err) {
        console.error('Failed to parse SSE payload', err);
      }
    };

    return () => {
      eventSource.close();
    };
  }, [isStreaming]);

  const handleExportCsv = () => {
    window.open('/api/v1/traffic/export', '_blank');
  };

  return (
    <div className="p-6 space-y-6">
      {/* Page Title & Controls */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4">
        <div>
          <h1 className="text-xl font-bold text-slate-100 uppercase tracking-tight flex items-center gap-2">
            <Radio className={`w-5 h-5 ${isStreaming ? 'text-emerald-400 animate-pulse' : 'text-slate-500'}`} />
            Live Traffic Stream
          </h1>
          <p className="text-xs text-slate-400">Real-time HTTP & HTTPS Request Telemetry Stream</p>
        </div>

        <div className="flex items-center space-x-3">
          <button
            onClick={() => setIsStreaming(!isStreaming)}
            className={`px-3 py-1.5 rounded-lg border text-xs font-semibold flex items-center gap-2 transition-all ${
              isStreaming
                ? 'bg-emerald-950 text-emerald-400 border-emerald-800'
                : 'bg-dark-800 text-slate-400 border-dark-700 hover:text-slate-200'
            }`}
          >
            {isStreaming ? <Pause className="w-3.5 h-3.5" /> : <Play className="w-3.5 h-3.5" />}
            {isStreaming ? 'Live Stream Active' : 'Stream Paused'}
          </button>

          <button
            onClick={handleExportCsv}
            className="px-3 py-1.5 rounded-lg bg-cyan-950 text-cyan-400 border border-cyan-800 text-xs font-semibold flex items-center gap-2 hover:bg-cyan-900/60"
          >
            <Download className="w-3.5 h-3.5" />
            Export CSV
          </button>
        </div>
      </div>

      {/* Filter Toolbar */}
      <div className="flex flex-col md:flex-row items-center justify-between gap-4 bg-dark-800 p-4 rounded-lg border border-dark-700">
        <div className="relative w-full md:w-96">
          <Search className="w-4 h-4 text-slate-500 absolute left-3 top-2.5" />
          <input
            type="text"
            placeholder="Search IP, Path, Correlation ID..."
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            className="w-full bg-dark-900 border border-dark-700 rounded-lg pl-9 pr-4 py-1.5 text-xs text-slate-200 focus:outline-none focus:border-cyan-500 font-mono"
          />
        </div>

        <div className="flex items-center space-x-3 w-full md:w-auto">
          <select
            value={filterDecision}
            onChange={(e) => setFilterDecision(e.target.value)}
            className="bg-dark-900 border border-dark-700 text-xs text-slate-300 rounded-lg px-3 py-1.5 focus:outline-none focus:border-cyan-500 font-mono"
          >
            <option value="">All Decisions</option>
            <option value="ALLOW">ALLOW</option>
            <option value="BLOCK">BLOCK</option>
            <option value="LOG">LOG</option>
            <option value="RATE_LIMIT">RATE_LIMIT</option>
          </select>
        </div>
      </div>

      {/* Traffic Table */}
      <div className="bg-dark-800 border border-dark-700 rounded-lg overflow-hidden">
        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs font-mono">
            <thead className="bg-dark-900 text-slate-400 uppercase border-b border-dark-700">
              <tr>
                <th className="p-3">Timestamp</th>
                <th className="p-3">Correlation ID</th>
                <th className="p-3">Client IP</th>
                <th className="p-3">Method</th>
                <th className="p-3">Path</th>
                <th className="p-3">Status</th>
                <th className="p-3">Latency</th>
                <th className="p-3">Decision</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-dark-700/50">
              {logs.length > 0 ? (
                logs.map((log) => (
                  <tr
                    key={log.id}
                    onClick={() => setSelectedLog(log)}
                    className="hover:bg-dark-700/40 cursor-pointer transition-colors"
                  >
                    <td className="p-3 text-slate-400">{new Date(log.timestamp).toLocaleTimeString()}</td>
                    <td className="p-3 text-slate-400 truncate max-w-[120px]">{log.correlationId}</td>
                    <td className="p-3 text-cyan-400 font-semibold">{log.clientIp}</td>
                    <td className="p-3 font-bold">{log.method}</td>
                    <td className="p-3 text-slate-200 truncate max-w-[280px]">{log.path}</td>
                    <td className="p-3 font-bold">
                      <span className={log.statusCode >= 400 ? 'text-red-400' : 'text-emerald-400'}>
                        {log.statusCode}
                      </span>
                    </td>
                    <td className="p-3 text-slate-400">{log.durationMs.toFixed(1)} ms</td>
                    <td className="p-3"><ThreatBadge type="decision" value={log.decision} /></td>
                  </tr>
                ))
              ) : (
                <tr>
                  <td colSpan={8} className="p-8 text-center text-slate-500 font-mono">
                    No traffic records match the filter criteria.
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      </div>

      {/* Selected Log Drawer Modal */}
      {selectedLog && (
        <div className="fixed inset-0 bg-black/70 backdrop-blur-sm z-50 flex items-center justify-center p-4">
          <div className="bg-dark-800 border border-dark-700 rounded-lg max-w-xl w-full p-6 space-y-4 shadow-2xl">
            <div className="flex items-center justify-between border-b border-dark-700 pb-3">
              <h3 className="text-sm font-bold text-slate-100 uppercase tracking-tight font-mono">
                Request Details ({selectedLog.correlationId})
              </h3>
              <button onClick={() => setSelectedLog(null)} className="text-slate-400 hover:text-white">
                <X className="w-5 h-5" />
              </button>
            </div>

            <div className="space-y-2 text-xs font-mono text-slate-300">
              <div className="flex justify-between p-2 rounded bg-dark-900">
                <span className="text-slate-500">Timestamp:</span>
                <span>{new Date(selectedLog.timestamp).toLocaleString()}</span>
              </div>
              <div className="flex justify-between p-2 rounded bg-dark-900">
                <span className="text-slate-500">Client IP:</span>
                <span className="text-cyan-400 font-bold">{selectedLog.clientIp}</span>
              </div>
              <div className="flex justify-between p-2 rounded bg-dark-900">
                <span className="text-slate-500">Method & Path:</span>
                <span className="font-bold">{selectedLog.method} {selectedLog.path}</span>
              </div>
              <div className="flex justify-between p-2 rounded bg-dark-900">
                <span className="text-slate-500">Response Status:</span>
                <span className="font-bold text-emerald-400">{selectedLog.statusCode}</span>
              </div>
              <div className="flex justify-between p-2 rounded bg-dark-900">
                <span className="text-slate-500">Processing Duration:</span>
                <span>{selectedLog.durationMs.toFixed(2)} ms</span>
              </div>
              <div className="flex justify-between p-2 rounded bg-dark-900">
                <span className="text-slate-500">WAF Decision:</span>
                <ThreatBadge type="decision" value={selectedLog.decision} />
              </div>
            </div>

            <div className="pt-2 flex justify-end">
              <button
                onClick={() => setSelectedLog(null)}
                className="px-4 py-1.5 rounded bg-dark-700 text-xs font-semibold text-slate-200 hover:bg-dark-600"
              >
                Close
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
