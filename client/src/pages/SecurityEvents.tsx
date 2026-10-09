import { useState, useEffect } from 'react';
import { SecurityEvent, AttackCategory, ThreatSeverity } from '../types';
import { api } from '../services/api';
import { ThreatBadge } from '../components/ThreatBadge';
import { ShieldAlert, Search, Filter, Eye, X } from 'lucide-react';

export const SecurityEvents: React.FC = () => {
  const [events, setEvents] = useState<SecurityEvent[]>([]);
  const [loading, setLoading] = useState(true);
  const [search, setSearch] = useState('');
  const [category, setCategory] = useState<string>('');
  const [severity, setSeverity] = useState<string>('');
  const [selectedEvent, setSelectedEvent] = useState<SecurityEvent | null>(null);

  const fetchEvents = () => {
    setLoading(true);
    let q = `limit=50`;
    if (search) q += `&search=${encodeURIComponent(search)}`;
    if (category) q += `&category=${category}`;
    if (severity) q += `&severity=${severity}`;

    api.getEvents(q)
      .then((res) => setEvents(res.events))
      .catch(console.error)
      .finally(() => setLoading(false));
  };

  useEffect(() => {
    fetchEvents();
  }, [search, category, severity]);

  return (
    <div className="p-6 space-y-6">
      {/* Title */}
      <div>
        <h1 className="text-xl font-bold text-slate-100 uppercase tracking-tight flex items-center gap-2">
          <ShieldAlert className="w-5 h-5 text-red-400" />
          Security Events & Threat Intelligence
        </h1>
        <p className="text-xs text-slate-400">Detailed Threat Interception Audit & Attack Payload Telemetry</p>
      </div>

      {/* Filter Controls */}
      <div className="grid grid-cols-1 md:grid-cols-4 gap-4 bg-dark-800 p-4 rounded-lg border border-dark-700">
        <div className="relative md:col-span-2">
          <Search className="w-4 h-4 text-slate-500 absolute left-3 top-2.5" />
          <input
            type="text"
            placeholder="Search by IP, Path, Rule ID, or Explanation..."
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            className="w-full bg-dark-900 border border-dark-700 rounded-lg pl-9 pr-4 py-1.5 text-xs text-slate-200 focus:outline-none focus:border-cyan-500 font-mono"
          />
        </div>

        <div>
          <select
            value={category}
            onChange={(e) => setCategory(e.target.value)}
            className="w-full bg-dark-900 border border-dark-700 text-xs text-slate-300 rounded-lg px-3 py-1.5 focus:outline-none focus:border-cyan-500 font-mono"
          >
            <option value="">All Attack Categories</option>
            <option value="SQLI">SQL Injection (SQLI)</option>
            <option value="XSS">Cross-Site Scripting (XSS)</option>
            <option value="CSRF">CSRF</option>
            <option value="LFI">Local File Inclusion (LFI)</option>
            <option value="REMOTE_ACCESS">Unauthorized Admin Access</option>
            <option value="MALFORMED">Malformed / Command Injection</option>
            <option value="BOT">Bot Activity</option>
            <option value="RATE_LIMIT">Rate Limit Throttling</option>
          </select>
        </div>

        <div>
          <select
            value={severity}
            onChange={(e) => setSeverity(e.target.value)}
            className="w-full bg-dark-900 border border-dark-700 text-xs text-slate-300 rounded-lg px-3 py-1.5 focus:outline-none focus:border-cyan-500 font-mono"
          >
            <option value="">All Severities</option>
            <option value="CRITICAL">CRITICAL</option>
            <option value="HIGH">HIGH</option>
            <option value="MEDIUM">MEDIUM</option>
            <option value="LOW">LOW</option>
          </select>
        </div>
      </div>

      {/* Events Table */}
      <div className="bg-dark-800 border border-dark-700 rounded-lg overflow-hidden">
        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs font-mono">
            <thead className="bg-dark-900 text-slate-400 uppercase border-b border-dark-700">
              <tr>
                <th className="p-3">Timestamp</th>
                <th className="p-3">Client IP</th>
                <th className="p-3">Rule ID</th>
                <th className="p-3">Target Path</th>
                <th className="p-3">Category</th>
                <th className="p-3">Severity</th>
                <th className="p-3">Decision</th>
                <th className="p-3 text-right">Actions</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-dark-700/50">
              {events.length > 0 ? (
                events.map((event) => (
                  <tr key={event.id} className="hover:bg-dark-700/30">
                    <td className="p-3 text-slate-400">{new Date(event.timestamp).toLocaleString()}</td>
                    <td className="p-3 text-cyan-400 font-bold">{event.clientIp}</td>
                    <td className="p-3 text-amber-400 font-bold">{event.matchedRuleId || 'POLICY'}</td>
                    <td className="p-3 text-slate-200 truncate max-w-[200px]">{event.path}</td>
                    <td className="p-3"><ThreatBadge type="category" value={event.category} /></td>
                    <td className="p-3"><ThreatBadge type="severity" value={event.severity} /></td>
                    <td className="p-3"><ThreatBadge type="decision" value={event.decision} /></td>
                    <td className="p-3 text-right">
                      <button
                        onClick={() => setSelectedEvent(event)}
                        className="px-2.5 py-1 rounded bg-dark-700 hover:bg-dark-600 text-cyan-400 font-semibold flex items-center gap-1 text-[11px] ml-auto"
                      >
                        <Eye className="w-3 h-3" /> Details
                      </button>
                    </td>
                  </tr>
                ))
              ) : (
                <tr>
                  <td colSpan={8} className="p-8 text-center text-slate-500 font-mono">
                    No security events recorded.
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      </div>

      {/* Event Details Modal */}
      {selectedEvent && (
        <div className="fixed inset-0 bg-black/70 backdrop-blur-sm z-50 flex items-center justify-center p-4">
          <div className="bg-dark-800 border border-dark-700 rounded-lg max-w-2xl w-full p-6 space-y-4 shadow-2xl max-h-[90vh] overflow-y-auto">
            <div className="flex items-center justify-between border-b border-dark-700 pb-3">
              <h3 className="text-sm font-bold text-slate-100 uppercase tracking-tight font-mono">
                Threat Inspection Details ({selectedEvent.correlationId})
              </h3>
              <button onClick={() => setSelectedEvent(null)} className="text-slate-400 hover:text-white">
                <X className="w-5 h-5" />
              </button>
            </div>

            <div className="space-y-3 text-xs font-mono">
              <div className="p-3 rounded bg-dark-900 border border-dark-700 space-y-1">
                <p className="text-slate-500 uppercase text-[10px]">Detection Explanation</p>
                <p className="text-slate-200 font-sans leading-relaxed">{selectedEvent.explanation}</p>
              </div>

              <div className="grid grid-cols-2 gap-3">
                <div className="p-2.5 rounded bg-dark-900 border border-dark-700">
                  <span className="text-slate-500 block text-[10px] uppercase">Client IP</span>
                  <span className="text-cyan-400 font-bold">{selectedEvent.clientIp} ({selectedEvent.ipVersion})</span>
                </div>
                <div className="p-2.5 rounded bg-dark-900 border border-dark-700">
                  <span className="text-slate-500 block text-[10px] uppercase">Rule Triggered</span>
                  <span className="text-amber-400 font-bold">{selectedEvent.matchedRuleId || 'BASELINE_POLICY'}</span>
                </div>
              </div>

              {selectedEvent.queryParams && selectedEvent.queryParams !== '{}' && (
                <div className="p-3 rounded bg-dark-900 border border-dark-700 space-y-1">
                  <p className="text-slate-500 uppercase text-[10px]">Query Parameters</p>
                  <pre className="text-slate-300 font-mono text-[11px] overflow-x-auto p-2 bg-dark-950 rounded">
                    {selectedEvent.queryParams}
                  </pre>
                </div>
              )}

              {selectedEvent.requestBody && (
                <div className="p-3 rounded bg-dark-900 border border-dark-700 space-y-1">
                  <p className="text-slate-500 uppercase text-[10px]">Sanitized Request Body Payload</p>
                  <pre className="text-red-300 font-mono text-[11px] overflow-x-auto p-2 bg-dark-950 rounded">
                    {selectedEvent.requestBody}
                  </pre>
                </div>
              )}

              {selectedEvent.userAgent && (
                <div className="p-3 rounded bg-dark-900 border border-dark-700 space-y-1">
                  <p className="text-slate-500 uppercase text-[10px]">User Agent</p>
                  <p className="text-slate-300 truncate">{selectedEvent.userAgent}</p>
                </div>
              )}
            </div>

            <div className="pt-2 flex justify-end">
              <button
                onClick={() => setSelectedEvent(null)}
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
