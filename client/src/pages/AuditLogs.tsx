import React, { useEffect, useState } from 'react';
import { AuditLog } from '../types';
import { api } from '../services/api';
import { FileCheck } from 'lucide-react';

export const AuditLogs: React.FC = () => {
  const [logs, setLogs] = useState<AuditLog[]>([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    api.getAuditLogs()
      .then((res) => setLogs(res.logs))
      .catch(console.error)
      .finally(() => setLoading(false));
  }, []);

  return (
    <div className="p-6 space-y-6">
      <div>
        <h1 className="text-xl font-bold text-slate-100 uppercase tracking-tight flex items-center gap-2">
          <FileCheck className="w-5 h-5 text-cyan-400" />
          Administrative Audit Logs
        </h1>
        <p className="text-xs text-slate-400">Immutable Audit Trail of WAF Configuration Changes and Security Operations</p>
      </div>

      <div className="bg-dark-800 border border-dark-700 rounded-lg overflow-hidden">
        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs font-mono">
            <thead className="bg-dark-900 text-slate-400 uppercase border-b border-dark-700">
              <tr>
                <th className="p-3">Timestamp</th>
                <th className="p-3">User / Actor</th>
                <th className="p-3">Action</th>
                <th className="p-3">Entity</th>
                <th className="p-3">Details Context</th>
                <th className="p-3">Source IP</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-dark-700/50">
              {logs.length > 0 ? (
                logs.map((log) => (
                  <tr key={log.id} className="hover:bg-dark-700/30">
                    <td className="p-3 text-slate-400">{new Date(log.timestamp).toLocaleString()}</td>
                    <td className="p-3 text-cyan-400 font-bold">{log.userEmail || 'SYSTEM'}</td>
                    <td className="p-3 text-amber-400 font-bold">{log.action}</td>
                    <td className="p-3 text-slate-300">{log.entity}</td>
                    <td className="p-3 text-slate-400 truncate max-w-[300px]">{log.details || 'N/A'}</td>
                    <td className="p-3 text-slate-400">{log.ipAddress || '127.0.0.1'}</td>
                  </tr>
                ))
              ) : (
                <tr>
                  <td colSpan={6} className="p-8 text-center text-slate-500 font-mono">
                    No audit logs recorded yet.
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
};
