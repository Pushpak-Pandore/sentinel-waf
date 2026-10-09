import React from 'react';
import { Cpu, ShieldCheck, AlertTriangle, CheckCircle2 } from 'lucide-react';

export interface MlShadowData {
  period: string;
  mode: string;
  totalEvaluated: number;
  anomaliesCount: number;
  normalCount: number;
  avgAnomalyScore: number;
  wafAgreementPercentage: number;
  recentAnomalies: Array<{
    id: string;
    correlationId: string;
    path: string;
    method: string;
    decision: string;
    mlAnomalyScore: number;
    mlPrediction: string;
    timestamp: string;
  }>;
}

interface MlShadowCardProps {
  data: MlShadowData | null;
  loading?: boolean;
}

export const MlShadowCard: React.FC<MlShadowCardProps> = ({ data, loading }) => {
  if (loading) {
    return (
      <div className="bg-dark-800 border border-dark-700 rounded-lg p-5 h-64 flex items-center justify-center">
        <Cpu className="w-6 h-6 text-cyan-400 animate-spin" />
      </div>
    );
  }

  if (!data) return null;

  return (
    <div className="bg-dark-800 border border-dark-700 rounded-lg p-5 space-y-5">
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2">
        <div className="flex items-center space-x-2">
          <Cpu className="w-5 h-5 text-purple-400" />
          <h3 className="text-xs uppercase font-mono font-bold text-slate-200">
            HTTP Anomaly Detection Engine (ML Shadow Mode)
          </h3>
        </div>

        <div className="flex items-center space-x-2">
          <span className="inline-flex items-center px-2 py-0.5 rounded text-[10px] font-mono font-bold bg-purple-950 text-purple-300 border border-purple-800/60">
            <ShieldCheck className="w-3 h-3 mr-1" /> SHADOW EVALUATION ONLY
          </span>
          <span className="text-[10px] font-mono text-slate-400">Non-Blocking</span>
        </div>
      </div>

      {/* Grid of Key Metrics */}
      <div className="grid grid-cols-2 sm:grid-cols-4 gap-4">
        <div className="bg-dark-900 border border-dark-700 rounded-lg p-3">
          <span className="text-[10px] font-mono text-slate-400 block uppercase">Evaluated Requests</span>
          <span className="text-lg font-mono font-bold text-slate-100">{data.totalEvaluated}</span>
        </div>

        <div className="bg-dark-900 border border-dark-700 rounded-lg p-3">
          <span className="text-[10px] font-mono text-slate-400 block uppercase">ML Anomalies Flagged</span>
          <span className="text-lg font-mono font-bold text-rose-400">{data.anomaliesCount}</span>
        </div>

        <div className="bg-dark-900 border border-dark-700 rounded-lg p-3">
          <span className="text-[10px] font-mono text-slate-400 block uppercase">Avg Anomaly Score</span>
          <span className="text-lg font-mono font-bold text-purple-400">{data.avgAnomalyScore} / 1.0</span>
        </div>

        <div className="bg-dark-900 border border-dark-700 rounded-lg p-3">
          <span className="text-[10px] font-mono text-slate-400 block uppercase">WAF CRS Agreement</span>
          <span className="text-lg font-mono font-bold text-emerald-400">{data.wafAgreementPercentage}%</span>
        </div>
      </div>

      {/* Recent Flagged Anomalies List */}
      <div>
        <h4 className="text-[11px] font-mono font-bold text-slate-300 uppercase mb-2">
          Recent ML Anomaly Telemetry (Shadow Predictions vs Deterministic WAF)
        </h4>

        {data.recentAnomalies.length === 0 ? (
          <div className="p-3 border border-dashed border-dark-700 rounded-lg text-center text-xs text-slate-500 font-mono">
            No structural HTTP anomalies detected by the ML shadow engine in this period.
          </div>
        ) : (
          <div className="space-y-2 max-h-48 overflow-y-auto">
            {data.recentAnomalies.map((anom) => (
              <div
                key={anom.id}
                className="flex items-center justify-between p-2.5 bg-dark-900 border border-dark-700 rounded text-xs font-mono"
              >
                <div className="flex items-center space-x-3">
                  <span className="px-1.5 py-0.5 rounded bg-dark-800 text-cyan-400 text-[10px] font-bold">
                    {anom.method}
                  </span>
                  <span className="text-slate-300 truncate max-w-xs">{anom.path}</span>
                </div>

                <div className="flex items-center space-x-4">
                  <div className="flex items-center text-rose-400 text-[11px] font-bold">
                    <AlertTriangle className="w-3.5 h-3.5 mr-1" />
                    Score: {anom.mlAnomalyScore}
                  </div>

                  <span
                    className={`px-2 py-0.5 rounded text-[10px] font-bold ${
                      anom.decision === 'BLOCK'
                        ? 'bg-rose-950 text-rose-300 border border-rose-800'
                        : 'bg-emerald-950 text-emerald-300 border border-emerald-800'
                    }`}
                  >
                    WAF: {anom.decision}
                  </span>
                </div>
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  );
};
