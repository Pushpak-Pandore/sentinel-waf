import React from 'react';
import { Globe, ShieldAlert, ShieldCheck } from 'lucide-react';

export interface CountryThreatData {
  countryCode: string;
  countryName: string;
  totalEvents: number;
  blockedCount: number;
  allowedCount: number;
  lat: number;
  lng: number;
}

interface WorldThreatMapProps {
  countries: CountryThreatData[];
  loading?: boolean;
}

export const WorldThreatMap: React.FC<WorldThreatMapProps> = ({ countries, loading }) => {
  if (loading) {
    return (
      <div className="bg-dark-800 border border-dark-700 rounded-lg p-6 h-80 flex flex-col items-center justify-center space-y-3">
        <Globe className="w-8 h-8 text-cyan-400 animate-spin" />
        <p className="text-xs font-mono text-slate-400">Loading GeoIP Threat Intelligence Map...</p>
      </div>
    );
  }

  const maxEvents = Math.max(1, ...countries.map((c) => c.totalEvents));

  return (
    <div className="bg-dark-800 border border-dark-700 rounded-lg p-5 space-y-5">
      <div className="flex items-center justify-between">
        <div className="flex items-center space-x-2">
          <Globe className="w-5 h-5 text-cyan-400" />
          <h3 className="text-xs uppercase font-mono font-bold text-slate-200">
            Global Geographic Threat Distribution Map
          </h3>
        </div>
        <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-dark-700 text-slate-400 border border-dark-600">
          MaxMind GeoIP2 Enriched
        </span>
      </div>

      {countries.length === 0 ? (
        <div className="h-48 border border-dashed border-dark-700 rounded-lg flex flex-col items-center justify-center text-xs text-slate-500 font-mono space-y-2">
          <Globe className="w-6 h-6 text-slate-600" />
          <span>No geographic attack origin data recorded in selected window.</span>
          <span className="text-[11px] text-slate-600">Send requests via Request Inspector to trigger GeoIP lookups.</span>
        </div>
      ) : (
        <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
          {/* Visual Vector Representation Grid */}
          <div className="lg:col-span-2 bg-dark-900 border border-dark-700 rounded-lg p-4 relative min-h-[220px] flex flex-col justify-between overflow-hidden">
            <div className="absolute inset-0 opacity-10 bg-[radial-gradient(#38bdf8_1px,transparent_1px)] [background-size:16px_16px] pointer-events-none" />
            
            <div className="text-[11px] font-mono text-slate-400 mb-3 flex items-center justify-between">
              <span>ACTIVE THREAT ORIGIN CLUSTERS</span>
              <span>{countries.length} COUNTRIES IDENTIFIED</span>
            </div>

            <div className="grid grid-cols-1 sm:grid-cols-2 gap-3 z-10">
              {countries.slice(0, 6).map((c) => {
                const intensityPct = Math.round((c.totalEvents / maxEvents) * 100);
                return (
                  <div
                    key={c.countryCode}
                    className="p-3 rounded-lg bg-dark-800/80 border border-dark-700 hover:border-cyan-500/50 transition-all"
                  >
                    <div className="flex items-center justify-between mb-1.5">
                      <div className="flex items-center space-x-2">
                        <span className="text-xs font-mono font-bold text-cyan-400 bg-cyan-950/60 px-1.5 py-0.5 rounded border border-cyan-800/40">
                          {c.countryCode}
                        </span>
                        <span className="text-xs font-medium text-slate-200 truncate max-w-[120px]">
                          {c.countryName}
                        </span>
                      </div>
                      <span className="text-xs font-mono font-bold text-slate-300">{c.totalEvents} req</span>
                    </div>

                    {/* Progress Bar Intensity */}
                    <div className="w-full bg-dark-950 rounded-full h-1.5 mb-2 overflow-hidden">
                      <div
                        className="bg-gradient-to-r from-cyan-500 to-rose-500 h-1.5 rounded-full"
                        style={{ width: `${Math.max(10, intensityPct)}%` }}
                      />
                    </div>

                    <div className="flex items-center justify-between text-[10px] font-mono text-slate-400">
                      <span className="flex items-center text-rose-400">
                        <ShieldAlert className="w-3 h-3 mr-1" /> {c.blockedCount} Blocked
                      </span>
                      <span className="flex items-center text-emerald-400">
                        <ShieldCheck className="w-3 h-3 mr-1" /> {c.allowedCount} Allowed
                      </span>
                    </div>
                  </div>
                );
              })}
            </div>

            <div className="mt-3 text-[10px] text-slate-500 font-mono italic">
              * Note: Geographic attribution is approximate and based on client remote socket or validated proxy header lookups.
            </div>
          </div>

          {/* Top Country Leaderboard */}
          <div className="bg-dark-900 border border-dark-700 rounded-lg p-4 flex flex-col justify-between">
            <div>
              <h4 className="text-xs font-mono font-bold text-slate-300 uppercase mb-3">
                Top Attack Origin Countries
              </h4>
              <div className="space-y-2.5">
                {countries.slice(0, 5).map((c, i) => (
                  <div key={c.countryCode} className="flex items-center justify-between text-xs font-mono py-1 border-b border-dark-800 last:border-0">
                    <div className="flex items-center space-x-2">
                      <span className="text-slate-500 font-bold w-4">#{i + 1}</span>
                      <span className="text-slate-200">{c.countryName}</span>
                    </div>
                    <div className="flex items-center space-x-3">
                      <span className="text-rose-400 font-bold">{c.blockedCount} blocked</span>
                    </div>
                  </div>
                ))}
              </div>
            </div>

            <div className="pt-3 border-t border-dark-800 text-[11px] font-mono text-slate-400 flex items-center justify-between">
              <span>Total Global Events:</span>
              <span className="text-cyan-400 font-bold">
                {countries.reduce((acc, curr) => acc + curr.totalEvents, 0)}
              </span>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
