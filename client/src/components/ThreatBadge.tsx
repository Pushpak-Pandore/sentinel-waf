import React from 'react';
import { ThreatSeverity, WafDecision, AttackCategory } from '../types';

interface BadgeProps {
  type?: 'severity' | 'decision' | 'category';
  value: string;
}

export const ThreatBadge: React.FC<BadgeProps> = ({ type = 'severity', value }) => {
  const val = value.toUpperCase();

  let colors = 'bg-slate-800 text-slate-300 border-slate-700';

  if (type === 'severity') {
    switch (val as ThreatSeverity) {
      case 'CRITICAL':
        colors = 'bg-red-950/80 text-red-400 border-red-800/80';
        break;
      case 'HIGH':
        colors = 'bg-orange-950/80 text-orange-400 border-orange-800/80';
        break;
      case 'MEDIUM':
        colors = 'bg-amber-950/80 text-amber-400 border-amber-800/80';
        break;
      case 'LOW':
        colors = 'bg-blue-950/80 text-blue-400 border-blue-800/80';
        break;
      default:
        colors = 'bg-emerald-950/80 text-emerald-400 border-emerald-800/80';
    }
  } else if (type === 'decision') {
    switch (val as WafDecision) {
      case 'BLOCK':
        colors = 'bg-red-950/90 text-red-400 border-red-800 font-semibold';
        break;
      case 'RATE_LIMIT':
        colors = 'bg-purple-950/90 text-purple-400 border-purple-800 font-semibold';
        break;
      case 'LOG':
        colors = 'bg-amber-950/90 text-amber-400 border-amber-800 font-semibold';
        break;
      case 'ALLOW':
        colors = 'bg-emerald-950/90 text-emerald-400 border-emerald-800 font-semibold';
        break;
    }
  } else {
    // Category
    colors = 'bg-dark-700 text-cyan-400 border-cyan-900/60 font-mono text-xs';
  }

  return (
    <span className={`inline-flex items-center px-2.5 py-0.5 rounded text-xs border uppercase tracking-wider ${colors}`}>
      {val}
    </span>
  );
};
