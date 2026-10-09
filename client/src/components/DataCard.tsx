import React from 'react';
import { LucideIcon } from 'lucide-react';

interface DataCardProps {
  title: string;
  value: string | number;
  subtitle?: string;
  icon: LucideIcon;
  trend?: string;
  variant?: 'default' | 'danger' | 'warning' | 'success' | 'info';
}

export const DataCard: React.FC<DataCardProps> = ({
  title,
  value,
  subtitle,
  icon: Icon,
  trend,
  variant = 'default',
}) => {
  let borderColor = 'border-slate-800';
  let iconBg = 'bg-slate-800/80 text-cyan-400';

  if (variant === 'danger') {
    borderColor = 'border-red-900/50';
    iconBg = 'bg-red-950/80 text-red-400';
  } else if (variant === 'warning') {
    borderColor = 'border-amber-900/50';
    iconBg = 'bg-amber-950/80 text-amber-400';
  } else if (variant === 'success') {
    borderColor = 'border-emerald-900/50';
    iconBg = 'bg-emerald-950/80 text-emerald-400';
  } else if (variant === 'info') {
    borderColor = 'border-blue-900/50';
    iconBg = 'bg-blue-950/80 text-blue-400';
  }

  return (
    <div className={`p-5 rounded-lg bg-dark-800 border ${borderColor} shadow-lg relative overflow-hidden transition-all duration-200 hover:border-slate-700`}>
      <div className="flex items-start justify-between">
        <div>
          <p className="text-xs uppercase font-medium text-slate-400 tracking-wider mb-1">{title}</p>
          <h3 className="text-2xl font-bold text-slate-100 font-mono">{value}</h3>
          {subtitle && <p className="text-xs text-slate-400 mt-1">{subtitle}</p>}
          {trend && <p className="text-xs text-emerald-400 font-medium mt-1">{trend}</p>}
        </div>
        <div className={`p-3 rounded-lg border border-slate-700/50 ${iconBg}`}>
          <Icon className="w-5 h-5" />
        </div>
      </div>
    </div>
  );
};
