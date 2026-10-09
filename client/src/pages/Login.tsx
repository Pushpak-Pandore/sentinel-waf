import React, { useState } from 'react';
import { useAuth } from '../context/AuthContext';
import { api } from '../services/api';
import { ShieldCheck, Lock, Mail, AlertCircle } from 'lucide-react';
import { useNavigate } from 'react-router-dom';

export const Login: React.FC = () => {
  const { login } = useAuth();
  const navigate = useNavigate();

  const [email, setEmail] = useState('admin@sentinel.local');
  const [password, setPassword] = useState('AdminPass123!');
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(false);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError('');
    setLoading(true);

    try {
      const data = await api.login({ email, password });
      login(data.token, data.user);
      navigate('/');
    } catch (err: any) {
      setError(err.message || 'Authentication failed');
    } finally {
      setLoading(false);
    }
  };

  const fillAdmin = () => {
    setEmail('admin@sentinel.local');
    setPassword('AdminPass123!');
  };

  const fillAnalyst = () => {
    setEmail('analyst@sentinel.local');
    setPassword('AnalystPass123!');
  };

  return (
    <div className="min-h-screen bg-dark-900 flex items-center justify-center p-4">
      <div className="max-w-md w-full bg-dark-800 border border-dark-700 rounded-xl p-8 space-y-6 shadow-2xl">
        {/* Brand */}
        <div className="text-center space-y-2">
          <div className="w-12 h-12 rounded-xl bg-cyan-950 border border-cyan-800 flex items-center justify-center text-cyan-400 mx-auto">
            <ShieldCheck className="w-7 h-7" />
          </div>
          <h1 className="text-2xl font-bold text-slate-100 tracking-tight">SENTINEL WAF</h1>
          <p className="text-xs text-slate-400 font-mono">Enterprise Threat Monitoring Console</p>
        </div>

        {error && (
          <div className="p-3 rounded bg-red-950/80 border border-red-800 text-red-300 text-xs font-mono flex items-center gap-2">
            <AlertCircle className="w-4 h-4 shrink-0" />
            <span>{error}</span>
          </div>
        )}

        <form onSubmit={handleSubmit} className="space-y-4 font-mono text-xs">
          <div>
            <label className="block text-slate-400 mb-1">Administrator Email</label>
            <div className="relative">
              <Mail className="w-4 h-4 text-slate-500 absolute left-3 top-2.5" />
              <input
                type="email"
                required
                value={email}
                onChange={(e) => setEmail(e.target.value)}
                className="w-full bg-dark-900 border border-dark-700 rounded-lg pl-9 pr-4 py-2 text-slate-200 focus:outline-none focus:border-cyan-500"
              />
            </div>
          </div>

          <div>
            <label className="block text-slate-400 mb-1">Password</label>
            <div className="relative">
              <Lock className="w-4 h-4 text-slate-500 absolute left-3 top-2.5" />
              <input
                type="password"
                required
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                className="w-full bg-dark-900 border border-dark-700 rounded-lg pl-9 pr-4 py-2 text-slate-200 focus:outline-none focus:border-cyan-500"
              />
            </div>
          </div>

          <button
            type="submit"
            disabled={loading}
            className="w-full py-2.5 rounded-lg bg-cyan-950 text-cyan-400 border border-cyan-800 font-bold hover:bg-cyan-900 transition-colors uppercase tracking-wider"
          >
            {loading ? 'Authenticating...' : 'Sign In to Security Console'}
          </button>
        </form>

        {/* Quick Demo Login Preset Buttons */}
        <div className="pt-4 border-t border-dark-700 space-y-2">
          <p className="text-[11px] font-mono text-slate-500 text-center uppercase">Pre-configured Demo Accounts:</p>
          <div className="grid grid-cols-2 gap-2">
            <button
              onClick={fillAdmin}
              className="px-3 py-1.5 rounded bg-dark-900 border border-dark-700 hover:border-slate-500 text-[11px] font-mono text-slate-300"
            >
              Fill Administrator
            </button>
            <button
              onClick={fillAnalyst}
              className="px-3 py-1.5 rounded bg-dark-900 border border-dark-700 hover:border-slate-500 text-[11px] font-mono text-slate-300"
            >
              Fill Analyst
            </button>
          </div>
        </div>
      </div>
    </div>
  );
};
