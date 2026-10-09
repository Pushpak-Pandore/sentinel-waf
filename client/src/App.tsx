import React from 'react';
import { BrowserRouter as Router, Routes, Route, Navigate } from 'react-router-dom';
import { AuthProvider, useAuth } from './context/AuthContext';
import { Navbar } from './components/Navbar';
import { Sidebar } from './components/Sidebar';

// Pages
import { Overview } from './pages/Overview';
import { LiveTraffic } from './pages/LiveTraffic';
import { SecurityEvents } from './pages/SecurityEvents';
import { AttackAnalytics } from './pages/AttackAnalytics';
import { WafRules } from './pages/WafRules';
import { IpAccessControl } from './pages/IpAccessControl';
import { RateLimiting } from './pages/RateLimiting';
import { ProtectedApps } from './pages/ProtectedApps';
import { RequestInspector } from './pages/RequestInspector';
import { AuditLogs } from './pages/AuditLogs';
import { SystemHealth } from './pages/SystemHealth';
import { Settings } from './pages/Settings';
import { Login } from './pages/Login';
import { WafExceptions } from './pages/WafExceptions';
import { VirtualPatches } from './pages/VirtualPatches';
import { SiemConfig } from './pages/SiemConfig';

const ProtectedLayout: React.FC<{ children: React.ReactNode }> = ({ children }) => {
  const { user, loading } = useAuth();

  if (loading) {
    return (
      <div className="min-h-screen bg-dark-900 flex items-center justify-center text-cyan-400 font-mono text-xs">
        Initializing Sentinel WAF Security Environment...
      </div>
    );
  }

  if (!user) {
    return <Navigate to="/login" replace />;
  }

  return (
    <div className="min-h-screen flex flex-col bg-dark-900">
      <Navbar />
      <div className="flex flex-1">
        <Sidebar />
        <main className="flex-1 overflow-y-auto bg-dark-900">
          {children}
        </main>
      </div>
    </div>
  );
};

export function App() {
  return (
    <AuthProvider>
      <Router>
        <Routes>
          <Route path="/login" element={<Login />} />
          
          <Route path="/" element={<ProtectedLayout><Overview /></ProtectedLayout>} />
          <Route path="/traffic" element={<ProtectedLayout><LiveTraffic /></ProtectedLayout>} />
          <Route path="/events" element={<ProtectedLayout><SecurityEvents /></ProtectedLayout>} />
          <Route path="/analytics" element={<ProtectedLayout><AttackAnalytics /></ProtectedLayout>} />
          <Route path="/rules" element={<ProtectedLayout><WafRules /></ProtectedLayout>} />
          <Route path="/exceptions" element={<ProtectedLayout><WafExceptions /></ProtectedLayout>} />
          <Route path="/virtual-patches" element={<ProtectedLayout><VirtualPatches /></ProtectedLayout>} />
          <Route path="/siem" element={<ProtectedLayout><SiemConfig /></ProtectedLayout>} />
          <Route path="/ip-access" element={<ProtectedLayout><IpAccessControl /></ProtectedLayout>} />
          <Route path="/rate-limiting" element={<ProtectedLayout><RateLimiting /></ProtectedLayout>} />
          <Route path="/apps" element={<ProtectedLayout><ProtectedApps /></ProtectedLayout>} />
          <Route path="/inspector" element={<ProtectedLayout><RequestInspector /></ProtectedLayout>} />
          <Route path="/audit" element={<ProtectedLayout><AuditLogs /></ProtectedLayout>} />
          <Route path="/health" element={<ProtectedLayout><SystemHealth /></ProtectedLayout>} />
          <Route path="/settings" element={<ProtectedLayout><Settings /></ProtectedLayout>} />

          <Route path="*" element={<Navigate to="/" replace />} />
        </Routes>
      </Router>
    </AuthProvider>
  );
}

export default App;
