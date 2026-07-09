import React, { useState, useEffect, useCallback } from 'react';
import axios from 'axios';
import { BrowserRouter, Routes, Route, Navigate, useNavigate } from 'react-router-dom';
import {
  PieChart, Pie, Cell, BarChart, Bar, XAxis, YAxis, Tooltip,
  ResponsiveContainer, LineChart, Line, CartesianGrid
} from 'recharts';
import { Shield, Download, LogOut, ShieldAlert } from 'lucide-react';
import Login from './Login';
import './index.css';

const COLORS = ['#ef4444', '#f59e0b', '#eab308', '#22c55e', '#3b82f6', '#8b5cf6'];
const REFRESH_INTERVAL = 30;

// Axios Interceptor for Auth
axios.defaults.baseURL = process.env.REACT_APP_API_URL;

axios.interceptors.request.use((config) => {
  const token = localStorage.getItem('cti_token');
  if (token) {
    config.headers.Authorization = `Bearer ${token}`;
  }
  return config;
});

function Dashboard({ setToken }) {
  const [threats, setThreats] = useState([]);
  const [summary, setSummary] = useState({});
  const [byType, setByType] = useState([]);
  const [bySource, setBySource] = useState([]);
  const [malwareFamilies, setMalwareFamilies] = useState([]);
  const [trendData, setTrendData] = useState([]);
  const [filter, setFilter] = useState('');
  const [severityFilter, setSeverityFilter] = useState('');
  const [loading, setLoading] = useState(true);
  const [countdown, setCountdown] = useState(REFRESH_INTERVAL);
  const [page, setPage] = useState(1);
  const [perPage, setPerPage] = useState(10);
  const navigate = useNavigate();

  const handleLogout = () => {
    localStorage.removeItem('cti_token');
    setToken(null);
    navigate('/login');
  };

  const fetchData = useCallback(async () => {
    try {
      const [threatsRes, summaryRes, typeRes, sourceRes] = await Promise.all([
        axios.get('/api/threats'),
        axios.get('/api/summary'),
        axios.get('/api/threats/by-type'),
        axios.get('/api/threats/by-source'),
      ]);

      const data = threatsRes.data.data || [];
      setThreats(data);
      setSummary(summaryRes.data);
      setByType(Object.entries(typeRes.data).map(([name, value]) => ({ name, value })));

      const srcEntries = Object.entries(sourceRes.data);
      const srcTotal = srcEntries.reduce((a, [, v]) => a + v, 0);
      setBySource(srcEntries.map(([name, value]) => ({
        name, value, pct: ((value / srcTotal) * 100).toFixed(1)
      })));

      const malwareCount = {};
      data.forEach(t => {
        const m = Array.isArray(t.malware) ? t.malware.join(',') : (t.malware || 'Unknown');
        malwareCount[m] = (malwareCount[m] || 0) + 1;
      });
      setMalwareFamilies(
        Object.entries(malwareCount)
          .sort((a, b) => b[1] - a[1])
          .slice(0, 8)
          .map(([name, count]) => ({ name, count }))
      );

      setTrendData(prev => {
        const now = new Date().toLocaleTimeString('en-GB', { hour12: false });
        const newPoint = { time: now, threats: data.length };
        return [...prev, newPoint].slice(-10);
      });

      setLoading(false);
      setCountdown(REFRESH_INTERVAL);
    } catch (err) {
      if (err.response && err.response.status === 401) {
        handleLogout();
      }
      setLoading(false);
    }
  }, [navigate]);

  useEffect(() => {
    fetchData();
    const interval = setInterval(fetchData, REFRESH_INTERVAL * 1000);
    return () => clearInterval(interval);
  }, [fetchData]);

  useEffect(() => {
    const timer = setInterval(() => setCountdown(c => (c <= 1 ? REFRESH_INTERVAL : c - 1)), 1000);
    return () => clearInterval(timer);
  }, []);

  const filtered = threats.filter(t => {
    const matchIP = filter === '' || (t.indicator || '').toLowerCase().includes(filter.toLowerCase());
    const matchSev = severityFilter === '' || t.severity === severityFilter;
    return matchIP && matchSev;
  });

  const totalPages = Math.ceil(filtered.length / perPage);
  const paginated = filtered.slice((page - 1) * perPage, page * perPage);

  const sevColor = (sev) => {
    if (sev === 'CRITICAL') return 'text-red-500 border-red-500/50 bg-red-500/10';
    if (sev === 'HIGH') return 'text-orange-500 border-orange-500/50 bg-orange-500/10';
    if (sev === 'MEDIUM') return 'text-yellow-500 border-yellow-500/50 bg-yellow-500/10';
    return 'text-green-500 border-green-500/50 bg-green-500/10';
  };

  const exportCSV = () => {
    const cols = ['indicator', 'type', 'source', 'severity', 'risk_score', 'timestamp'];
    const rows = [cols.join(','), ...threats.map(t => cols.map(c => `"${t[c] || ''}"`).join(','))];
    const blob = new Blob([rows.join('\n')], { type: 'text/csv' });
    const a = document.createElement('a');
    a.href = URL.createObjectURL(blob);
    a.download = `cti_threats.csv`;
    a.click();
  };

  if (loading && threats.length === 0) {
    return (
      <div className="min-h-screen bg-dark-900 flex items-center justify-center">
        <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-blue-500"></div>
      </div>
    );
  }

  return (
    <div className="min-h-screen bg-dark-900 text-gray-100 p-6">
      {/* Header */}
      <header className="glass-panel rounded-2xl p-4 mb-6 flex justify-between items-center">
        <div className="flex items-center space-x-4">
          <div className="bg-dark-800 p-3 rounded-xl border border-gray-700">
            <ShieldAlert size={28} className="text-blue-400" />
          </div>
          <div>
            <h1 className="text-2xl font-bold tracking-tight">Enterprise CTI</h1>
            <p className="text-sm text-gray-400">Cyber Threat Intelligence Platform</p>
          </div>
        </div>
        
        <div className="flex items-center space-x-6">
          <div className="flex items-center space-x-2 text-sm text-gray-400">
            <div className="w-2 h-2 rounded-full bg-green-500 animate-pulse"></div>
            <span>LIVE (Refresh in {countdown}s)</span>
          </div>
          <button onClick={exportCSV} className="flex items-center space-x-2 bg-dark-800 hover:bg-dark-700 px-4 py-2 rounded-lg border border-gray-700 transition">
            <Download size={16} />
            <span>Export CSV</span>
          </button>
          <button onClick={handleLogout} className="flex items-center space-x-2 bg-red-500/10 hover:bg-red-500/20 text-red-400 px-4 py-2 rounded-lg border border-red-500/30 transition">
            <LogOut size={16} />
            <span>Logout</span>
          </button>
        </div>
      </header>

      {/* Stats Cards */}
      <div className="grid grid-cols-1 md:grid-cols-3 lg:grid-cols-6 gap-4 mb-6">
        {[
          { label: 'TOTAL', val: summary.total || 0, color: 'text-blue-400' },
          { label: 'CRITICAL', val: summary.critical || 0, color: 'text-red-500' },
          { label: 'HIGH', val: summary.high || 0, color: 'text-orange-500' },
          { label: 'MEDIUM', val: summary.medium || 0, color: 'text-yellow-500' },
          { label: 'LOW', val: summary.low || 0, color: 'text-green-500' },
          { label: 'AVG RISK', val: summary.avg_score || 0, color: 'text-purple-400' },
        ].map((s, i) => (
          <div key={i} className="glass-panel p-4 rounded-xl flex flex-col items-center justify-center">
            <span className={`text-3xl font-bold ${s.color}`}>{s.val}</span>
            <span className="text-xs text-gray-400 font-semibold tracking-wider mt-1">{s.label}</span>
          </div>
        ))}
      </div>

      {/* Charts */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6 mb-6">
        <div className="glass-panel p-5 rounded-xl">
          <h3 className="text-lg font-semibold mb-4 flex items-center"><Shield size={18} className="mr-2 text-blue-400" /> Threats by Type</h3>
          <ResponsiveContainer width="100%" height={250}>
            <BarChart data={byType}>
              <XAxis dataKey="name" stroke="#64748b" fontSize={12} />
              <YAxis stroke="#64748b" fontSize={12} />
              <Tooltip contentStyle={{ background: '#1e293b', border: '1px solid #334155', borderRadius: '8px' }} />
              <Bar dataKey="value" fill="#3b82f6" radius={[4, 4, 0, 0]} />
            </BarChart>
          </ResponsiveContainer>
        </div>

        <div className="glass-panel p-5 rounded-xl">
          <h3 className="text-lg font-semibold mb-4 flex items-center"><Shield size={18} className="mr-2 text-purple-400" /> Detection Trend</h3>
          <ResponsiveContainer width="100%" height={250}>
            <LineChart data={trendData}>
              <CartesianGrid strokeDasharray="3 3" stroke="#334155" />
              <XAxis dataKey="time" stroke="#64748b" fontSize={12} />
              <YAxis stroke="#64748b" fontSize={12} />
              <Tooltip contentStyle={{ background: '#1e293b', border: '1px solid #334155', borderRadius: '8px' }} />
              <Line type="monotone" dataKey="threats" stroke="#8b5cf6" strokeWidth={3} dot={{ fill: '#8b5cf6', r: 4 }} />
            </LineChart>
          </ResponsiveContainer>
        </div>
      </div>

      {/* Data Table */}
      <div className="glass-panel rounded-xl overflow-hidden">
        <div className="p-4 border-b border-gray-700 bg-dark-800/50 flex flex-wrap gap-4 items-center justify-between">
          <div className="flex gap-4">
            <input
              type="text"
              placeholder="Search IOCs..."
              className="bg-dark-900 border border-gray-700 rounded-lg px-4 py-2 text-sm focus:outline-none focus:border-blue-500 w-64"
              value={filter}
              onChange={e => { setFilter(e.target.value); setPage(1); }}
            />
            <select
              className="bg-dark-900 border border-gray-700 rounded-lg px-4 py-2 text-sm focus:outline-none focus:border-blue-500"
              value={severityFilter}
              onChange={e => { setSeverityFilter(e.target.value); setPage(1); }}
            >
              <option value="">All Severities</option>
              <option value="CRITICAL">CRITICAL</option>
              <option value="HIGH">HIGH</option>
              <option value="MEDIUM">MEDIUM</option>
            </select>
          </div>
          <div className="text-sm text-gray-400">
            Showing {filtered.length} Indicators
          </div>
        </div>

        <div className="overflow-x-auto">
          <table className="w-full text-left text-sm whitespace-nowrap">
            <thead className="bg-dark-800/80 text-gray-400 uppercase font-semibold text-xs tracking-wider">
              <tr>
                <th className="px-6 py-4">Indicator (IOC)</th>
                <th className="px-6 py-4">Type</th>
                <th className="px-6 py-4">Source</th>
                <th className="px-6 py-4">Severity</th>
                <th className="px-6 py-4">Risk Score</th>
                <th className="px-6 py-4">Timestamp</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-gray-700/50">
              {paginated.map((t, i) => (
                <tr key={i} className="hover:bg-white/5 transition-colors">
                  <td className="px-6 py-4 font-mono text-blue-400">{t.indicator}</td>
                  <td className="px-6 py-4">
                    <span className="bg-dark-700 text-gray-300 px-2 py-1 rounded text-xs">{t.type}</span>
                  </td>
                  <td className="px-6 py-4">{t.source}</td>
                  <td className="px-6 py-4">
                    <span className={`px-2 py-1 rounded text-xs font-bold border ${sevColor(t.severity)}`}>
                      {t.severity}
                    </span>
                  </td>
                  <td className="px-6 py-4 font-bold">{t.risk_score}</td>
                  <td className="px-6 py-4 text-gray-400 text-xs">{new Date(t.timestamp).toLocaleString()}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
        
        {/* Pagination Controls */}
        <div className="p-4 border-t border-gray-700 bg-dark-800/30 flex justify-between items-center">
          <div className="text-sm text-gray-400">
            Page {page} of {Math.max(1, totalPages)}
          </div>
          <div className="flex space-x-2">
            <button onClick={() => setPage(p => Math.max(1, p - 1))} disabled={page === 1} className="px-3 py-1 bg-dark-700 rounded hover:bg-dark-600 disabled:opacity-50">Prev</button>
            <button onClick={() => setPage(p => Math.min(totalPages, p + 1))} disabled={page === totalPages || totalPages === 0} className="px-3 py-1 bg-dark-700 rounded hover:bg-dark-600 disabled:opacity-50">Next</button>
          </div>
        </div>
      </div>
    </div>
  );
}

function App() {
  const [token, setToken] = useState(localStorage.getItem('cti_token'));

  return (
    <BrowserRouter>
      <Routes>
        <Route path="/login" element={token ? <Navigate to="/" /> : <Login setToken={setToken} />} />
        <Route path="/" element={token ? <Dashboard setToken={setToken} /> : <Navigate to="/login" />} />
      </Routes>
    </BrowserRouter>
  );
}

export default App;
