import React, { useState, useEffect, useCallback } from 'react';
import axios from 'axios';
import {
  PieChart, Pie, Cell, BarChart, Bar, XAxis, YAxis, Tooltip,
  ResponsiveContainer, LineChart, Line, CartesianGrid, Legend
} from 'recharts';
import './App.css';

const COLORS = ['#f85149', '#e3b341', '#d29922', '#3fb950', '#58a6ff', '#bc8cff'];
const REFRESH_INTERVAL = 30;

function highlight(text, query) {
  if (!query || !text) return text;
  const str = String(text);
  const idx = str.toLowerCase().indexOf(query.toLowerCase());
  if (idx === -1) return str;
  return (
    <>
      {str.substring(0, idx)}
      <mark style={{ background: '#e3b341', color: '#0d1117', borderRadius: '2px' }}>
        {str.substring(idx, idx + query.length)}
      </mark>
      {str.substring(idx + query.length)}
    </>
  );
}

function Spinner() {
  return (
    <div className="spinner-wrap">
      <div className="spinner"></div>
      <span>Fetching threat intelligence...</span>
    </div>
  );
}

function App() {
  const [threats, setThreats] = useState([]);
  const [summary, setSummary] = useState({});
  const [byType, setByType] = useState([]);
  const [bySource, setBySource] = useState([]);
  const [malwareFamilies, setMalwareFamilies] = useState([]);
  const [trendData, setTrendData] = useState([]);
  const [filter, setFilter] = useState('');
  const [severityFilter, setSeverityFilter] = useState('');
  const [lastUpdated, setLastUpdated] = useState('');
  const [loading, setLoading] = useState(true);
  const [countdown, setCountdown] = useState(REFRESH_INTERVAL);
  const [page, setPage] = useState(1);
  const [perPage, setPerPage] = useState(10);
  const [copied, setCopied] = useState(null);

  const fetchData = useCallback(async () => {
    try {
      const [threatsRes, summaryRes, typeRes, sourceRes] = await Promise.all([
        axios.get('http://localhost:5000/api/threats'),
        axios.get('http://localhost:5000/api/summary'),
        axios.get('http://localhost:5000/api/threats/by-type'),
        axios.get('http://localhost:5000/api/threats/by-source'),
      ]);

      const data = threatsRes.data.data || [];
      setThreats(data);
      setSummary(summaryRes.data);
      setLastUpdated(threatsRes.data.last_updated);
      setByType(Object.entries(typeRes.data).map(([name, value]) => ({ name, value })));

      // Source with percentages
      const srcEntries = Object.entries(sourceRes.data);
      const srcTotal = srcEntries.reduce((a, [, v]) => a + v, 0);
      setBySource(srcEntries.map(([name, value]) => ({
        name, value, pct: ((value / srcTotal) * 100).toFixed(1)
      })));

      // Top malware families
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

      // Trend data (simulate hourly)
      setTrendData(prev => {
        const now = new Date().toLocaleTimeString('en-GB', { hour12: false });
        const newPoint = { time: now, threats: data.length };
        const updated = [...prev, newPoint].slice(-10);
        return updated;
      });

      setLoading(false);
      setCountdown(REFRESH_INTERVAL);
    } catch (err) {
      console.error('Error:', err);
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    fetchData();
    const interval = setInterval(fetchData, REFRESH_INTERVAL * 1000);
    return () => clearInterval(interval);
  }, [fetchData]);

  // Countdown timer
  useEffect(() => {
    const timer = setInterval(() => {
      setCountdown(c => (c <= 1 ? REFRESH_INTERVAL : c - 1));
    }, 1000);
    return () => clearInterval(timer);
  }, []);

  // Filter
  const filtered = threats.filter(t => {
    const matchIP = filter === '' || (t.ioc || '').toLowerCase().includes(filter.toLowerCase())
      || (t.malware || '').toString().toLowerCase().includes(filter.toLowerCase());
    const matchSev = severityFilter === '' || t.severity === severityFilter;
    return matchIP && matchSev;
  });

  // Pagination
  const totalPages = Math.ceil(filtered.length / perPage);
  const paginated = filtered.slice((page - 1) * perPage, page * perPage);

  const sevColor = (sev) => {
    if (sev === 'CRITICAL') return '#f85149';
    if (sev === 'HIGH') return '#e3b341';
    if (sev === 'MEDIUM') return '#d29922';
    return '#3fb950';
  };

  const exportCSV = () => {
    const cols = ['ioc', 'type', 'threat', 'malware', 'source', 'severity', 'risk_score', 'timestamp'];
    const rows = [cols.join(','), ...threats.map(t => cols.map(c => `"${t[c] || ''}"`).join(','))];
    const blob = new Blob([rows.join('\n')], { type: 'text/csv' });
    const a = document.createElement('a');
    a.href = URL.createObjectURL(blob);
    a.download = `cti_threats_${new Date().toISOString().slice(0, 10)}.csv`;
    a.click();
  };

  const copyIOC = (ioc) => {
    navigator.clipboard.writeText(ioc);
    setCopied(ioc);
    setTimeout(() => setCopied(null), 2000);
  };

  const CustomPieLabel = ({ cx, cy, midAngle, innerRadius, outerRadius, name, pct }) => {
    const RADIAN = Math.PI / 180;
    const radius = innerRadius + (outerRadius - innerRadius) * 1.4;
    const x = cx + radius * Math.cos(-midAngle * RADIAN);
    const y = cy + radius * Math.sin(-midAngle * RADIAN);
    return (
      <text x={x} y={y} fill="#c9d1d9" textAnchor="middle" dominantBaseline="central" fontSize={11}>
        {name} ({pct}%)
      </text>
    );
  };

  return (
    <div className="app">
      <header>
        <div className="logo">
          <span className="shield">🛡</span>
          <div>
            <div className="title">CTI DASHBOARD</div>
            <div className="subtitle">CYBER THREAT INTELLIGENCE</div>
          </div>
        </div>
        <div className="header-right">
          <span className="updated">Updated: {lastUpdated || '—'}</span>
          <span className="countdown">Refresh in {countdown}s</span>
          <button className="export-btn" onClick={exportCSV}>⬇ Export CSV</button>
          <div className="live-badge">● LIVE</div>
        </div>
      </header>

      {/* Stats */}
      <div className="stats">
        {[
          { key: 'total', label: 'TOTAL THREATS', val: summary.total || 0 },
          { key: 'critical', label: 'CRITICAL', val: summary.critical || 0 },
          { key: 'high', label: 'HIGH', val: summary.high || 0 },
          { key: 'medium', label: 'MEDIUM', val: summary.medium || 0 },
          { key: 'low', label: 'LOW', val: summary.low || 0 },
          { key: 'avg', label: 'AVG SCORE', val: summary.avg_score || 0 },
        ].map(s => (
          <div key={s.key} className={`stat ${s.key}`}>
            <div className="num">{s.val}</div>
            <div className="label">{s.label}</div>
          </div>
        ))}
      </div>

      {/* Charts Row 1 */}
      <div className="charts">
        <div className="chart-panel">
          <div className="panel-title">● Threats by Type</div>
          <ResponsiveContainer width="100%" height={200}>
            <BarChart data={byType}>
              <XAxis dataKey="name" tick={{ fill: '#8b949e', fontSize: 10 }} />
              <YAxis tick={{ fill: '#8b949e', fontSize: 10 }} />
              <Tooltip contentStyle={{ background: '#161b22', border: '1px solid #30363d', color: '#c9d1d9' }} />
              <Bar dataKey="value" fill="#58a6ff" radius={[4, 4, 0, 0]} />
            </BarChart>
          </ResponsiveContainer>
        </div>

        <div className="chart-panel">
          <div className="panel-title">● Threats by Source</div>
          <ResponsiveContainer width="100%" height={200}>
            <PieChart>
              <Pie
                data={bySource}
                dataKey="value"
                nameKey="name"
                cx="50%"
                cy="50%"
                outerRadius={70}
                labelLine={false}
                label={CustomPieLabel}
              >
                {bySource.map((entry, index) => (
                  <Cell key={index} fill={COLORS[index % COLORS.length]} />
                ))}
              </Pie>
              <Tooltip
                contentStyle={{ background: '#161b22', border: '1px solid #30363d', color: '#c9d1d9' }}
                formatter={(value, name, props) => [`${value} (${props.payload.pct}%)`, name]}
              />
            </PieChart>
          </ResponsiveContainer>
        </div>
      </div>

      {/* Charts Row 2 */}
      <div className="charts">
        <div className="chart-panel">
          <div className="panel-title">● Top Malware Families</div>
          <ResponsiveContainer width="100%" height={200}>
            <BarChart data={malwareFamilies} layout="vertical">
              <XAxis type="number" tick={{ fill: '#8b949e', fontSize: 10 }} />
              <YAxis dataKey="name" type="category" tick={{ fill: '#8b949e', fontSize: 10 }} width={80} />
              <Tooltip contentStyle={{ background: '#161b22', border: '1px solid #30363d', color: '#c9d1d9' }} />
              <Bar dataKey="count" fill="#f85149" radius={[0, 4, 4, 0]} />
            </BarChart>
          </ResponsiveContainer>
        </div>

        <div className="chart-panel">
          <div className="panel-title">● Threat Detection Trend</div>
          <ResponsiveContainer width="100%" height={200}>
            <LineChart data={trendData}>
              <CartesianGrid strokeDasharray="3 3" stroke="#1e3a5f" />
              <XAxis dataKey="time" tick={{ fill: '#8b949e', fontSize: 10 }} />
              <YAxis tick={{ fill: '#8b949e', fontSize: 10 }} />
              <Tooltip contentStyle={{ background: '#161b22', border: '1px solid #30363d', color: '#c9d1d9' }} />
              <Line type="monotone" dataKey="threats" stroke="#3fb950" strokeWidth={2} dot={{ fill: '#3fb950' }} />
            </LineChart>
          </ResponsiveContainer>
        </div>
      </div>

      {/* Filters */}
      <div className="filters">
        <input
          className="filter-input"
          placeholder="Filter by IOC or malware..."
          value={filter}
          onChange={e => { setFilter(e.target.value); setPage(1); }}
        />
        <select className="filter-select" value={severityFilter} onChange={e => { setSeverityFilter(e.target.value); setPage(1); }}>
          <option value="">All Severity</option>
          <option value="CRITICAL">CRITICAL</option>
          <option value="HIGH">HIGH</option>
          <option value="MEDIUM">MEDIUM</option>
          <option value="LOW">LOW</option>
        </select>
        <button className="clear-btn" onClick={() => { setFilter(''); setSeverityFilter(''); setPage(1); }}>✕ Clear</button>
        <select className="filter-select" value={perPage} onChange={e => { setPerPage(Number(e.target.value)); setPage(1); }}>
          <option value={10}>Show 10</option>
          <option value={25}>Show 25</option>
          <option value={50}>Show 50</option>
        </select>
        <span className="count">Showing {filtered.length} of {threats.length}</span>
      </div>

      {/* Table */}
      <div className="table-wrap">
        {loading ? <Spinner /> : (
          <>
            <table>
              <thead>
                <tr>
                  <th>IOC</th><th>Type</th><th>Threat</th><th>Malware</th>
                  <th>Source</th><th>Severity</th><th>Risk Score</th><th>Timestamp</th>
                </tr>
              </thead>
              <tbody>
                {paginated.map((t, i) => (
                  <tr key={i}>
                    <td>
                      <span
                        className="ioc"
                        title={t.ioc}
                        onClick={() => copyIOC(t.ioc)}
                        style={{ cursor: 'pointer' }}
                      >
                        {copied === t.ioc ? '✅ Copied!' : highlight(t.ioc, filter)}
                      </span>
                    </td>
                    <td><span className="type-badge">{t.type}</span></td>
                    <td>{highlight(t.threat, filter)}</td>
                    <td>{highlight(Array.isArray(t.malware) ? t.malware.join(', ') : t.malware, filter)}</td>
                    <td>{t.source}</td>
                    <td>
                      <span className="sev-badge" style={{ color: sevColor(t.severity), borderColor: sevColor(t.severity) }}>
                        {t.severity}
                      </span>
                    </td>
                    <td style={{ color: sevColor(t.severity), fontWeight: 'bold' }}>{t.risk_score}</td>
                    <td className="ts">{t.timestamp}</td>
                  </tr>
                ))}
              </tbody>
            </table>

            {/* Pagination */}
            <div className="pagination">
              <button className="page-btn" onClick={() => setPage(1)} disabled={page === 1}>«</button>
              <button className="page-btn" onClick={() => setPage(p => Math.max(1, p - 1))} disabled={page === 1}>‹</button>
              <span className="page-info">Page {page} of {totalPages}</span>
              <button className="page-btn" onClick={() => setPage(p => Math.min(totalPages, p + 1))} disabled={page === totalPages}>›</button>
              <button className="page-btn" onClick={() => setPage(totalPages)} disabled={page === totalPages}>»</button>
            </div>
          </>
        )}
      </div>

      <footer>CTI Dashboard — Darshan B | React · Flask · OSINT APIs · ML Risk Scoring</footer>
    </div>
  );
}

export default App;
