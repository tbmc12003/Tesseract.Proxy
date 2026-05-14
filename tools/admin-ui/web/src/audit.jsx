import { useEffect, useMemo, useRef, useState } from 'preact/hooks';

const OUTCOMES = ['forward', 'reject', 'upstream_err'];
const MAX_RECORDS = 5000;
const HISTORY_PAGE = 1000;

export function AuditPanel() {
  const [records, setRecords] = useState([]);   // append-only, capped MAX_RECORDS
  const [paused, setPaused] = useState(false);
  const [dropped, setDropped] = useState(0);
  const [conn, setConn] = useState('connecting'); // connecting | open | error | paused
  const [filters, setFilters] = useState({
    outcomes: new Set(OUTCOMES),
    broker: '',
    statusPrefix: '',
    text: '',
  });
  const [historyState, setHistoryState] = useState({ loading: false, err: null, done: false });

  // EventSource lifecycle — recreated on pause/resume.
  const esRef = useRef(null);
  useEffect(() => {
    if (paused) {
      setConn('paused');
      return;
    }
    setConn('connecting');
    const es = new EventSource('/api/audit/tail');
    esRef.current = es;
    es.onopen = () => setConn('open');
    es.onerror = () => setConn('error'); // browser auto-reconnects with Last-Event-ID
    es.onmessage = (e) => {
      try {
        const rec = JSON.parse(e.data);
        setRecords((prev) => {
          const next = prev.length >= MAX_RECORDS ? prev.slice(prev.length - MAX_RECORDS + 1) : prev.slice();
          next.push(rec);
          return next;
        });
      } catch (_) { /* malformed line — ignore */ }
    };
    es.addEventListener('dropped', (e) => {
      try {
        const d = JSON.parse(e.data);
        setDropped((n) => n + (d.count || 0));
      } catch (_) { /* ignore */ }
    });
    return () => es.close();
  }, [paused]);

  async function loadOlder() {
    setHistoryState({ loading: true, err: null, done: false });
    try {
      const oldest = records[0]?.time;
      const url = oldest
        ? `/api/audit/range?until=${encodeURIComponent(oldest)}`
        : `/api/audit/range?lines=${HISTORY_PAGE}`;
      const resp = await fetch(url);
      if (!resp.ok) {
        const j = await resp.json().catch(() => ({}));
        throw new Error(j.error || `HTTP ${resp.status}`);
      }
      const text = await resp.text();
      const lines = text.split('\n').filter((l) => l.length > 0);
      const recs = [];
      for (const l of lines) {
        try { recs.push(JSON.parse(l)); } catch (_) { /* skip */ }
      }
      setRecords((prev) => [...recs, ...prev]);
      setHistoryState({ loading: false, err: null, done: recs.length === 0 });
    } catch (e) {
      setHistoryState({ loading: false, err: String(e.message || e), done: false });
    }
  }

  function clear() {
    setRecords([]);
    setDropped(0);
    setHistoryState({ loading: false, err: null, done: false });
  }

  function toggleOutcome(o) {
    setFilters((f) => {
      const next = new Set(f.outcomes);
      next.has(o) ? next.delete(o) : next.add(o);
      return { ...f, outcomes: next };
    });
  }

  const brokers = useMemo(() => {
    const s = new Set();
    for (const r of records) if (r.broker_id) s.add(r.broker_id);
    return [...s].sort();
  }, [records]);

  const filtered = useMemo(() => {
    const text = filters.text.toLowerCase();
    return records.filter((r) => {
      if (!filters.outcomes.has(r.outcome)) return false;
      if (filters.broker && r.broker_id !== filters.broker) return false;
      if (filters.statusPrefix && !String(r.status || '').startsWith(filters.statusPrefix)) return false;
      if (text) {
        // JSON.stringify is allocation-heavy but the filtered set is at
        // most MAX_RECORDS — fine for an admin tool. Could be cached if
        // it ever shows up in profiles.
        if (!JSON.stringify(r).toLowerCase().includes(text)) return false;
      }
      return true;
    });
  }, [records, filters]);

  function exportJSON() {
    download(`audit-${stamp()}.json`, JSON.stringify(filtered, null, 2), 'application/json');
  }
  function exportCSV() {
    download(`audit-${stamp()}.csv`, toCSV(filtered), 'text/csv');
  }

  return (
    <div>
      <div style={toolbar}>
        <button onClick={() => setPaused((p) => !p)}>
          {paused ? '▶ Resume' : '⏸ Pause'}
        </button>
        <button onClick={loadOlder} disabled={historyState.loading}>
          {historyState.loading ? 'Loading…' : '↥ Load older'}
        </button>
        <button onClick={exportJSON} disabled={filtered.length === 0}>⇩ JSON</button>
        <button onClick={exportCSV} disabled={filtered.length === 0}>⇩ CSV</button>
        <button onClick={clear}>Clear</button>
        <ConnBadge state={conn} />
        {dropped > 0 && (
          <span class="err" title="The proxy dropped records because the SSE buffer filled. Resume + clear to reset.">
            dropped: {dropped}
          </span>
        )}
        <span class="muted" style={{ marginLeft: 'auto', fontSize: '0.8rem' }}>
          {filtered.length} / {records.length} records
        </span>
      </div>



      <div style={filterBar}>
        <div style={chipGroup}>
          {OUTCOMES.map((o) => {
            const on = filters.outcomes.has(o);
            return (
              <button
                key={o}
                onClick={() => toggleOutcome(o)}
                style={{ ...chip, ...(on ? chipOn[o] : chipOff) }}
                title={`Toggle ${o}`}
              >
                {o}
              </button>
            );
          })}
        </div>
        <label style={lbl}>
          broker
          <select
            value={filters.broker}
            onChange={(e) => setFilters((f) => ({ ...f, broker: e.currentTarget.value }))}
            style={smallInput}
          >
            <option value="">(any)</option>
            {brokers.map((b) => <option value={b}>{b}</option>)}
          </select>
        </label>
        <label style={lbl}>
          status
          <input
            type="text"
            placeholder="2 / 4xx / 200"
            value={filters.statusPrefix}
            onInput={(e) => setFilters((f) => ({ ...f, statusPrefix: e.currentTarget.value }))}
            style={{ ...smallInput, width: '6rem' }}
          />
        </label>
        <label style={{ ...lbl, flex: 1 }}>
          search
          <input
            type="text"
            placeholder="free-text over JSON"
            value={filters.text}
            onInput={(e) => setFilters((f) => ({ ...f, text: e.currentTarget.value }))}
            style={{ ...smallInput, width: '100%' }}
          />
        </label>
      </div>

      {historyState.err && <div class="err" style={{ marginBottom: '0.5rem' }}>history: {historyState.err}</div>}
      {historyState.done && <div class="muted" style={{ marginBottom: '0.5rem' }}>no older records returned</div>}

      <Table records={filtered} />
      <LogPanel />
    </div>
  );
}

function ConnBadge({ state }) {
  const map = {
    open:        { color: '#2a7', text: '● live' },
    connecting:  { color: '#888', text: '○ connecting' },
    paused:      { color: '#888', text: '⏸ paused' },
    error:       { color: '#c33', text: '● error (auto-reconnecting)' },
  };
  const s = map[state] || { color: '#888', text: state };
  return <span style={{ color: s.color, fontSize: '0.8rem' }}>{s.text}</span>;
}

function Table({ records }) {
  // Newest first for readability.
  const rows = useMemo(() => records.slice().reverse(), [records]);
  return (
    <div style={tableWrap}>
      <table style={{ width: '100%', fontSize: '0.82rem' }}>
        <thead>
          <tr>
            <th style={{ width: '8.5rem' }}>time</th>
            <th style={{ width: '6rem' }}>outcome</th>
            <th style={{ width: '6rem' }}>broker</th>
            <th style={{ width: '5rem' }}>method</th>
            <th>path</th>
            <th style={{ width: '4rem' }}>status</th>
            <th style={{ width: '5rem', textAlign: 'right' }}>latency</th>
          </tr>
        </thead>
        <tbody>
          {rows.map((r, i) => (
            <tr key={`${r.time}-${i}`} style={rowFor(r.outcome)}>
              <td><code>{fmtTime(r.time)}</code></td>
              <td>{r.outcome || '—'}</td>
              <td><code>{r.broker_id || ''}</code></td>
              <td>{r.method || ''}</td>
              <td style={pathCell}><code>{r.path || ''}</code></td>
              <td>{r.status || ''}</td>
              <td style={{ textAlign: 'right' }}>{r.latency_ms != null ? `${r.latency_ms}ms` : ''}</td>
            </tr>
          ))}
          {rows.length === 0 && (
            <tr><td colSpan={7} class="muted" style={{ textAlign: 'center', padding: '1rem' }}>
              No records match. Waiting for live data, or try Load older.
            </td></tr>
          )}
        </tbody>
      </table>
    </div>
  );
}

function fmtTime(s) {
  if (!s) return '';
  const d = new Date(s);
  if (isNaN(d.getTime())) return s;
  const hh = String(d.getHours()).padStart(2, '0');
  const mm = String(d.getMinutes()).padStart(2, '0');
  const ss = String(d.getSeconds()).padStart(2, '0');
  const ms = String(d.getMilliseconds()).padStart(3, '0');
  return `${hh}:${mm}:${ss}.${ms}`;
}

function rowFor(outcome) {
  if (outcome === 'reject') return { background: '#c331' };
  if (outcome === 'upstream_err') return { background: '#e941' };
  return null;
}

const toolbar = {
  display: 'flex', alignItems: 'center', gap: '0.5rem',
  marginBottom: '0.5rem', flexWrap: 'wrap',
};
const filterBar = {
  display: 'flex', alignItems: 'flex-end', gap: '0.75rem',
  marginBottom: '0.75rem', flexWrap: 'wrap',
};
const chipGroup = { display: 'flex', gap: '0.25rem' };
const chip = {
  border: '1px solid #8884', borderRadius: '999px',
  padding: '0.15rem 0.6rem', fontSize: '0.75rem',
  fontFamily: 'inherit', cursor: 'pointer',
};
const chipOff = { background: 'transparent', opacity: 0.5 };
const chipOn = {
  forward:      { background: '#2a72', borderColor: '#2a7' },
  reject:       { background: '#c332', borderColor: '#c33' },
  upstream_err: { background: '#e942', borderColor: '#e94' },
};
const lbl = {
  display: 'flex', flexDirection: 'column', fontSize: '0.7rem',
  gap: '0.15rem', color: '#888',
};
const smallInput = {
  padding: '0.2rem 0.4rem', fontFamily: 'inherit', fontSize: '0.85rem',
};
const tableWrap = {
  border: '1px solid #8884', borderRadius: '0.3rem',
  maxHeight: '60vh', overflow: 'auto',
};
const pathCell = {
  overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap',
  maxWidth: '24rem',
};

// --- Export helpers ---------------------------------------------------------

function download(name, content, mime) {
  const blob = new Blob([content], { type: mime });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = name;
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  // Give the browser a tick to start the download before revoking.
  setTimeout(() => URL.revokeObjectURL(url), 250);
}

function stamp() {
  const d = new Date();
  const pad = (n, w = 2) => String(n).padStart(w, '0');
  return `${d.getFullYear()}${pad(d.getMonth() + 1)}${pad(d.getDate())}-`
       + `${pad(d.getHours())}${pad(d.getMinutes())}${pad(d.getSeconds())}`;
}

// CSV columns mirror the table; unknown fields tucked into the last
// `raw_json` column so nothing's lost.
const CSV_COLS = ['time', 'outcome', 'broker_id', 'method', 'path', 'status', 'latency_ms'];
function toCSV(records) {
  const header = [...CSV_COLS, 'raw_json'].join(',') + '\n';
  const rows = records.map((r) => {
    const known = CSV_COLS.map((k) => csvField(r[k]));
    known.push(csvField(JSON.stringify(r)));
    return known.join(',');
  });
  return header + rows.join('\n') + (rows.length ? '\n' : '');
}
function csvField(v) {
  if (v == null) return '';
  const s = String(v);
  if (/[,"\n\r]/.test(s)) return `"${s.replace(/"/g, '""')}"`;
  return s;
}

// --- Log retention panel (R7.5) --------------------------------------------

function LogPanel() {
  const [stat, setStat] = useState(null);   // { path, size, mtime, exists }
  const [err, setErr] = useState(null);
  const [busy, setBusy] = useState(false);
  const [lastRotated, setLastRotated] = useState(null);

  async function refresh() {
    setErr(null);
    try {
      const resp = await fetch('/api/log/stat');
      const j = await resp.json();
      if (!resp.ok) throw new Error(j.error || `HTTP ${resp.status}`);
      setStat(j);
    } catch (e) {
      setErr(String(e.message || e));
    }
  }
  useEffect(() => { refresh(); }, []);

  async function rotate() {
    if (!confirm('Rotate the audit log now? The current file will be renamed and a fresh one started.')) return;
    setBusy(true);
    setErr(null);
    try {
      const resp = await fetch('/api/log/rotate', { method: 'POST' });
      const j = await resp.json();
      if (!resp.ok) throw new Error(j.error || `HTTP ${resp.status}`);
      setLastRotated(j.rotated_to);
      await refresh();
    } catch (e) {
      setErr(String(e.message || e));
    } finally {
      setBusy(false);
    }
  }

  return (
    <details style={logPanelBox}>
      <summary style={logPanelSummary}>
        <span><strong>audit log</strong> retention</span>
        <span class="muted" style={{ marginLeft: '0.75rem', fontSize: '0.8rem' }}>
          {stat ? `${fmtBytes(stat.size)} · last write ${fmtDateTime(stat.mtime)}` : 'loading…'}
        </span>
      </summary>
      <div style={{ padding: '0.5rem 0' }}>
        {err && <div class="err" style={{ marginBottom: '0.5rem' }}>{err}</div>}
        {stat && (
          <table style={{ fontSize: '0.8rem', width: '100%' }}>
            <tbody>
              <tr><td class="muted" style={cellLbl}>path</td><td><code>{stat.path}</code></td></tr>
              <tr><td class="muted" style={cellLbl}>size</td><td>{fmtBytes(stat.size)} ({stat.size} bytes)</td></tr>
              <tr><td class="muted" style={cellLbl}>mtime</td><td>{fmtDateTime(stat.mtime)}</td></tr>
              <tr><td class="muted" style={cellLbl}>exists</td><td>{String(stat.exists)}</td></tr>
            </tbody>
          </table>
        )}
        <div style={{ marginTop: '0.6rem', display: 'flex', gap: '0.5rem', alignItems: 'center' }}>
          <button onClick={rotate} disabled={busy}>
            {busy ? 'Rotating…' : 'Rotate now'}
          </button>
          <button onClick={refresh} disabled={busy}>Refresh stat</button>
          {lastRotated && (
            <span class="muted" style={{ fontSize: '0.8rem' }}>
              rotated to <code>{lastRotated}</code>
            </span>
          )}
        </div>
      </div>
    </details>
  );
}

function fmtBytes(n) {
  if (n == null || n === 0) return '0 B';
  const units = ['B', 'KB', 'MB', 'GB'];
  let i = 0;
  while (n >= 1024 && i < units.length - 1) { n /= 1024; i++; }
  return `${n.toFixed(i === 0 ? 0 : 1)} ${units[i]}`;
}
function fmtDateTime(s) {
  if (!s) return '—';
  const d = new Date(s);
  if (isNaN(d.getTime())) return s;
  return d.toLocaleString();
}

const logPanelBox = {
  border: '1px solid #8884', borderRadius: '0.3rem',
  padding: '0.5rem 0.75rem', marginTop: '0.75rem', fontSize: '0.85rem',
};
const logPanelSummary = {
  cursor: 'pointer', display: 'flex', alignItems: 'center',
};
const cellLbl = { width: '5rem', paddingRight: '0.5rem', verticalAlign: 'top' };
