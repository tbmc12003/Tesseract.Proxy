import { useCallback, useEffect, useState } from 'preact/hooks';
import { PublishPanel } from './publish.jsx';
import { BrokerEditor } from './editor.jsx';
import { AuditPanel } from './audit.jsx';

export function App() {
  const [tab, setTab] = useState('brokers'); // 'brokers' | 'audit'
  return (
    <div>
      <header style={hdr}>
        <h1 style={{ margin: 0, fontSize: '1.25rem' }}>
          Tesseract <span class="muted">(loopback admin)</span>
        </h1>
        <HealthBadge />
        <nav style={tabs}>
          <TabButton active={tab === 'brokers'} onClick={() => setTab('brokers')}>Brokers</TabButton>
          <TabButton active={tab === 'audit'}   onClick={() => setTab('audit')}>Audit log</TabButton>
        </nav>
      </header>
      {tab === 'brokers' ? <BrokersPane /> : <AuditPanel />}
    </div>
  );
}

// HealthBadge polls /api/proxy/health every 5 s. States:
//   ok      — 200 from the proxy
//   down    — non-200 or fetch error
//   nocfg   — admin-ui returns 424 (mTLS not wired yet)
function HealthBadge() {
  const [state, setState] = useState({ kind: 'unknown', note: 'checking…' });
  useEffect(() => {
    let stopped = false;
    async function poll() {
      try {
        const resp = await fetch('/api/proxy/health', { cache: 'no-store' });
        if (stopped) return;
        if (resp.status === 424) {
          setState({ kind: 'nocfg', note: 'mTLS to proxy not configured' });
          return;
        }
        if (resp.ok) {
          setState({ kind: 'ok', note: 'proxy OK' });
          return;
        }
        const t = await resp.text().catch(() => '');
        setState({ kind: 'down', note: `proxy ${resp.status}${t ? ': ' + t.slice(0, 80) : ''}` });
      } catch (e) {
        if (stopped) return;
        setState({ kind: 'down', note: String(e.message || e) });
      }
    }
    poll();
    const id = setInterval(poll, 5000);
    return () => { stopped = true; clearInterval(id); };
  }, []);
  const map = {
    ok:      { color: '#2a7', dot: '●' },
    down:    { color: '#c33', dot: '●' },
    nocfg:   { color: '#888', dot: '○' },
    unknown: { color: '#888', dot: '○' },
  };
  const s = map[state.kind] || map.unknown;
  return (
    <span title={state.note} style={{ color: s.color, fontSize: '0.85rem', marginLeft: '0.5rem' }}>
      {s.dot} <span class="muted" style={{ fontSize: '0.75rem' }}>proxy</span>
    </span>
  );
}

function TabButton({ active, onClick, children }) {
  return (
    <button
      onClick={onClick}
      style={{ ...tabBtn, ...(active ? tabBtnActive : null) }}
    >
      {children}
    </button>
  );
}

function BrokersPane() {
  const [brokers, setBrokers] = useState(null);
  const [err, setErr] = useState(null);
  const [selected, setSelected] = useState(null);
  const [isNew, setIsNew] = useState(false);
  const [reloadTick, setReloadTick] = useState(0);

  const reload = useCallback(() => setReloadTick((t) => t + 1), []);

  useEffect(() => {
    fetch('/api/brokers')
      .then((r) => (r.ok ? r.json() : r.json().then((j) => Promise.reject(j.error || r.statusText))))
      .then((list) => {
        setBrokers(list);
        setErr(null);
        if (!isNew && selected && !list.find((b) => b.id === selected)) {
          setSelected(list[0]?.id ?? null);
        } else if (!isNew && !selected && list.length > 0) {
          setSelected(list[0].id);
        }
      })
      .catch((e) => setErr(String(e)));
  }, [reloadTick]);

  if (err) return <div class="err">Error loading brokers: {err}</div>;
  if (!brokers) return <div>Loading brokers…</div>;

  function startNew() { setIsNew(true); setSelected(null); }
  function onSaved(id) { setIsNew(false); setSelected(id); reload(); }
  function onDeleted() { setIsNew(false); setSelected(null); reload(); }

  return (
    <div>
      <PublishPanel />
      <div style={layout}>
        <aside style={sidebar}>
          <div style={sideHdr}>
            <strong>brokers</strong>
            <button onClick={startNew} title="Add new broker">+ new</button>
          </div>
          <ul style={list}>
            {brokers.map((b) => {
              const active = !isNew && b.id === selected;
              return (
                <li
                  key={b.id}
                  style={{ ...listItem, ...(active ? listItemActive : null) }}
                  onClick={() => { setIsNew(false); setSelected(b.id); }}
                >
                  <div><code>{b.id}</code></div>
                  <div class="muted" style={{ fontSize: '0.8rem' }}>
                    {b.display_name}{b.enabled ? '' : ' · disabled'}
                  </div>
                </li>
              );
            })}
            {isNew && <li style={{ ...listItem, ...listItemActive }}><em>new broker…</em></li>}
          </ul>
        </aside>
        <main style={main}>
          {isNew ? (
            <BrokerEditor isNew onSaved={onSaved} onDeleted={onDeleted} />
          ) : selected ? (
            <BrokerEditor key={selected} name={selected} onSaved={onSaved} onDeleted={onDeleted} />
          ) : (
            <p class="muted">No broker selected. Use <strong>+ new</strong> to add one.</p>
          )}
        </main>
      </div>
    </div>
  );
}

const hdr = { display: 'flex', alignItems: 'center', gap: '1rem', marginBottom: '0.75rem' };
const tabs = { display: 'flex', gap: '0.25rem', marginLeft: 'auto' };
const tabBtn = {
  padding: '0.3rem 0.8rem', borderRadius: '0.3rem',
  border: '1px solid #8884', background: 'transparent',
  cursor: 'pointer', fontFamily: 'inherit',
};
const tabBtnActive = { background: '#0af2', borderColor: '#0af6' };
const layout = { display: 'grid', gridTemplateColumns: '14rem 1fr', gap: '1rem', marginTop: '1rem' };
const sidebar = { borderRight: '1px solid #8884', paddingRight: '0.75rem' };
const sideHdr = { display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '0.5rem' };
const list = { listStyle: 'none', padding: 0, margin: 0 };
const listItem = { padding: '0.4rem 0.6rem', cursor: 'pointer', borderRadius: '0.3rem' };
const listItemActive = { background: '#0af2', outline: '1px solid #0af6' };
const main = { minWidth: 0 };
