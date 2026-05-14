import { useEffect, useState } from 'preact/hooks';

// Mirrors the enums in tesseract-proxy-config/schemas/bundle.schema.json.
// Server still enforces validation; this is just for dropdowns.
const METHODS = ['GET', 'POST', 'PUT', 'PATCH', 'DELETE'];
const KINDS = [
  'place', 'modify', 'cancel',
  'place_multi', 'modify_multi', 'cancel_multi',
  'place_multileg', 'exit', 'exit_positions',
  'cancel_cover', 'cancel_bracket',
];

const BROKER_ID_RE = /^[a-z][a-z0-9_]{1,31}$/;

function emptyBroker(id) {
  return {
    id,
    display_name: '',
    host: '',
    enabled: false,
    order_endpoints: [{ method: 'POST', path: '/', kind: 'place' }],
    idempotency: {
      client_order_id_header: '',
      client_order_id_body_path: '',
      echo_in_response_path: '',
    },
    rate_limit: { per_user_rps: 0, per_user_burst: 0 },
  };
}

export function BrokerEditor({ name, isNew, onSaved, onDeleted }) {
  const [obj, setObj] = useState(null);
  const [err, setErr] = useState(null);
  const [status, setStatus] = useState(null);
  const [busy, setBusy] = useState(false);
  const [dirty, setDirty] = useState(false);

  useEffect(() => {
    setErr(null);
    setStatus(null);
    setDirty(false);
    if (isNew) {
      setObj(emptyBroker(''));
      return;
    }
    setObj(null);
    fetch(`/api/brokers/${encodeURIComponent(name)}`)
      .then((r) => (r.ok ? r.json() : r.json().then((j) => Promise.reject(j.error || r.statusText))))
      .then(setObj)
      .catch((e) => setErr(String(e)));
  }, [name, isNew]);

  if (err) return <div class="err">Error: {err}</div>;
  if (!obj) return <div>Loading…</div>;

  function patch(updater) {
    setObj((prev) => {
      const next = structuredClone(prev);
      updater(next);
      return next;
    });
    setDirty(true);
    setStatus(null);
  }

  async function save() {
    setBusy(true);
    setStatus(null);
    try {
      if (isNew && !BROKER_ID_RE.test(obj.id)) {
        throw new Error('id must match ^[a-z][a-z0-9_]{1,31}$');
      }
      const url = isNew ? '/api/brokers' : `/api/brokers/${encodeURIComponent(obj.id)}`;
      const method = isNew ? 'POST' : 'PUT';
      const resp = await fetch(url, {
        method,
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(obj),
      });
      if (!resp.ok) {
        const j = await resp.json().catch(() => ({}));
        throw new Error(j.error || `HTTP ${resp.status}`);
      }
      setDirty(false);
      setStatus({ kind: 'ok', msg: 'Saved.' });
      onSaved?.(obj.id);
    } catch (e) {
      setStatus({ kind: 'err', msg: String(e.message || e) });
    } finally {
      setBusy(false);
    }
  }

  async function del() {
    if (!confirm(`Delete broker "${obj.id}"? This removes ${obj.id}.yaml from the working tree.`)) return;
    setBusy(true);
    try {
      const resp = await fetch(`/api/brokers/${encodeURIComponent(obj.id)}`, { method: 'DELETE' });
      if (!resp.ok && resp.status !== 204) {
        const j = await resp.json().catch(() => ({}));
        throw new Error(j.error || `HTTP ${resp.status}`);
      }
      onDeleted?.(obj.id);
    } catch (e) {
      setStatus({ kind: 'err', msg: String(e.message || e) });
    } finally {
      setBusy(false);
    }
  }

  return (
    <div>
      <div style={hdr}>
        <h2 style={{ margin: 0 }}>
          {isNew ? <em>new broker</em> : <code>{obj.id}</code>}
          {dirty && <span style={dirtyBadge}>unsaved</span>}
        </h2>
        <div style={{ display: 'flex', gap: '0.5rem' }}>
          <button onClick={save} disabled={busy || !dirty}>
            {busy ? 'Saving…' : isNew ? 'Create' : 'Save'}
          </button>
          {!isNew && (
            <button onClick={del} disabled={busy} style={{ color: '#c33' }}>
              Delete
            </button>
          )}
        </div>
      </div>

      {status && (
        <div class={status.kind === 'err' ? 'err' : ''} style={statusLine}>
          {status.msg}
        </div>
      )}

      <section style={section}>
        <h3 style={h3}>Identity</h3>
        <Field label="id">
          <input
            type="text"
            value={obj.id}
            disabled={!isNew}
            onInput={(e) => patch((n) => (n.id = e.currentTarget.value))}
            style={input}
          />
          {isNew && <small class="muted">^[a-z][a-z0-9_]{'{1,31}'}$</small>}
        </Field>
        <Field label="display_name">
          <input
            type="text"
            value={obj.display_name}
            onInput={(e) => patch((n) => (n.display_name = e.currentTarget.value))}
            style={input}
          />
        </Field>
        <Field label="host">
          <input
            type="text"
            value={obj.host}
            onInput={(e) => patch((n) => (n.host = e.currentTarget.value))}
            style={input}
            placeholder="api.example.com"
          />
        </Field>
        <Field label="enabled">
          <input
            type="checkbox"
            checked={!!obj.enabled}
            onChange={(e) => patch((n) => (n.enabled = e.currentTarget.checked))}
          />
        </Field>
      </section>

      <section style={section}>
        <h3 style={h3}>order_endpoints</h3>
        <table style={{ width: '100%' }}>
          <thead>
            <tr>
              <th style={{ width: '7rem' }}>method</th>
              <th>path</th>
              <th style={{ width: '11rem' }}>kind</th>
              <th style={{ width: '3rem' }}></th>
            </tr>
          </thead>
          <tbody>
            {obj.order_endpoints.map((ep, i) => (
              <tr key={i}>
                <td>
                  <select
                    value={ep.method}
                    onChange={(e) => patch((n) => (n.order_endpoints[i].method = e.currentTarget.value))}
                    style={input}
                  >
                    {METHODS.map((m) => <option value={m}>{m}</option>)}
                  </select>
                </td>
                <td>
                  <input
                    type="text"
                    value={ep.path}
                    onInput={(e) => patch((n) => (n.order_endpoints[i].path = e.currentTarget.value))}
                    style={input}
                    placeholder="/api/v3/orders"
                  />
                </td>
                <td>
                  <select
                    value={ep.kind}
                    onChange={(e) => patch((n) => (n.order_endpoints[i].kind = e.currentTarget.value))}
                    style={input}
                  >
                    {KINDS.map((k) => <option value={k}>{k}</option>)}
                  </select>
                </td>
                <td>
                  <button
                    onClick={() => patch((n) => n.order_endpoints.splice(i, 1))}
                    disabled={obj.order_endpoints.length <= 1}
                    title="Remove row"
                  >
                    ✕
                  </button>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
        <button
          onClick={() => patch((n) => n.order_endpoints.push({ method: 'POST', path: '/', kind: 'place' }))}
          style={{ marginTop: '0.5rem' }}
        >
          + Add endpoint
        </button>
      </section>

      <section style={section}>
        <h3 style={h3}>idempotency</h3>
        <Field label="client_order_id_header">
          <input
            type="text"
            value={obj.idempotency.client_order_id_header}
            onInput={(e) => patch((n) => (n.idempotency.client_order_id_header = e.currentTarget.value))}
            style={input}
            placeholder="(blank if header not used)"
          />
        </Field>
        <Field label="client_order_id_body_path">
          <input
            type="text"
            value={obj.idempotency.client_order_id_body_path}
            onInput={(e) => patch((n) => (n.idempotency.client_order_id_body_path = e.currentTarget.value))}
            style={input}
            placeholder="$.orderTag"
          />
        </Field>
        <Field label="echo_in_response_path">
          <input
            type="text"
            value={obj.idempotency.echo_in_response_path}
            onInput={(e) => patch((n) => (n.idempotency.echo_in_response_path = e.currentTarget.value))}
            style={input}
            placeholder="data.orderNumber"
          />
        </Field>
      </section>

      <section style={section}>
        <h3 style={h3}>rate_limit (advisory)</h3>
        <Field label="per_user_rps">
          <input
            type="number"
            min="0"
            value={obj.rate_limit.per_user_rps}
            onInput={(e) => patch((n) => (n.rate_limit.per_user_rps = parseInt(e.currentTarget.value, 10) || 0))}
            style={{ ...input, width: '8rem' }}
          />
        </Field>
        <Field label="per_user_burst">
          <input
            type="number"
            min="0"
            value={obj.rate_limit.per_user_burst}
            onInput={(e) => patch((n) => (n.rate_limit.per_user_burst = parseInt(e.currentTarget.value, 10) || 0))}
            style={{ ...input, width: '8rem' }}
          />
        </Field>
      </section>
    </div>
  );
}

function Field({ label, children }) {
  return (
    <div style={fieldRow}>
      <label style={fieldLbl}>{label}</label>
      <div style={{ flex: 1 }}>{children}</div>
    </div>
  );
}

const hdr = {
  display: 'flex', justifyContent: 'space-between', alignItems: 'center',
  marginBottom: '1rem',
};
const section = {
  border: '1px solid #8884', borderRadius: '0.4rem',
  padding: '0.75rem 1rem', marginBottom: '1rem',
};
const h3 = { margin: '0 0 0.6rem 0', fontSize: '0.95rem' };
const fieldRow = { display: 'flex', alignItems: 'center', gap: '0.75rem', marginBottom: '0.4rem' };
const fieldLbl = { width: '14rem', fontFamily: 'monospace', fontSize: '0.85rem' };
const input = { padding: '0.25rem 0.4rem', width: '100%', boxSizing: 'border-box', fontFamily: 'inherit' };
const dirtyBadge = {
  marginLeft: '0.6rem', fontSize: '0.7rem', padding: '0.1rem 0.4rem',
  background: '#e94', color: 'white', borderRadius: '0.2rem',
};
const statusLine = { padding: '0.4rem 0.6rem', marginBottom: '0.75rem', background: '#0001', borderRadius: '0.3rem' };
