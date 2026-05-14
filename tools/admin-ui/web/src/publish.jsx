import { useState } from 'preact/hooks';

const REQUIRED = 'DEPLOY';

export function PublishPanel() {
  const [open, setOpen] = useState(false);
  const [phrase, setPhrase] = useState('');
  const [running, setRunning] = useState(false);
  const [log, setLog] = useState('');
  const [done, setDone] = useState(null); // null | 'ok' | 'err'

  function close() {
    if (running) return;
    setOpen(false);
    setPhrase('');
    setLog('');
    setDone(null);
  }

  async function run() {
    setRunning(true);
    setLog('');
    setDone(null);
    try {
      const resp = await fetch('/api/publish', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ confirm: phrase }),
      });
      if (!resp.ok && resp.headers.get('content-type')?.includes('application/json')) {
        const j = await resp.json();
        setLog(`HTTP ${resp.status}: ${j.error || resp.statusText}\n`);
        setDone('err');
        setRunning(false);
        return;
      }
      const reader = resp.body.getReader();
      const dec = new TextDecoder();
      let buf = '';
      for (;;) {
        const { value, done: streamDone } = await reader.read();
        if (streamDone) break;
        buf += dec.decode(value, { stream: true });
        setLog(buf);
      }
      setDone(buf.includes('FAILED') ? 'err' : 'ok');
    } catch (e) {
      setLog((l) => l + `\nclient error: ${e}\n`);
      setDone('err');
    } finally {
      setRunning(false);
    }
  }

  if (!open) {
    return (
      <button onClick={() => setOpen(true)} style={{ marginBottom: '1rem' }}>
        Publish to Lightsail…
      </button>
    );
  }

  return (
    <div style={modalBackdrop} onClick={close}>
      <div style={modal} onClick={(e) => e.stopPropagation()}>
        <h2 style={{ marginTop: 0 }}>Publish broker bundle</h2>
        <p>
          This will run <code>build-bundle</code> and{' '}
          <code>reload-bundle.sh</code> against the configured Lightsail
          host. Type <code>{REQUIRED}</code> to confirm.
        </p>
        <input
          type="text"
          value={phrase}
          onInput={(e) => setPhrase(e.currentTarget.value)}
          disabled={running}
          autoFocus
          placeholder={REQUIRED}
          style={{ width: '100%', padding: '0.4rem', fontFamily: 'monospace' }}
        />
        <div style={{ marginTop: '0.75rem', display: 'flex', gap: '0.5rem' }}>
          <button onClick={close} disabled={running}>Cancel</button>
          <button
            onClick={run}
            disabled={running || phrase !== REQUIRED}
          >
            {running ? 'Publishing…' : 'Publish'}
          </button>
          {done === 'ok' && <span style={{ color: 'green' }}>✓ complete</span>}
          {done === 'err' && <span class="err">✗ failed</span>}
        </div>
        {log && (
          <pre style={logBox}>{log}</pre>
        )}
      </div>
    </div>
  );
}

const modalBackdrop = {
  position: 'fixed', inset: 0, background: '#0008',
  display: 'flex', alignItems: 'flex-start', justifyContent: 'center',
  paddingTop: '4rem', zIndex: 10,
};
const modal = {
  background: 'Canvas', color: 'CanvasText', padding: '1.25rem',
  borderRadius: '0.5rem', width: 'min(48rem, 90vw)',
  boxShadow: '0 10px 40px #0006',
};
const logBox = {
  marginTop: '1rem', maxHeight: '24rem', overflow: 'auto',
  background: '#0001', padding: '0.75rem', fontSize: '0.8rem',
  whiteSpace: 'pre-wrap', wordBreak: 'break-word',
};
