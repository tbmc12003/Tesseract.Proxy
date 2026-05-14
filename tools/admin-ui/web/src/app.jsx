import { useEffect, useState } from 'preact/hooks';

export function App() {
  const [brokers, setBrokers] = useState(null);
  const [err, setErr] = useState(null);

  useEffect(() => {
    fetch('/api/brokers')
      .then((r) => (r.ok ? r.json() : r.json().then((j) => Promise.reject(j.error || r.statusText))))
      .then(setBrokers)
      .catch((e) => setErr(String(e)));
  }, []);

  if (err) return <div class="err">Error: {err}</div>;
  if (!brokers) return <div>Loading brokers…</div>;

  return (
    <div>
      <h1>Tesseract — Brokers <span class="muted">(loopback admin)</span></h1>
      <table>
        <thead>
          <tr>
            <th>id</th>
            <th>display name</th>
            <th>enabled</th>
          </tr>
        </thead>
        <tbody>
          {brokers.map((b) => (
            <tr key={b.id}>
              <td><code>{b.id}</code></td>
              <td>{b.display_name}</td>
              <td>{b.enabled ? 'yes' : 'no'}</td>
            </tr>
          ))}
        </tbody>
      </table>
      <p class="muted">CRUD UI lands in R6.4. This screen is the R6.1 smoke test.</p>
    </div>
  );
}
