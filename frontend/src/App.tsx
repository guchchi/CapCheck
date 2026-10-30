import { useEffect, useState } from "react";
import { createScan, getEvidence, getFindings, getHealth, getScan } from "./api";
import type { Evidence, Finding, ScanStatus } from "./types";

const POLL_INTERVAL_MS = 400;
const POLL_LIMIT = 50;

export default function App() {
  const [fixtures, setFixtures] = useState<string[]>([]);
  const [fixture, setFixture] = useState("exfil_server");
  const [scan, setScan] = useState<ScanStatus | null>(null);
  const [findings, setFindings] = useState<Finding[]>([]);
  const [selected, setSelected] = useState<Finding | null>(null);
  const [evidence, setEvidence] = useState<Evidence[]>([]);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    getHealth()
      .then((health) => {
        setFixtures(health.fixtures);
        if (health.fixtures.length > 0 && !health.fixtures.includes("exfil_server")) {
          setFixture(health.fixtures[0]);
        }
      })
      .catch((err: Error) => setError(err.message));
  }, []);

  async function poll(scanId: string): Promise<ScanStatus> {
    for (let attempt = 0; attempt < POLL_LIMIT; attempt += 1) {
      const status = await getScan(scanId);
      setScan(status);
      if (status.status === "complete" || status.status === "failed") {
        return status;
      }
      await new Promise((resolve) => setTimeout(resolve, POLL_INTERVAL_MS));
    }
    throw new Error("Scan did not finish in time.");
  }

  async function handleScan() {
    setBusy(true);
    setError(null);
    setFindings([]);
    setSelected(null);
    setEvidence([]);
    try {
      const created = await createScan(fixture);
      const status = await poll(created.scan_id);
      if (status.status === "failed") {
        throw new Error(status.error ?? "Scan failed.");
      }
      const result = await getFindings(created.scan_id);
      setFindings(result);
      if (result.length > 0) {
        await selectFinding(created.scan_id, result[0]);
      }
    } catch (err) {
      setError((err as Error).message);
    } finally {
      setBusy(false);
    }
  }

  async function selectFinding(scanId: string, finding: Finding) {
    setSelected(finding);
    try {
      const items = await Promise.all(
        finding.evidence_ids.map((id) => getEvidence(scanId, id)),
      );
      setEvidence(items);
    } catch (err) {
      setError((err as Error).message);
    }
  }

  return (
    <main className="shell">
      <header>
        <h1>CapCheck</h1>
        <p className="tagline">
          Evidence-driven static analysis for MCP servers. Parses source, never runs it.
        </p>
      </header>

      <section className="panel">
        <label htmlFor="fixture">Local fixture (development)</label>
        <div className="row">
          <select
            id="fixture"
            value={fixture}
            onChange={(event) => setFixture(event.target.value)}
            disabled={busy}
          >
            {fixtures.map((name) => (
              <option key={name} value={name}>
                {name}
              </option>
            ))}
          </select>
          <button onClick={handleScan} disabled={busy || fixtures.length === 0}>
            {busy ? "Scanning…" : "Scan"}
          </button>
        </div>
        {error && <p className="error">{error}</p>}
      </section>

      {scan && (
        <section className="panel">
          <h2>Scan {scan.scan_id}</h2>
          <dl className="stats">
            <div>
              <dt>Status</dt>
              <dd>{scan.status}</dd>
            </div>
            <div>
              <dt>Stage</dt>
              <dd>{scan.stage}</dd>
            </div>
            <div>
              <dt>Files</dt>
              <dd>{scan.files_scanned}</dd>
            </div>
            <div>
              <dt>Tools</dt>
              <dd>{scan.tool_count}</dd>
            </div>
            <div>
              <dt>Findings</dt>
              <dd>{scan.finding_count}</dd>
            </div>
            <div>
              <dt>Critical</dt>
              <dd>{scan.critical_count}</dd>
            </div>
          </dl>

          {scan.risk && (
            <div className="risk">
              <strong>
                Risk {scan.risk.score}/100 — {scan.risk.band}
              </strong>
              <p className="muted">{scan.risk.method}</p>
            </div>
          )}
        </section>
      )}

      <div className="columns">
        <section className="panel">
          <h2>Findings</h2>
          {findings.length === 0 && <p className="muted">No findings.</p>}
          <ul className="findings">
            {findings.map((finding) => (
              <li key={finding.id}>
                <button
                  className={selected?.id === finding.id ? "finding active" : "finding"}
                  onClick={() => scan && selectFinding(scan.scan_id, finding)}
                >
                  <span className={`sev sev-${finding.severity}`}>{finding.severity}</span>
                  <span className="rule">{finding.rule_id}</span>
                  <span className="title">{finding.title}</span>
                  <span className="confidence">confidence {finding.confidence}</span>
                </button>
              </li>
            ))}
          </ul>
        </section>

        <section className="panel">
          <h2>Evidence</h2>
          {!selected && <p className="muted">Select a finding to inspect its evidence.</p>}
          {selected && (
            <>
              <p className="muted">{selected.reason}</p>
              {evidence.map((item) => (
                <article key={item.id} className="evidence">
                  <header>
                    <code>
                      {item.path}:{item.line_start}
                    </code>
                    <span className="muted"> {item.extractor}</span>
                  </header>
                  <pre>{item.snippet}</pre>
                </article>
              ))}
            </>
          )}
        </section>
      </div>
    </main>
  );
}
