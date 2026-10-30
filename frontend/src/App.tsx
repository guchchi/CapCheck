import { useEffect, useState } from "react";
import {
  createScan,
  getEvidence,
  getFindings,
  getHealth,
  getScan,
  getTools,
} from "./api";
import type { Evidence, Finding, ScanStatus, ToolDef } from "./types";

const POLL_INTERVAL_MS = 400;
const POLL_LIMIT = 300;
const STAGES = ["queued", "ingest", "discover", "analyze", "correlate", "complete"];

type SourceMode = "github" | "fixture";

function Stepper({ scan }: { scan: ScanStatus }) {
  const current = Math.max(0, STAGES.indexOf(scan.stage));
  return (
    <ol className="stepper">
      {STAGES.map((stage, index) => {
        let state = "todo";
        if (scan.status === "failed" && stage === scan.stage) {
          state = "failed";
        } else if (scan.status === "complete" || index < current) {
          state = "done";
        } else if (index === current) {
          state = "active";
        }
        return (
          <li key={stage} className={`step ${state}`}>
            <span className="dot" />
            {stage}
          </li>
        );
      })}
    </ol>
  );
}

export default function App() {
  const [fixtures, setFixtures] = useState<string[]>([]);
  const [mode, setMode] = useState<SourceMode>("github");
  const [repoUrl, setRepoUrl] = useState("");
  const [fixture, setFixture] = useState("exfil_server");
  const [scan, setScan] = useState<ScanStatus | null>(null);
  const [tools, setTools] = useState<ToolDef[]>([]);
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
    let status = await getScan(scanId);
    setScan(status);
    for (let attempt = 0; attempt < POLL_LIMIT; attempt += 1) {
      if (status.status === "complete" || status.status === "failed") {
        return status;
      }
      await new Promise((resolve) => setTimeout(resolve, POLL_INTERVAL_MS));
      status = await getScan(scanId);
      setScan(status);
    }
    throw new Error("Scan did not finish in time.");
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

  async function handleScan() {
    if (mode === "github" && !repoUrl.trim()) {
      setError("Enter a public GitHub repository URL.");
      return;
    }

    setBusy(true);
    setError(null);
    setScan(null);
    setTools([]);
    setFindings([]);
    setSelected(null);
    setEvidence([]);

    try {
      const created = await createScan(
        mode === "github" ? { repo_url: repoUrl.trim() } : { fixture },
      );
      const status = await poll(created.scan_id);
      if (status.status === "failed") {
        throw new Error(status.error ?? "Scan failed.");
      }
      const [toolList, result] = await Promise.all([
        getTools(created.scan_id),
        getFindings(created.scan_id),
      ]);
      setTools(toolList);
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

  return (
    <main className="shell">
      <header>
        <h1>CapCheck</h1>
        <p className="tagline">
          Evidence-driven static analysis for MCP servers. Parses source, never
          runs it.
        </p>
      </header>

      <section className="panel">
        <div className="tabs">
          <button
            className={mode === "github" ? "tab active" : "tab"}
            onClick={() => setMode("github")}
            disabled={busy}
          >
            Public GitHub repository
          </button>
          <button
            className={mode === "fixture" ? "tab active" : "tab"}
            onClick={() => setMode("fixture")}
            disabled={busy}
          >
            Local fixture
          </button>
        </div>

        {mode === "github" ? (
          <div className="row">
            <input
              className="url-input"
              type="url"
              value={repoUrl}
              placeholder="https://github.com/owner/repository"
              onChange={(event) => setRepoUrl(event.target.value)}
              onKeyDown={(event) => {
                if (event.key === "Enter" && !busy) {
                  void handleScan();
                }
              }}
              disabled={busy}
            />
            <button onClick={handleScan} disabled={busy}>
              {busy ? "Scanning…" : "Scan repository"}
            </button>
          </div>
        ) : (
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
              {busy ? "Scanning…" : "Scan fixture"}
            </button>
          </div>
        )}

        <p className="muted">
          Public repositories only. Archives are downloaded over HTTPS and
          parsed as data; no install, build or repository code is executed.
        </p>
        {error && <p className="error">{error}</p>}
      </section>

      {scan && (
        <section className="panel">
          <h2>Scan {scan.scan_id}</h2>
          <p className="source-line">
            <code>{scan.source}</code>
            {scan.commit_sha && (
              <span className="muted"> @ {scan.commit_sha.slice(0, 10)}</span>
            )}
          </p>

          <Stepper scan={scan} />

          <dl className="stats">
            <div>
              <dt>Status</dt>
              <dd>{scan.status}</dd>
            </div>
            <div>
              <dt>Languages</dt>
              <dd>{scan.languages.length ? scan.languages.join(", ") : "—"}</dd>
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

          {scan.status === "failed" && (
            <p className="error">
              {scan.error_code ? `${scan.error_code}: ` : ""}
              {scan.error}
            </p>
          )}

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

      {scan && scan.status === "complete" && (
        <section className="panel">
          <h2>MCP tools ({tools.length})</h2>
          {tools.length === 0 && (
            <p className="muted">
              No MCP tool declarations were found in the analysed source.
            </p>
          )}
          {tools.length > 0 && (
            <div className="table-wrap">
              <table className="tools">
                <thead>
                  <tr>
                    <th>Tool</th>
                    <th>Language</th>
                    <th>Declared description</th>
                    <th>Observed capabilities</th>
                    <th>Source</th>
                  </tr>
                </thead>
                <tbody>
                  {tools.map((tool) => (
                    <tr key={`${tool.source_file}:${tool.line}:${tool.name}`}>
                      <td>
                        <code>{tool.name}</code>
                        {tool.params.length > 0 && (
                          <div className="muted">{tool.params.join(", ")}</div>
                        )}
                      </td>
                      <td>{tool.language}</td>
                      <td>
                        {tool.declared_description || (
                          <span className="muted">none declared</span>
                        )}
                      </td>
                      <td>
                        {tool.observed_capabilities.length === 0 ? (
                          <span className="muted">none in handler</span>
                        ) : (
                          tool.observed_capabilities.map((capability) => (
                            <span key={capability} className="cap">
                              {capability}
                            </span>
                          ))
                        )}
                      </td>
                      <td>
                        <code>
                          {tool.source_file}:{tool.line}
                        </code>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
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
                  <span className={`sev sev-${finding.severity}`}>
                    {finding.severity}
                  </span>
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
          {!selected && (
            <p className="muted">Select a finding to inspect its evidence.</p>
          )}
          {selected && (
            <>
              <p className="muted">{selected.reason}</p>
              <p>{selected.summary}</p>
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
