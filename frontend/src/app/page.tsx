"use client";

import { FormEvent, useCallback, useEffect, useMemo, useRef, useState } from "react";

type Vulnerability = {
  id: number;
  name: string;
  severity: string;
  endpoint?: string | null;
  payload?: string | null;
  confidence?: string | null;
  evidence?: string | null;
  explanation?: string | null;
  remediation?: string | null;
  owasp_category?: string | null;
};

type ScanSummary = {
  id: number;
  target_url: string;
  status: string;
  score?: number | null;
  created_at: string;
  completed_at?: string | null;
};

type ScanDetail = ScanSummary & {
  vulnerabilities: Vulnerability[];
};

type ProgressEvent = {
  scan_id: number;
  status: string;
  progress: number;
  message: string;
};

type AuthMode = "login" | "register";

type AuthToken = {
  access_token: string;
  token_type: string;
  expires_in: number;
};

type AISummary = {
  executive_summary: string;
  risk_rating: string;
  key_findings: string;
  top_risks: string[];
  immediate_actions: string[];
};

const API_BASE = process.env.NEXT_PUBLIC_API_BASE_URL ?? "http://localhost:8000";
const TOKEN_STORAGE_KEY = "scanner_access_token";

function buildApiUrl(path: string, tokenForQuery?: string) {
  const normalized = path.startsWith("/") ? path : `/${path}`;
  const url = new URL(`${API_BASE}${normalized}`);
  if (tokenForQuery) {
    url.searchParams.set("token", tokenForQuery);
  }
  return url.toString();
}

function authHeaders(token: string, includeJsonContentType = false): Headers {
  const headers = new Headers();
  headers.set("Authorization", `Bearer ${token}`);
  if (includeJsonContentType) {
    headers.set("Content-Type", "application/json");
  }
  return headers;
}

function formatDate(value?: string | null) {
  if (!value) return "-";
  const d = new Date(value);
  if (Number.isNaN(d.getTime())) return value;
  return d.toLocaleString();
}

function scoreClass(score?: number | null) {
  if (score == null) return "pill-neutral";
  if (score >= 80) return "pill-safe";
  if (score >= 60) return "pill-watch";
  return "pill-risk";
}

export default function Home() {
  const [authMode, setAuthMode] = useState<AuthMode>("login");
  const [username, setUsername] = useState("");
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [token, setToken] = useState<string>("");
  const [authLoading, setAuthLoading] = useState(false);
  const [targetUrl, setTargetUrl] = useState("");
  const [scans, setScans] = useState<ScanSummary[]>([]);
  const [selectedScanId, setSelectedScanId] = useState<number | null>(null);
  const [selectedScan, setSelectedScan] = useState<ScanDetail | null>(null);
  const [progressEvent, setProgressEvent] = useState<ProgressEvent | null>(null);
  const [loadingScans, setLoadingScans] = useState(false);
  const [creatingScan, setCreatingScan] = useState(false);
  const [downloadingPdf, setDownloadingPdf] = useState(false);
  const [loadingAiSummary, setLoadingAiSummary] = useState(false);
  const [aiSummary, setAiSummary] = useState<AISummary | null>(null);
  const [stoppingScans, setStoppingScans] = useState<Set<number>>(new Set());
  const [error, setError] = useState<string | null>(null);
  const streamRef = useRef<EventSource | null>(null);

  useEffect(() => {
    const existing = window.localStorage.getItem(TOKEN_STORAGE_KEY) || "";
    if (existing) setToken(existing);
  }, []);

  const onAuthSubmit = useCallback(async (event: FormEvent) => {
    event.preventDefault();
    setError(null);
    setAuthLoading(true);

    try {
      if (authMode === "register") {
        const registerRes = await fetch(buildApiUrl("/api/auth/register"), {
          method: "POST",
          headers: new Headers({ "Content-Type": "application/json" }),
          body: JSON.stringify({
            username: username.trim(),
            email: email.trim(),
            password,
          }),
        });
        if (!registerRes.ok) {
          throw new Error("Registration failed. Try a different username/email.");
        }
      }

      const loginRes = await fetch(buildApiUrl("/api/auth/login"), {
        method: "POST",
        headers: new Headers({ "Content-Type": "application/json" }),
        body: JSON.stringify({ username: username.trim(), password }),
      });

      if (!loginRes.ok) {
        throw new Error("Invalid credentials.");
      }

      const data = (await loginRes.json()) as AuthToken;
      window.localStorage.setItem(TOKEN_STORAGE_KEY, data.access_token);
      setToken(data.access_token);
      setPassword("");
      setEmail("");
      setAuthMode("login");
    } catch (e) {
      const message = e instanceof Error ? e.message : "Authentication failed";
      setError(message);
    } finally {
      setAuthLoading(false);
    }
  }, [authMode, email, password, username]);

  const onLogout = useCallback(() => {
    window.localStorage.removeItem(TOKEN_STORAGE_KEY);
    streamRef.current?.close();
    setToken("");
    setScans([]);
    setSelectedScanId(null);
    setSelectedScan(null);
    setProgressEvent(null);
  }, []);

  const selectedStatus = selectedScan?.status ?? "idle";

  const userScanNumberById = useMemo(() => {
    const ordered = [...scans].sort(
      (a, b) => new Date(a.created_at).getTime() - new Date(b.created_at).getTime(),
    );
    const result = new Map<number, number>();
    ordered.forEach((scan, idx) => {
      result.set(scan.id, idx + 1);
    });
    return result;
  }, [scans]);

  const progress = useMemo(() => {
    if (!selectedScanId || progressEvent?.scan_id !== selectedScanId) {
      return selectedStatus === "completed" ? 100 : 0;
    }
    return progressEvent.progress;
  }, [selectedScanId, progressEvent, selectedStatus]);

  const loadScans = useCallback(async () => {
    if (!token) return;
    setLoadingScans(true);
    try {
      const res = await fetch(buildApiUrl("/api/scans"), {
        cache: "no-store",
        headers: authHeaders(token),
      });
      if (res.status === 401) {
        onLogout();
        throw new Error("Session expired. Please login again.");
      }
      if (!res.ok) throw new Error("Could not load scans");
      const data = (await res.json()) as ScanSummary[];
      setScans(data);

      setSelectedScanId((current) => current ?? (data[0]?.id ?? null));
    } catch (e) {
      const message = e instanceof Error ? e.message : "Unknown error";
      setError(message);
    } finally {
      setLoadingScans(false);
    }
  }, [token, onLogout]);

  const loadScanDetails = useCallback(async (scanId: number) => {
    if (!token) return;
    try {
      const res = await fetch(buildApiUrl(`/api/scans/${scanId}`), {
        cache: "no-store",
        headers: authHeaders(token),
      });
      if (res.status === 401) {
        onLogout();
        throw new Error("Session expired. Please login again.");
      }
      if (!res.ok) throw new Error("Could not load scan details");
      const data = (await res.json()) as ScanDetail;
      setSelectedScan(data);
      if (data.status === "completed" || data.status === "failed") {
        streamRef.current?.close();
      }
    } catch (e) {
      const message = e instanceof Error ? e.message : "Unknown error";
      setError(message);
    }
  }, [token, onLogout]);

  const openProgressStream = useCallback((scanId: number) => {
    if (!token) return;
    streamRef.current?.close();

    const stream = new EventSource(buildApiUrl(`/api/scans/${scanId}/progress`, token));
    streamRef.current = stream;

    stream.onmessage = (event) => {
      const data = JSON.parse(event.data) as ProgressEvent;
      setProgressEvent(data);

      if (data.status === "completed" || data.status === "failed" || data.status === "cancelled") {
        stream.close();
        void loadScans();
        void loadScanDetails(scanId);
      }
    };

    stream.onerror = () => {
      stream.close();
    };
  }, [loadScanDetails, loadScans, token]);

  const onCreateScan = useCallback(async (event: FormEvent) => {
    event.preventDefault();
    if (!token) return;
    if (!targetUrl.trim()) return;

    setCreatingScan(true);
    setError(null);

    try {
      const res = await fetch(buildApiUrl("/api/scans"), {
        method: "POST",
        headers: authHeaders(token, true),
        body: JSON.stringify({ target_url: targetUrl.trim() }),
      });

      if (res.status === 401) {
        onLogout();
        throw new Error("Session expired. Please login again.");
      }

      if (!res.ok) {
        throw new Error("Failed to start scan. Check the target URL.");
      }

      const scan = (await res.json()) as ScanDetail;
      setTargetUrl("");
      setSelectedScanId(scan.id);
      setSelectedScan(scan);
      setProgressEvent({
        scan_id: scan.id,
        status: "pending",
        progress: 0,
        message: "Scan queued",
      });

      await loadScans();
      openProgressStream(scan.id);
    } catch (e) {
      const message = e instanceof Error ? e.message : "Unknown error";
      setError(message);
    } finally {
      setCreatingScan(false);
    }
  }, [loadScans, openProgressStream, onLogout, targetUrl, token]);

  const onDownloadPdf = useCallback(async () => {
    if (!token) return;
    if (!selectedScan || selectedScan.status !== "completed") {
      return;
    }

    setDownloadingPdf(true);
    setError(null);

    try {
      const response = await fetch(buildApiUrl(`/api/scans/${selectedScan.id}/report/pdf`), {
        headers: authHeaders(token),
      });
      if (response.status === 401) {
        onLogout();
        throw new Error("Session expired. Please login again.");
      }
      if (!response.ok) {
        throw new Error("Could not generate the PDF report.");
      }

      const blob = await response.blob();
      const objectUrl = window.URL.createObjectURL(blob);
      const anchor = document.createElement("a");
      anchor.href = objectUrl;
      anchor.download = `scan_${selectedScan.id}_report.pdf`;
      document.body.appendChild(anchor);
      anchor.click();
      anchor.remove();
      window.URL.revokeObjectURL(objectUrl);
    } catch (e) {
      const message = e instanceof Error ? e.message : "Unknown error";
      setError(message);
    } finally {
      setDownloadingPdf(false);
    }
  }, [selectedScan, token, onLogout]);

  const onGenerateAiSummary = useCallback(async () => {
    if (!token || !selectedScan || selectedScan.status !== "completed") {
      return;
    }

    setLoadingAiSummary(true);
    setError(null);

    try {
      const response = await fetch(buildApiUrl(`/api/scans/${selectedScan.id}/ai-summary`), {
        headers: authHeaders(token),
      });

      if (response.status === 401) {
        onLogout();
        throw new Error("Session expired. Please login again.");
      }
      if (!response.ok) {
        let detail = "Could not generate AI triage summary.";
        try {
          const body = (await response.json()) as { detail?: string };
          if (body?.detail) {
            detail = body.detail;
          }
        } catch {
          // Ignore parse errors and keep generic message.
        }
        throw new Error(detail);
      }

      const data = (await response.json()) as AISummary;
      setAiSummary(data);
    } catch (e) {
      const message = e instanceof Error ? e.message : "Unknown error";
      setError(message);
    } finally {
      setLoadingAiSummary(false);
    }
  }, [onLogout, selectedScan, token]);

  const onCancelScan = useCallback(async () => {
    if (!token || !selectedScan) {
      return;
    }

    const scanId = selectedScan.id;
    setStoppingScans((prev) => new Set(prev).add(scanId));
    setError(null);

    try {
      const response = await fetch(buildApiUrl(`/api/scans/${scanId}`), {
        method: "DELETE",
        headers: authHeaders(token),
      });

      if (response.status === 401) {
        onLogout();
        throw new Error("Session expired. Please login again.");
      }

      if (!response.ok) {
        const text = await response.text();
        let errorMsg = "Could not cancel scan.";
        try {
          const body = JSON.parse(text) as { detail?: string };
          if (body?.detail) {
            errorMsg = body.detail;
          }
        } catch {
          // Keep generic message
        }
        throw new Error(errorMsg);
      }

      // Refresh scan details to update status
      void loadScanDetails(scanId);
    } catch (e) {
      const message = e instanceof Error ? e.message : "Unknown error";
      setError(message);
    } finally {
      setStoppingScans((prev) => {
        const next = new Set(prev);
        next.delete(scanId);
        return next;
      });
    }
  }, [token, selectedScan, onLogout, loadScanDetails]);

  useEffect(() => {
    if (!token) return;
    void loadScans();
  }, [loadScans, token]);

  useEffect(() => {
    if (!token) return;
    if (!selectedScanId) return;
    void loadScanDetails(selectedScanId);
  }, [selectedScanId, loadScanDetails, token]);

  useEffect(() => {
    if (!token) return;
    if (!selectedScanId || !selectedScan) return;
    if (selectedScan.status === "pending" || selectedScan.status === "scanning") {
      openProgressStream(selectedScanId);
    }
  }, [selectedScanId, selectedScan, openProgressStream, token]);

  useEffect(() => {
    setAiSummary(null);
  }, [selectedScanId]);

  useEffect(() => {
    return () => {
      streamRef.current?.close();
    };
  }, []);

  if (!token) {
    return (
      <div className="app-shell">
        <main className="dashboard">
          <header className="hero">
            <p className="kicker">SECURE ACCESS</p>
            <h1>Sign In To Scanner</h1>
            <p className="hero-subtext">Create an account or login to access your private scan workspace.</p>
          </header>

          <section className="panel launch-panel" style={{ maxWidth: "560px" }}>
            <form className="scan-form" onSubmit={onAuthSubmit}>
              <label htmlFor="username">Username</label>
              <input
                id="username"
                type="text"
                value={username}
                onChange={(e) => setUsername(e.target.value)}
                required
              />

              {authMode === "register" ? (
                <>
                  <label htmlFor="email">Email</label>
                  <input
                    id="email"
                    type="email"
                    value={email}
                    onChange={(e) => setEmail(e.target.value)}
                    required
                  />
                </>
              ) : null}

              <label htmlFor="password">Password</label>
              <input
                id="password"
                type="password"
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                minLength={8}
                required
              />

              <div className="input-row">
                <button type="submit" disabled={authLoading}>
                  {authLoading ? "Please wait..." : authMode === "login" ? "Login" : "Create Account"}
                </button>
                <button
                  type="button"
                  className="secondary-button"
                  onClick={() => setAuthMode((prev) => (prev === "login" ? "register" : "login"))}
                >
                  {authMode === "login" ? "Switch to Register" : "Switch to Login"}
                </button>
              </div>
            </form>
            {error ? <p className="error-text">{error}</p> : null}
          </section>
        </main>
      </div>
    );
  }

  return (
    <div className="app-shell">
      <div className="ambient ambient-left" aria-hidden="true" />
      <div className="ambient ambient-right" aria-hidden="true" />

      <main className="dashboard">
        <header className="hero">
          <p className="kicker">WEB APP SECURITY WORKBENCH</p>
          <h1>Vulnerability Scanner</h1>
          <p className="hero-subtext">
            Launch scans, monitor progress in real time, and review actionable findings from your backend engine.
          </p>
          <div style={{ marginTop: "0.8rem" }}>
            <button type="button" className="secondary-button" onClick={onLogout}>Logout</button>
          </div>
        </header>

        <section className="panel launch-panel">
          <form className="scan-form" onSubmit={onCreateScan}>
            <label htmlFor="targetUrl">Target URL</label>
            <div className="input-row">
              <input
                id="targetUrl"
                type="url"
                placeholder="https://example.com"
                value={targetUrl}
                onChange={(e) => setTargetUrl(e.target.value)}
                required
              />
              <button type="submit" disabled={creatingScan}>
                {creatingScan ? "Starting..." : "Start Scan"}
              </button>
            </div>
          </form>
          {error ? <p className="error-text">{error}</p> : null}
        </section>

        <section className="content-grid">
          <aside className="panel history-panel">
            <div className="panel-title-row">
              <h2>Scan History</h2>
              {loadingScans ? <span className="tiny">Refreshing...</span> : null}
            </div>

            {scans.length === 0 ? (
              <p className="empty-state">No scans yet. Start one above.</p>
            ) : (
              <ul className="scan-list">
                {scans.map((scan) => (
                  <li key={scan.id}>
                    <button
                      className={`scan-item ${scan.id === selectedScanId ? "active" : ""}`}
                      onClick={() => setSelectedScanId(scan.id)}
                      type="button"
                    >
                      <div>
                        <p className="tiny">Scan #{userScanNumberById.get(scan.id) ?? "-"}</p>
                        <p className="scan-target">{scan.target_url}</p>
                        <p className="tiny">Created: {formatDate(scan.created_at)}</p>
                      </div>
                      <div className="scan-meta">
                        <span className={`status-badge status-${scan.status}`}>{scan.status}</span>
                        <span className={`score-pill ${scoreClass(scan.score)}`}>
                          {scan.score == null ? "n/a" : `${scan.score}/100`}
                        </span>
                      </div>
                    </button>
                  </li>
                ))}
              </ul>
            )}
          </aside>

          <section className="panel detail-panel">
            {!selectedScan ? (
              <p className="empty-state">Select a scan to view details.</p>
            ) : (
              <>
                <div className="detail-header">
                  <h2>Scan #{userScanNumberById.get(selectedScan.id) ?? selectedScan.id}</h2>
                  <span className={`status-badge status-${selectedScan.status}`}>
                    {selectedScan.status}
                  </span>
                </div>

                <p className="scan-target inline">{selectedScan.target_url}</p>

                <div className="metrics-grid">
                  <article>
                    <h3>Security Score</h3>
                    <p className={`score-value ${scoreClass(selectedScan.score)}`}>
                      {selectedScan.score == null ? "Pending" : `${selectedScan.score}/100`}
                    </p>
                  </article>
                  <article>
                    <h3>Issues Found</h3>
                    <p className="count-value">{selectedScan.vulnerabilities.length}</p>
                  </article>
                  <article>
                    <h3>Completed</h3>
                    <p className="tiny">{formatDate(selectedScan.completed_at)}</p>
                  </article>
                </div>

                <div className="progress-block">
                  <div className="panel-title-row">
                    <h3>Live Progress</h3>
                    <span className="tiny">{progress}%</span>
                  </div>
                  <div className="progress-track">
                    <div className="progress-fill" style={{ width: `${progress}%` }} />
                  </div>
                  <p className="tiny">
                    {progressEvent?.scan_id === selectedScan.id
                      ? progressEvent.message
                      : "Waiting for update..."}
                  </p>
                </div>

                <div className="panel-title-row findings-heading">
                  <h3>Findings</h3>
                  <div className="action-row">
                    {(selectedScan.status === "pending" ||
                      selectedScan.status === "crawling" ||
                      selectedScan.status === "scanning") && (
                      <button
                        type="button"
                        className="secondary-button danger-button"
                        disabled={stoppingScans.has(selectedScan.id)}
                        onClick={() => {
                          void onCancelScan();
                        }}
                      >
                        {stoppingScans.has(selectedScan.id) ? "Stopping..." : "Stop Scan"}
                      </button>
                    )}
                    <button
                      type="button"
                      className="secondary-button"
                      disabled={selectedScan.status !== "completed" || loadingAiSummary}
                      onClick={() => {
                        void onGenerateAiSummary();
                      }}
                    >
                      {loadingAiSummary ? "Analyzing..." : "Generate AI Triage"}
                    </button>
                    <button
                      type="button"
                      className="secondary-button"
                      disabled={selectedScan.status !== "completed" || downloadingPdf}
                      onClick={() => {
                        void onDownloadPdf();
                      }}
                    >
                      {downloadingPdf ? "Preparing PDF..." : "Download PDF"}
                    </button>
                  </div>
                </div>

                {aiSummary ? (
                  <section className="ai-summary-panel">
                    <div className="panel-title-row">
                      <h3>AI Triage Highlights</h3>
                    </div>

                    <div className="risk-rating-box">
                      <strong>Overall Risk Rating:</strong>
                      <span className={`risk-badge risk-${aiSummary.risk_rating.toLowerCase()}`}>
                        {aiSummary.risk_rating}
                      </span>
                    </div>

                    <div className="summary-section">
                      <h4>Executive Summary</h4>
                      <p>{aiSummary.executive_summary}</p>
                    </div>

                    {aiSummary.key_findings ? (
                      <div className="findings-section">
                        <h4>Key Findings</h4>
                        <p>{aiSummary.key_findings}</p>
                      </div>
                    ) : null}

                    {aiSummary.top_risks.length > 0 ? (
                      <div className="risks-section">
                        <h4>Top Security Risks</h4>
                        <ul className="ai-points risk-list">
                          {aiSummary.top_risks.map((risk, idx) => (
                            <li key={`risk-${idx}`}>{risk}</li>
                          ))}
                        </ul>
                      </div>
                    ) : null}

                    {aiSummary.immediate_actions.length > 0 ? (
                      <div className="actions-section immediate">
                        <h4>Immediate Actions</h4>
                        <ul className="ai-points action-list">
                          {aiSummary.immediate_actions.map((action, idx) => (
                            <li key={`immediate-${idx}`}>{action}</li>
                          ))}
                        </ul>
                      </div>
                    ) : null}
                  </section>
                ) : null}

                {selectedScan.vulnerabilities.length === 0 ? (
                  <p className="empty-state slim">No vulnerabilities recorded for this scan.</p>
                ) : (
                  <ul className="findings-list">
                    {selectedScan.vulnerabilities.map((v) => (
                      <li key={v.id} className="finding-item">
                        <div className="finding-head">
                          <strong>{v.name}</strong>
                          <div className="finding-badges">
                            <span className={`severity severity-${v.severity.toLowerCase()}`}>{v.severity}</span>
                            {v.confidence ? (
                              <span className={`confidence confidence-${v.confidence.toLowerCase()}`}>{v.confidence} confidence</span>
                            ) : null}
                          </div>
                        </div>
                        <p className="tiny">Endpoint: {v.endpoint || "N/A"}</p>
                        {v.payload ? <p className="tiny">Payload: {v.payload}</p> : null}
                        {v.evidence ? <p className="tiny">Evidence: {v.evidence}</p> : null}
                        {v.owasp_category ? <p className="tiny">OWASP: {v.owasp_category}</p> : null}
                        {v.explanation ? <p>{v.explanation}</p> : null}
                        {v.remediation ? <p className="remediation">Fix: {v.remediation}</p> : null}
                      </li>
                    ))}
                  </ul>
                )}
              </>
            )}
          </section>
        </section>
      </main>
    </div>
  );
}
