import { useState } from "react";
import "./App.css";
const API_BASE = "http://localhost:8000";
function App() {
  const [emailText, setEmailText] = useState("");
  const [file, setFile] = useState(null);
  const [result, setResult] = useState(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);
  const handleFileChange = (e) => {
    setFile(e.target.files[0] || null);
    setEmailText(""); // clear text if a file is chosen
  };
  const handleTextChange = (e) => {
    setEmailText(e.target.value);
    setFile(null); // clear file if text is typed
  };
  const handleAnalyze = async () => {
    setError(null);
    setResult(null);
    if (!emailText && !file) {
      setError("Please paste an email or upload a .eml file.");
      return;
    }
    setLoading(true);
    try {
      let response;
      if (file) {
        const formData = new FormData();
        formData.append("file", file);
        response = await fetch(`${API_BASE}/analyze/eml`, {
          method: "POST",
          body: formData,
        });
      } else {
        response = await fetch(`${API_BASE}/analyze/text`, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ raw_text: emailText }),
        });
      }
      if (!response.ok) {
        throw new Error(`Server error: ${response.status}`);
      }
      const data = await response.json();
      setResult(data);
    } catch (err) {
      setError(`Failed to analyze: ${err.message}. Is the backend running?`);
    } finally {
      setLoading(false);
    }
  };
  const riskLevel = result?.risk_analysis?.risk_level?.toLowerCase() || "";
  const riskScore = result?.risk_analysis?.risk_score ?? 0;
  const mlConfidence = result?.ml_analysis?.ml_confidence ?? 0;
  const reasons = result?.risk_analysis?.reasons || [];
  return (
    <div className="app-shell">
      <header className="topbar">
        <a className="brand" href="/" aria-label="PhishGuard home">
          <span className="brand-mark">P</span>
          <span>PhishGuard</span>
        </a>
        <div className="status-pill">
          <span className="status-dot" /> Scanner ready
        </div>
      </header>

      <main className="app">
        <section className="intro">
          <div>
            <p className="eyebrow">Email threat intelligence</p>
            <h1>Inspect before you trust.</h1>
            <p className="intro-copy">
              Analyze suspicious messages for phishing signals, risky links, and
              social engineering patterns.
            </p>
          </div>
          <div className="shield-badge" aria-hidden="true">
            PG
          </div>
        </section>

        <section className="workspace-grid">
          <div className="panel analyze-panel">
            <div className="panel-heading">
              <div>
                <p className="section-kicker">New scan</p>
                <h2>Analyze an email</h2>
              </div>
              <span className="step-label">01 / INPUT</span>
            </div>

            <label className="field-label" htmlFor="email-content">
              Raw email content
            </label>
            <textarea
              id="email-content"
              placeholder="Paste the full email, including headers if available..."
              value={emailText}
              onChange={handleTextChange}
              rows={11}
            />

            <div className="or-divider">
              <span>or</span>
            </div>

            <label
              className={`file-drop ${file ? "has-file" : ""}`}
              htmlFor="email-file"
            >
              <span className="upload-icon">+</span>
              <span className="file-copy">
                <strong>{file ? file.name : "Upload an .eml file"}</strong>
                <small>
                  {file
                    ? "Ready to analyze"
                    : "Choose a saved email from your device"}
                </small>
              </span>
              <span className="browse-label">Browse</span>
              <input
                id="email-file"
                type="file"
                accept=".eml"
                onChange={handleFileChange}
              />
            </label>

            <button
              className="analyze-button"
              onClick={handleAnalyze}
              disabled={loading}
            >
              <span>{loading ? "Analyzing message" : "Run security scan"}</span>
              <span className="button-arrow">-&gt;</span>
            </button>

            {error && (
              <p className="error-message" role="alert">
                {error}
              </p>
            )}
          </div>

          <aside className="panel guide-panel">
            <p className="section-kicker">What we check</p>
            <h2>Signals that matter</h2>
            <div className="signal-list">
              <div className="signal-item">
                <span className="signal-number">01</span>
                <span>
                  <strong>Sender identity</strong>
                  <small>Display name and domain mismatches</small>
                </span>
              </div>
              <div className="signal-item">
                <span className="signal-number">02</span>
                <span>
                  <strong>Link safety</strong>
                  <small>Insecure and lookalike destinations</small>
                </span>
              </div>
              <div className="signal-item">
                <span className="signal-number">03</span>
                <span>
                  <strong>Language patterns</strong>
                  <small>Urgency and sensitive data requests</small>
                </span>
              </div>
            </div>
            <div className="privacy-note">
              <span className="lock-mark">*</span>
              <span>Analysis stays on your local PhishGuard service.</span>
            </div>
          </aside>
        </section>

        {result && (
          <section className="results-section">
            <div className="results-heading">
              <div>
                <p className="section-kicker">Scan complete</p>
                <h2>Threat profile</h2>
              </div>
              <span className={`result-tag ${riskLevel}`}>
                {riskLevel || "unknown"} risk
              </span>
            </div>
            <div className="result-grid">
              <div className={`score-card ${riskLevel}`}>
                <div className="score-ring">
                  <span>{Math.round(riskScore)}</span>
                  <small>/100</small>
                </div>
                <div>
                  <p className="score-label">Overall risk score</p>
                  <strong>
                    {result.risk_analysis.risk_level} risk detected
                  </strong>
                </div>
              </div>
              <div className="metric-card">
                <span>Model verdict</span>
                <strong>{result.ml_analysis.ml_prediction}</strong>
                <small>{(mlConfidence * 100).toFixed(0)}% confidence</small>
              </div>
              <div className="metric-card">
                <span>Sender</span>
                <strong>
                  {result.parsed_email.sender_name || "Unknown sender"}
                </strong>
                <small>
                  {result.parsed_email.sender_email || "No address found"}
                </small>
              </div>
            </div>
            <div className="details-grid">
              <div className="detail-block">
                <p className="detail-label">Message details</p>
                <div className="detail-row">
                  <span>Subject</span>
                  <strong>
                    {result.parsed_email.subject || "No subject found"}
                  </strong>
                </div>
                <div className="detail-row">
                  <span>Reply-to</span>
                  <strong>
                    {result.parsed_email.reply_to || "Not provided"}
                  </strong>
                </div>
              </div>
              <div className="detail-block">
                <p className="detail-label">Why this was flagged</p>
                {reasons.length ? (
                  <ul className="reason-list">
                    {reasons.map((reason, index) => (
                      <li key={`${reason}-${index}`}>{reason}</li>
                    ))}
                  </ul>
                ) : (
                  <p className="clear-message">
                    No suspicious signals were detected.
                  </p>
                )}
              </div>
            </div>
          </section>
        )}
      </main>
      <footer className="footer">
        <span>PHISHGUARD SECURITY TOOL</span>
        <span>Built for safer inboxes</span>
      </footer>
    </div>
  );
}

export default App;
