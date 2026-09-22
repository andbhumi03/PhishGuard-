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
    setFile(e.target.files[0]);
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

  return (
    <div className="app">
      <h1>PhishGuard</h1>
      <p>
        Paste an email or upload a .eml file to analyze it for phishing
        indicators.
      </p>

      <textarea
        placeholder="Paste raw email text here..."
        value={emailText}
        onChange={handleTextChange}
        rows={10}
      />

      <div className="upload-row">
        <label>Or upload .eml file:</label>
        <input type="file" accept=".eml" onChange={handleFileChange} />
        {file && <span> Selected: {file.name}</span>}
      </div>

      <button onClick={handleAnalyze} disabled={loading}>
        {loading ? "Analyzing..." : "Analyze"}
      </button>

      {error && <p style={{ color: "red" }}>{error}</p>}

      {result && (
        <div className="threat-profile">
          <h2>Threat Profile</h2>
          <p>
            <strong>Risk Level:</strong> {result.risk_analysis.risk_level}
          </p>
          <p>
            <strong>Risk Score:</strong> {result.risk_analysis.risk_score}/100
          </p>
          <p>
            <strong>ML Prediction:</strong> {result.ml_analysis.ml_prediction} (
            {(result.ml_analysis.ml_confidence * 100).toFixed(0)}% confidence)
          </p>

          <h3>Sender Info</h3>
          <p>
            <strong>From:</strong> {result.parsed_email.sender_name} &lt;
            {result.parsed_email.sender_email}&gt;
          </p>
          <p>
            <strong>Subject:</strong> {result.parsed_email.subject}
          </p>

          <h3>Reasons</h3>
          <ul>
            {result.risk_analysis.reasons.map((r, i) => (
              <li key={i}>{r}</li>
            ))}
          </ul>
        </div>
      )}
    </div>
  );
}

export default App;
