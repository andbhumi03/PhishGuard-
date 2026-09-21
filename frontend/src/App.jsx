import { useState } from "react";
import "./App.css";

function App() {
  const [emailText, setEmailText] = useState("");
  const [file, setFile] = useState(null);
  const [result, setResult] = useState(null);
  const [loading, setLoading] = useState(false);

  const handleFileChange = (e) => {
    setFile(e.target.files[0]);
  };

  const handleAnalyze = async () => {
    setLoading(true);
    // Fake result for now — replace with real API call once backend is ready
    setTimeout(() => {
      setResult({
        risk_level: "High",
        risk_score: 82,
        confidence: 0.91,
        reasons: [
          'Urgent language detected ("act now", "verify immediately")',
          "Sender domain does not match display name",
          "Suspicious URL found: paypa1-secure.com",
        ],
      });
      setLoading(false);
    }, 1000);
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
        onChange={(e) => setEmailText(e.target.value)}
        rows={10}
      />

      <div className="upload-row">
        <label>Or upload .eml file:</label>
        <input type="file" accept=".eml" onChange={handleFileChange} />
      </div>

      <button onClick={handleAnalyze} disabled={loading}>
        {loading ? "Analyzing..." : "Analyze"}
      </button>

      {result && (
        <div className="threat-profile">
          <h2>Threat Profile</h2>
          <p>
            <strong>Risk Level:</strong> {result.risk_level}
          </p>
          <p>
            <strong>Risk Score:</strong> {result.risk_score}/100
          </p>
          <p>
            <strong>Model Confidence:</strong>{" "}
            {(result.confidence * 100).toFixed(0)}%
          </p>
          <h3>Reasons:</h3>
          <ul>
            {result.reasons.map((r, i) => (
              <li key={i}>{r}</li>
            ))}
          </ul>
        </div>
      )}
    </div>
  );
}

export default App;
