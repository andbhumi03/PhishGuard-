# PhishGuard

An AI-assisted phishing email analysis tool. Users can paste raw email text or upload a `.eml` file, and PhishGuard extracts sender info, content, and URLs to detect phishing indicators using rule-based checks combined with a trained ML model (TF-IDF + Logistic Regression), producing an explainable
risk score.

## Tech Stack

- Frontend: React
- Backend: FastAPI (Python)
- Database: SQLite
- ML: scikit-learn (TF-IDF + Logistic Regression)

## Status

---

## Features (planned)

- Paste email or upload `.eml` file
- Sender analysis (display name mismatch, reply-to mismatch, domain checks)
- Content analysis (urgency language, credential/payment requests)
- URL analysis
- ML-based phishing prediction with confidence score
- Combined explainable risk score with reasoning
- Save and view past analyses

## Setup

_Coming soon_

## Credits

Uses scikit-learn, FastAPI, React, and a public phishing email dataset for model training.
