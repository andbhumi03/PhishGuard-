from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
import re
from email import message_from_string
from email.utils import parseaddr
from fastapi import FastAPI, UploadFile, File
from urllib.parse import urlparse
import difflib
import pickle
from database import SessionLocal, Analysis, URLRecord, ReasonRecord
app = FastAPI()
with open("models/phishing_model.pkl", "rb") as f:
    ml_model = pickle.load(f)

with open("models/vectorizer.pkl", "rb") as f:
    ml_vectorizer = pickle.load(f)

def check_rules(parsed_email: dict):
    """
    Runs simple rule-based checks on the parsed email.
    Returns a score (points added per suspicious signal) and a list of reasons.
    """
    score = 0
    reasons = []

    sender_name = parsed_email.get("sender_name", "").lower()
    sender_email = parsed_email.get("sender_email", "").lower()
    reply_to = parsed_email.get("reply_to", "").lower()
    subject = parsed_email.get("subject", "").lower()
    body = parsed_email.get("body", "").lower()

    # 1. Sender display name mentions a known brand but domain doesn't match
    known_brands = ["paypal", "amazon", "microsoft", "google", "apple", "netflix", "bank"]
    for brand in known_brands:
        if brand in sender_name and brand not in sender_email:
            score += 25
            reasons.append(f"Sender display name mentions '{brand}' but email domain does not match")
            break

    # 2. Reply-To domain differs from From domain
    if reply_to:
        sender_domain = sender_email.split("@")[-1] if "@" in sender_email else ""
        reply_domain = reply_to.split("@")[-1] if "@" in reply_to else reply_to
        if sender_domain and reply_domain and sender_domain != reply_domain:
            score += 20
            reasons.append("Reply-To domain differs from sender's domain")

    # 3. Urgent / pressure language
    urgency_phrases = [
        "act now", "urgent", "immediately", "account will be suspended",
        "verify your account", "your account has been", "click here now",
        "limited time", "act fast", "final notice"
    ]
    for phrase in urgency_phrases:
        if phrase in body or phrase in subject:
            score += 15
            reasons.append(f"Urgent/pressure language detected: \"{phrase}\"")
            break

    # 4. Credential or payment request language
    credential_phrases = [
        "enter your password", "confirm your password", "otp", "one-time password",
        "enter your pin", "confirm your card", "banking details", "ssn", "social security"
    ]
    for phrase in credential_phrases:
        if phrase in body:
            score += 25
            reasons.append(f"Requests sensitive information: \"{phrase}\"")
            break

    # 5. Free email domain used for a "business" sender
    free_domains = ["gmail.com", "yahoo.com", "outlook.com", "hotmail.com"]
    if any(sender_email.endswith(fd) for fd in free_domains) and any(b in sender_name for b in known_brands):
        score += 15
        reasons.append("Claims to be a company but uses a free/personal email domain")

    return {
        "rule_score": min(score, 100),
        "reasons": reasons,
    }
def check_urls(urls: list, sender_domain: str = ""):
    score = 0
    reasons = []
    url_details = []

    known_brands = ["paypal", "amazon", "microsoft", "google", "apple", "netflix", "facebook", "instagram"]

    for url in urls:
        parsed = urlparse(url)
        domain = parsed.netloc.lower()
        is_suspicious = False
        reason = None

        # Skip harsh flagging if the URL's domain matches the sender's own domain
        # (e.g. an email from devpost.com linking to devpost.com is normal)
        is_internal_link = sender_domain and sender_domain in domain

        # 1. Not using HTTPS — only flag strongly if NOT an internal link
        if parsed.scheme != "https" and not is_internal_link:
            score += 15
            reason = "URL does not use HTTPS"
            is_suspicious = True
            reasons.append(f"Insecure link (no HTTPS): {url}")
        elif parsed.scheme != "https" and is_internal_link:
            score += 3  # minor point, not a big red flag for internal links
            reasons.append(f"Note: internal link uses HTTP not HTTPS: {url}")

        # 2 & 3. Lookalike/brand checks stay the same (still important even for internal links)
        for brand in known_brands:
            similarity = difflib.SequenceMatcher(None, brand, domain.replace(".com", "").split(".")[0]).ratio()
            if brand not in domain and similarity > 0.7:
                score += 30
                is_suspicious = True
                reasons.append(f"Suspicious lookalike domain: {domain} (mimics '{brand}')")
                break

        for brand in known_brands:
            if brand in domain and domain != f"{brand}.com" and domain != f"www.{brand}.com":
                score += 20
                is_suspicious = True
                reasons.append(f"Domain mimics '{brand}' with extra text: {domain}")
                break

        url_details.append({
            "url": url,
            "domain": domain,
            "uses_https": parsed.scheme == "https",
            "is_suspicious": is_suspicious,
            "reason": reason,
        })

    return {
        "url_score": min(score, 100),
        "reasons": reasons,
        "url_details": url_details,
    }
def predict_phishing(body_text: str):
    """
    Uses the trained ML model to predict phishing probability
    based on the email body text.
    """
    text_vector = ml_vectorizer.transform([body_text])
    prediction = ml_model.predict(text_vector)[0]
    probabilities = ml_model.predict_proba(text_vector)[0]

    # Get confidence for the predicted class
    class_index = list(ml_model.classes_).index(prediction)
    confidence = probabilities[class_index]

    return {
        "ml_prediction": prediction,
        "ml_confidence": round(float(confidence), 2),
    }
# Allow frontend (React on localhost:5173) to call this backend
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

class EmailTextInput(BaseModel):
    raw_text: str

def extract_urls(text: str):
    url_pattern = r'https?://[^\s<>"\']+'
    return re.findall(url_pattern, text)

def parse_email_text(raw_text: str):
    """
    Parses raw email text (can be plain pasted text or a real raw email
    with headers). Falls back gracefully if headers aren't present.
    """
    gmail_match = re.search(
        r"^\s*###\s*(.*?)\s*<([^<>\s@]+@[^<>\s]+)>\s*$",
        raw_text,
        re.MULTILINE,
    )
    if gmail_match:
        sender_name = gmail_match.group(1).strip()
        sender_email = gmail_match.group(2).strip()
        copied_text = raw_text[:gmail_match.start()] + raw_text[gmail_match.end():]
        subject_match = re.search(r"^\s*Subject:\s*(.+?)\s*$", copied_text, re.MULTILINE | re.IGNORECASE)
        subject = subject_match.group(1).strip() if subject_match else ""
        if subject_match:
            copied_text = copied_text[:subject_match.start()] + copied_text[subject_match.end():]
        body = copied_text.strip()
        return {
            "sender_name": sender_name,
            "sender_email": sender_email,
            "reply_to": "",
            "subject": subject,
            "body": body,
            "urls": [url.rstrip(").,;]") for url in extract_urls(body)],
        }

    msg = message_from_string(raw_text)
    from_header = msg.get("From", "")
    reply_to = msg.get("Reply-To", "")
    subject = msg.get("Subject", "")
    sender_name, sender_email = parseaddr(from_header)
    # Try to get body; if no proper MIME structure, treat whole input as body
    if msg.is_multipart():
        body = ""
        for part in msg.walk():
            if part.get_content_type() == "text/plain":
                body += part.get_payload(decode=True).decode(errors="ignore")
    else:
        body = msg.get_payload()
        if not body:
            body = raw_text  # fallback: no headers at all, treat as plain pasted text
    urls = extract_urls(body)
    return {
        "sender_name": sender_name,
        "sender_email": sender_email,
        "reply_to": reply_to,
        "subject": subject,
        "body": body.strip(),
        "urls": urls,
    }
def combine_risk_score(rule_result: dict, url_result: dict, ml_result: dict):
    """
    Combines rule-based score, URL score, and ML prediction into a
    single explainable risk score and level.
    """
    rule_score = rule_result.get("rule_score", 0)
    url_score = url_result.get("url_score", 0)

    ml_prediction = ml_result.get("ml_prediction", "legitimate")
    ml_confidence = ml_result.get("ml_confidence", 0)

    # Convert ML result into a 0-100 contribution
    if ml_prediction == "phishing":
        ml_score = ml_confidence * 100
    else:
        ml_score = (1 - ml_confidence) * 100

    # Weighted combination: rules 35%, URL 25%, ML 40%
    final_score = (rule_score * 0.35) + (url_score * 0.25) + (ml_score * 0.40)
    final_score = round(min(final_score, 100), 1)

    if final_score >= 60:
        risk_level = "High"
    elif final_score >= 30:
        risk_level = "Medium"
    else:
        risk_level = "Low"

    # Combine all reasons from rules and URL analysis
    all_reasons = rule_result.get("reasons", []) + url_result.get("reasons", [])

    # Add an ML-based reason too, for transparency
    if ml_prediction == "phishing":
        all_reasons.append(
            f"ML model classified this as phishing with {round(ml_confidence * 100)}% confidence"
        )
    else:
        all_reasons.append(
            f"ML model classified this as legitimate with {round(ml_confidence * 100)}% confidence"
        )

    return {
        "risk_score": final_score,
        "risk_level": risk_level,
        "reasons": all_reasons,
    }
def save_analysis(source_type, parsed, risk_result, ml_result, url_result):
    db = SessionLocal()
    try:
        analysis = Analysis(
            source_type=source_type,
            sender_name=parsed.get("sender_name", ""),
            sender_email=parsed.get("sender_email", ""),
            subject=parsed.get("subject", ""),
            body=parsed.get("body", ""),
            risk_score=risk_result.get("risk_score", 0),
            risk_level=risk_result.get("risk_level", ""),
            ml_prediction=ml_result.get("ml_prediction", ""),
            ml_confidence=ml_result.get("ml_confidence", 0),
        )
        db.add(analysis)
        db.commit()
        db.refresh(analysis)

        for url_item in url_result.get("url_details", []):
            db.add(URLRecord(
                analysis_id=analysis.id,
                url=url_item.get("url", ""),
                domain=url_item.get("domain", ""),
                uses_https=str(url_item.get("uses_https", False)),
                is_suspicious=str(url_item.get("is_suspicious", False)),
            ))

        for reason in risk_result.get("reasons", []):
            db.add(ReasonRecord(analysis_id=analysis.id, message=reason))

        db.commit()
        return analysis.id
    finally:
        db.close()
@app.get("/")
def root():
    return {"message": "PhishGuard backend running"}
@app.get("/analyses")
def list_analyses():
    db = SessionLocal()
    try:
        results = db.query(Analysis).order_by(Analysis.created_at.desc()).all()
        return [
            {
                "id": a.id,
                "sender_email": a.sender_email,
                "subject": a.subject,
                "risk_score": a.risk_score,
                "risk_level": a.risk_level,
                "created_at": a.created_at.isoformat(),
            }
            for a in results
        ]
    finally:
        db.close()
@app.post("/analyze/text")
def analyze_text(input_data: EmailTextInput):
    parsed = parse_email_text(input_data.raw_text)
    rule_result = check_rules(parsed)
    sender_domain = parsed.get("sender_email", "").split("@")[-1] if "@" in parsed.get("sender_email", "") else ""
    url_result = check_urls(parsed.get("urls", []), sender_domain)
    ml_result = predict_phishing(parsed.get("body", ""))
    risk_result = combine_risk_score(rule_result, url_result, ml_result)
    analysis_id = save_analysis("paste", parsed, risk_result, ml_result, url_result)
    return {
        "status": "parsed",
        "analysis_id": analysis_id,
        "parsed_email": parsed,
        "rule_analysis": rule_result,
        "url_analysis": url_result,
        "ml_analysis": ml_result,
        "risk_analysis": risk_result,
    }


@app.post("/analyze/eml")
async def analyze_eml(file: UploadFile = File(...)):
    contents = await file.read()
    raw_text = contents.decode(errors="ignore")
    parsed = parse_email_text(raw_text)
    rule_result = check_rules(parsed)
    url_result = check_urls(parsed.get("urls", []))
    ml_result = predict_phishing(parsed.get("body", ""))
    risk_result = combine_risk_score(rule_result, url_result, ml_result)

    analysis_id = save_analysis("eml", parsed, risk_result, ml_result, url_result)

    return {
        "status": "parsed",
        "filename": file.filename,
        "analysis_id": analysis_id,
        "parsed_email": parsed,
        "rule_analysis": rule_result,
        "url_analysis": url_result,
        "ml_analysis": ml_result,
        "risk_analysis": risk_result,
    }