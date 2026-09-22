from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
import re
from email import message_from_string
from email.utils import parseaddr
from fastapi import FastAPI, UploadFile, File
app = FastAPI()
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

# Allow frontend (React on localhost:5173) to call this backend
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  
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

@app.get("/")
def root():
    return {"message": "PhishGuard backend running"}
@app.post("/analyze/text")
def analyze_text(input_data: EmailTextInput):
    parsed = parse_email_text(input_data.raw_text)
    rule_result = check_rules(parsed)
    return {
        "status": "parsed",
        "parsed_email": parsed,
        "rule_analysis": rule_result,
    }
@app.post("/analyze/eml")
async def analyze_eml(file: UploadFile = File(...)):
    contents = await file.read()
    raw_text = contents.decode(errors="ignore")
    parsed = parse_email_text(raw_text)
    rule_result = check_rules(parsed)
    return {
        "status": "parsed",
        "filename": file.filename,
        "parsed_email": parsed,
        "rule_analysis": rule_result,
    }