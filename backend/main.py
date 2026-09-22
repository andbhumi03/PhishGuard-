from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
import re
from email import message_from_string
from email.utils import parseaddr
from fastapi import FastAPI, UploadFile, File
app = FastAPI()

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
    return {
        "status": "parsed",
        "parsed_email": parsed,
    }
@app.post("/analyze/eml")
async def analyze_eml(file: UploadFile = File(...)):
    contents = await file.read()
    raw_text = contents.decode(errors="ignore")
    parsed = parse_email_text(raw_text)
    return {
        "status": "parsed",
        "filename": file.filename,
        "parsed_email": parsed,
    }