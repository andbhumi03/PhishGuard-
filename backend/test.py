import requests

with open("test_email.eml", "rb") as f:
    response = requests.post(
        "http://localhost:8000/analyze/eml",
        files={"file": ("test_email.eml", f, "message/rfc822")}
    )

print(response.status_code)
print(response.json())