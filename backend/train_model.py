import pandas as pd
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.model_selection import train_test_split
import pickle
import os

# Small built-in dataset (phishing + legitimate email samples)
data = {
    "text": [
        "Your account will be suspended. Click here to verify immediately.",
        "Urgent: your password has expired, confirm your password now.",
        "Dear customer, your bank account has been locked. Verify your identity.",
        "Congratulations! You've won a prize. Click here to claim now.",
        "Your PayPal account requires immediate verification. Act now.",
        "Update your billing information immediately or lose access.",
        "Confirm your OTP to avoid account suspension.",
        "Your Netflix subscription payment failed. Update card details now.",
        "Security alert: unusual login detected. Verify your account now.",
        "Click here to reset your password within 24 hours.",
        "Your Amazon order could not be delivered. Confirm your address now.",
        "Final notice: your account will be permanently closed today.",
        "Verify your Apple ID immediately to avoid suspension.",
        "You have a pending refund. Click to claim your money now.",
        "Your account has been compromised, reset your password immediately.",
        "Hi, here are the notes from today's meeting. Let me know if I missed anything.",
        "Reminder: team meeting scheduled for tomorrow at 10 AM.",
        "Thanks for your email, I'll get back to you by Friday.",
        "Please find attached the quarterly report for review.",
        "Happy birthday! Hope you have a great day.",
        "Can we reschedule our call to next week?",
        "Here's the invoice for last month's services.",
        "Looking forward to catching up over coffee soon.",
        "The project deadline has been moved to next Monday.",
        "Please review the attached document and share your feedback.",
        "Your flight booking confirmation for next week is attached.",
        "Reminder to submit your timesheet by end of day.",
        "Great meeting you at the conference last week!",
        "The office will be closed for the holiday on Friday.",
        "Attached is the presentation for tomorrow's meeting.",
    ],
    "label": [
        "phishing", "phishing", "phishing", "phishing", "phishing",
        "phishing", "phishing", "phishing", "phishing", "phishing",
        "phishing", "phishing", "phishing", "phishing", "phishing",
        "legitimate", "legitimate", "legitimate", "legitimate", "legitimate",
        "legitimate", "legitimate", "legitimate", "legitimate", "legitimate",
        "legitimate", "legitimate", "legitimate", "legitimate", "legitimate",
    ]
}

df = pd.DataFrame(data)

X_train, X_test, y_train, y_test = train_test_split(
    df["text"], df["label"], test_size=0.2, random_state=42
)

vectorizer = TfidfVectorizer()
X_train_tfidf = vectorizer.fit_transform(X_train)
X_test_tfidf = vectorizer.transform(X_test)

model = LogisticRegression()
model.fit(X_train_tfidf, y_train)

accuracy = model.score(X_test_tfidf, y_test)
print(f"Model trained. Test accuracy: {accuracy:.2f}")

os.makedirs("models", exist_ok=True)

with open("models/phishing_model.pkl", "wb") as f:
    pickle.dump(model, f)

with open("models/vectorizer.pkl", "wb") as f:
    pickle.dump(vectorizer, f)

print("Model and vectorizer saved to models/")