import pandas as pd
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.model_selection import train_test_split
import pickle
import os

df = pd.read_csv("data/phishing_email.csv")

df = df.dropna(subset=["text_combined", "label"])

df = df.sample(n=8000, random_state=42)

X = df["text_combined"]
y = df["label"].map({
    1: "phishing",
    0: "legitimate"
})


X_train, X_test, y_train, y_test = train_test_split(
    X, y, test_size=0.2, random_state=42, stratify=y
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