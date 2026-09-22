import pandas as pd

df = pd.read_csv("data/phishing_email.csv")

print(df.columns.tolist())
print(df["label"].value_counts())