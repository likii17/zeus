import pandas as pd
import matplotlib.pyplot as plt
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.svm import SVC
from sklearn.pipeline import Pipeline
from sklearn.metrics import classification_report, accuracy_score, confusion_matrix

df = pd.read_csv("/kaggle/input/phishingemails/Phishing_Email.csv")
df = df.dropna()

email_type_counts = df['Email Type'].value_counts()
unique_email_types = email_type_counts.index.tolist()
color_map = {'Phishing Email': 'red', 'Safe Email': 'green'}
colors = [color_map.get(email_type, 'gray') for email_type in unique_email_types]

plt.figure(figsize=(8, 6))
plt.bar(unique_email_types, email_type_counts, color=colors)
plt.xlabel('Email Type')
plt.ylabel('Count')
plt.title('Distribution of Email Types with Custom Colors')
plt.xticks(rotation=45)
plt.tight_layout()
plt.show()

Safe_Email = df[df["Email Type"] == "Safe Email"]
Phishing_Email = df[df["Email Type"] == "Phishing Email"]
Safe_Email = Safe_Email.sample(Phishing_Email.shape[0])
Data = pd.concat([Safe_Email, Phishing_Email], ignore_index=True)

X = Data["Email Text"].values
y = Data["Email Type"].values
X_train, x_test, y_train, y_test = train_test_split(X, y, test_size=0.3, random_state=0)

classifier = Pipeline([("tfidf", TfidfVectorizer()), ("classifier", RandomForestClassifier(n_estimators=10))])
classifier.fit(X_train, y_train)
y_pred = classifier.predict(x_test)

print("RandomForestClassifier Accuracy:", accuracy_score(y_test, y_pred))
print("Confusion Matrix:\n", confusion_matrix(y_test, y_pred))
print("Classification Report:\n", classification_report(y_test, y_pred))

SVM = Pipeline([("tfidf", TfidfVectorizer()), ("SVM", SVC(C=100, gamma="auto"))])
SVM.fit(X_train, y_train)
s_ypred = SVM.predict(x_test)
print("SVM Accuracy:", accuracy_score(y_test, s_ypred))
