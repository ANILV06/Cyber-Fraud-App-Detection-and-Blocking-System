import pandas as pd
from sklearn.ensemble import RandomForestClassifier, GradientBoostingClassifier
from sklearn.svm import SVC
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score
import joblib
from utils import extract_features

# Load dataset
df = pd.read_csv("urls.csv")

# Extract features
X = df["url"].apply(extract_features).tolist()
y = df["label"]

# Train/test split
X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)

# Initialize models
rf = RandomForestClassifier()
svm = SVC(probability=True)
gb = GradientBoostingClassifier()

# Train models
rf.fit(X_train, y_train)
svm.fit(X_train, y_train)
gb.fit(X_train, y_train)

# Evaluate
print("Random Forest Accuracy:", accuracy_score(y_test, rf.predict(X_test)))
print("SVM Accuracy:", accuracy_score(y_test, svm.predict(X_test)))
print("Gradient Boosting Accuracy:", accuracy_score(y_test, gb.predict(X_test)))

# Save models
joblib.dump(rf, "ml/rf_model.pkl")
joblib.dump(svm, "ml/svm_model.pkl")
joblib.dump(gb, "ml/gb_model.pkl")
