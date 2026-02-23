import numpy as np
import joblib
from sklearn.ensemble import IsolationForest
from model import MLModel

# 1. Initialize
ml = MLModel()
print("🏋️  Training the Sentinel Brain...")

# 2. Generate Dummy "Normal" Traffic (The Baseline)
# We pretend normal users look like this:
normal_payloads = [
    "user_login=admin", "page=dashboard", "action=view_report",
    "search=red_shoes", "user_id=1024", "session_id=A8291",
    "item=laptop&qty=1", "newsletter=subscribe", "home_page",
    "contact_us_form", "about_us", "terms_of_service"
]

# Create 100 variations of normal traffic
training_data = []
for p in normal_payloads:
    training_data.append(ml.extract_features(p)[0]) # Extract features

# Add some random noise to make it robust
for _ in range(50):
    # Random normal-ish looking vector
    training_data.append([10 + np.random.randint(0, 20), 2.5 + np.random.rand(), 0.1 + np.random.rand()*0.1])

X_train = np.array(training_data)

# 3. Train Isolation Forest
# contamination=0.01 means we assume 1% of our training data might be bad (outliers)
clf = IsolationForest(n_estimators=100, contamination=0.01, random_state=42)
clf.fit(X_train)

# 4. Save the Brain
joblib.dump(clf, "isolation_forest.pkl")
print(f"✅ Model trained on {len(X_train)} inputs and saved to 'isolation_forest.pkl'")