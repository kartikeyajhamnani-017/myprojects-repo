import joblib
import numpy as np
import math
from sklearn.ensemble import IsolationForest

# The file where we save the trained brain
MODEL_FILE = "isolation_forest.pkl"

class MLModel:
    def __init__(self):
        self.model = None
        self.load_model()

    def load_model(self):
        """Attempts to load the pre-trained model."""
        try:
            self.model = joblib.load(MODEL_FILE)
            print("🧠 ML Model loaded successfully.")
        except FileNotFoundError:
            print(f"⚠️  No model found at {MODEL_FILE}. Run train_model.py first!")
            self.model = None

    def extract_features(self, payload):
        """
        Converts text payload into 3 numerical features:
        1. Length
        2. Entropy (Randomness)
        3. Special Character Ratio
        """
        # Feature 1: Length
        length = len(payload)
        
        # Feature 2: Shannon Entropy
        if length == 0:
            entropy = 0
        else:
            prob = [float(payload.count(c)) / length for c in dict.fromkeys(list(payload))]
            entropy = - sum([p * math.log(p) / math.log(2.0) for p in prob])

        # Feature 3: Special Char Ratio
        special_chars = set("!@#$%^&*()[]{};:'\"<>,./?\\|`~-_=+")
        special_count = sum(1 for char in payload if char in special_chars)
        ratio = special_count / length if length > 0 else 0

        # Return as a 2D array (required by sklearn)
        return np.array([[length, entropy, ratio]])

    def predict(self, payload):
        """
        Returns:
        -1 if Anomaly (Threat)
         1 if Normal (Safe)
        """
        if self.model is None:
            return 1 # Fail safe: assume normal if no brain exists
        
        features = self.extract_features(payload)
        prediction = self.model.predict(features)
        return prediction[0]