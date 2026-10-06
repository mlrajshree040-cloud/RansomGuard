import os
import joblib
import numpy as np
from ransomguard.logger import log


MODEL_PATH = os.path.join(os.path.dirname(__file__), "ransomguard_model.pkl")


class MLDetector:
    """
    Wraps the trained Random Forest classifier.
    Uses predict_proba to get confidence, and triggers when > threshold.
    """

    def __init__(self, threshold=0.8):
        self.threshold = threshold
        self.model = None
        self._load()

    def _load(self):
        if not os.path.exists(MODEL_PATH):
            log.warning(
                f"[MLDetector] Model not found at {MODEL_PATH}. "
                f"Run: python -m ml.generate_dataset && python -m ml.train_model"
            )
            return
        try:
            self.model = joblib.load(MODEL_PATH)
            log.info(f"[MLDetector] Loaded model from {MODEL_PATH}")
        except Exception as e:
            log.error(f"[MLDetector] Failed to load model: {e}")

    def is_ready(self):
        return self.model is not None

    def predict(self, features):
        """
        features: list of 6 floats from FeatureExtractor.extract()
        Returns: dict(prob, verdict, confidence)
        """
        if not self.is_ready():
            return {"prob": 0.0, "verdict": "UNKNOWN", "confidence": 0.0}

        try:
            X = np.array(features, dtype=float).reshape(1, -1)
            prob = float(self.model.predict_proba(X)[0][1])  # P(ransomware)
        except Exception as e:
            log.error(f"[MLDetector] Predict failed: {e}")
            return {"prob": 0.0, "verdict": "ERROR", "confidence": 0.0}

        if prob >= self.threshold:
            verdict = "RANSOMWARE"
        elif prob >= 0.5:
            verdict = "SUSPICIOUS"
        else:
            verdict = "BENIGN"

        return {
            "prob": round(prob, 4),
            "verdict": verdict,
            "confidence": round(prob if prob >= 0.5 else 1 - prob, 4),
        }