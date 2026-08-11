from __future__ import annotations

from pathlib import Path

import joblib
import numpy as np

from .features import FEATURE_NAMES
from .flows import Flow
from .rules import RuleEngine


class Detector:
    def __init__(self, model_path: str = "models/nids_model.joblib",
                 threshold: float = 0.65):
        self.model_path = Path(model_path)
        self.threshold = threshold
        self.model = joblib.load(self.model_path) if self.model_path.exists() else None
        self.rules = RuleEngine()

    def predict(self, flow: Flow, features: dict[str, float]) -> tuple[str | None, float, str | None]:
        rule_type, rule_confidence, reason = self.rules.inspect(flow)
        if rule_type:
            return rule_type, rule_confidence, f"rule: {reason}"
        if self.model is None:
            return None, 0.0, "model not trained; run scripts/train.py"
        vector = np.asarray([[features[name] for name in FEATURE_NAMES]], dtype=float)
        label = str(self.model.predict(vector)[0])
        confidence = float(max(self.model.predict_proba(vector)[0]))
        if label.lower() in {"benign", "normal", "0"} or confidence < self.threshold:
            return None, confidence, "classified as benign or below threshold"
        return label, confidence, "machine-learning classification"
