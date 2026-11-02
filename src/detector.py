"""
Inference and Real-Time Detection Engine for Campus Cyber Threat Detection.
"""

from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List
import joblib
import numpy as np
import pandas as pd

from src.config_loader import get_project_root
from src.dataset_generator import CampusDatasetGenerator
from src.incident_advisor import IncidentAdvisor
from src.preprocessor import CampusThreatPreprocessor


class CampusThreatDetector:
    """Production detection engine that classifies incoming campus network flows."""

    def __init__(self, models_dir: Path | str | None = None):
        root = get_project_root()
        self.models_dir = Path(models_dir) if models_dir else root / "models" / "saved"

        self.preprocessor = CampusThreatPreprocessor()
        self.preprocessor.load(self.models_dir)

        model_path = self.models_dir / "best_model.joblib"
        if not model_path.exists():
            raise FileNotFoundError(f"Champion model not found at {model_path}. Train the model first.")

        self.model = joblib.load(model_path)
        self.classes = list(self.preprocessor.label_encoder.classes_)
        self.dataset_generator = CampusDatasetGenerator()

    def detect_single(self, flow: Dict[str, Any]) -> Dict[str, Any]:
        """Classify a single network flow record."""
        X_scaled = self.preprocessor.transform_single(flow)
        pred_idx = int(self.model.predict(X_scaled)[0])
        threat_label = self.classes[pred_idx]

        probabilities = {}
        confidence = 1.0
        if hasattr(self.model, "predict_proba"):
            probs = self.model.predict_proba(X_scaled)[0]
            confidence = float(np.max(probs))
            probabilities = {
                cls_name: round(float(prob), 4)
                for cls_name, prob in zip(self.classes, probs)
            }

        advisory = IncidentAdvisor.get_advisory(threat_label)

        return {
            "prediction": threat_label,
            "is_threat": threat_label != "Benign",
            "confidence": round(confidence, 4),
            "probabilities": probabilities,
            "advisory": advisory,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }

    def detect_batch(self, df: pd.DataFrame) -> pd.DataFrame:
        """Classify a batch of network flow records."""
        result_df = df.copy()
        X_scaled = self.preprocessor.transform(result_df)
        pred_indices = self.model.predict(X_scaled)
        predictions = self.preprocessor.inverse_transform_labels(pred_indices)

        result_df["predicted_threat"] = predictions
        result_df["is_threat"] = result_df["predicted_threat"] != "Benign"

        if hasattr(self.model, "predict_proba"):
            probs = self.model.predict_proba(X_scaled)
            result_df["confidence"] = np.round(np.max(probs, axis=1), 4)
        else:
            result_df["confidence"] = 1.0

        # Add severity
        result_df["severity"] = result_df["predicted_threat"].apply(
            lambda t: IncidentAdvisor.get_advisory(t)["severity"]
        )

        return result_df

    def simulate_stream_event(self) -> Dict[str, Any]:
        """Generate a realistic single stream event with synthetic campus IP metadata and model prediction."""
        raw_df = self.dataset_generator.generate(total_samples=1)
        flow_dict = raw_df.iloc[0].to_dict()
        true_label = flow_dict.pop("label", "Unknown")

        # Synthesize realistic IP addresses based on subnets
        subnet_ips = {
            "dorms": f"10.10.{np.random.randint(1, 254)}.{np.random.randint(1, 254)}",
            "labs": f"10.20.{np.random.randint(1, 254)}.{np.random.randint(1, 254)}",
            "admin": f"10.30.{np.random.randint(1, 254)}.{np.random.randint(1, 254)}",
            "server_farm": f"10.40.1.{np.random.randint(10, 50)}",
            "guest_wifi": f"10.50.{np.random.randint(1, 254)}.{np.random.randint(1, 254)}",
            "external": f"{np.random.randint(104, 212)}.{np.random.randint(1, 254)}.{np.random.randint(1, 254)}.{np.random.randint(1, 254)}",
        }

        src_ip = subnet_ips.get(flow_dict.get("src_subnet", "dorms"))
        dst_ip = subnet_ips.get(flow_dict.get("dst_subnet", "server_farm"))

        detection = self.detect_single(flow_dict)
        detection["flow_data"] = flow_dict
        detection["src_ip"] = src_ip
        detection["dst_ip"] = dst_ip
        detection["ground_truth"] = true_label

        return detection
