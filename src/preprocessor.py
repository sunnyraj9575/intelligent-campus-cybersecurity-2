"""
Data Preprocessing pipeline for Campus Threat Detection.
Handles feature scaling, categorical encoding, and feature column alignment.
"""

import json
from pathlib import Path
from typing import Dict, List, Optional, Tuple, Union
import joblib
import numpy as np
import pandas as pd
from sklearn.preprocessing import LabelEncoder, RobustScaler

from src.feature_engineering import NetworkFeatureEngineer


class CampusThreatPreprocessor:
    """End-to-end preprocessor for network flow features."""

    CATEGORICAL_COLUMNS = [
        "protocol_type",
        "service",
        "conn_state",
        "src_subnet",
        "dst_subnet",
    ]

    NUMERICAL_COLUMNS = [
        "duration",
        "src_bytes",
        "dst_bytes",
        "src_pkts",
        "dst_pkts",
        "pkt_rate",
        "byte_rate",
        "avg_pkt_size",
        "failed_logins",
        "port_entropy",
        "payload_entropy",
        "syn_flag_count",
        "rst_flag_count",
        "ack_flag_count",
        "byte_ratio",
        "pkt_ratio",
        "syn_to_ack_ratio",
        "bytes_per_pkt",
        "port_scan_signal",
        "flood_intensity",
        "is_guest_network",
        "is_cross_subnet_sensitive",
        "is_outbound_exfiltration_risk",
    ]

    def __init__(self):
        self.scaler = RobustScaler()
        self.label_encoder = LabelEncoder()
        self.feature_columns: List[str] = []
        self.is_fitted: bool = False

    def fit_transform(
        self, df: pd.DataFrame, target_col: str = "label"
    ) -> Tuple[np.ndarray, np.ndarray]:
        """Fit preprocessor on training data and return scaled X and encoded y."""
        # Step 1: Feature engineering
        engineered_df = NetworkFeatureEngineer.extract_features(df)

        # Step 2: Separate X and y
        y_raw = engineered_df[target_col]
        X_raw = engineered_df.drop(columns=[target_col], errors="ignore")

        # Step 3: Encode categorical columns via one-hot encoding
        X_encoded = pd.get_dummies(X_raw, columns=self.CATEGORICAL_COLUMNS, drop_first=False)

        # Keep track of all feature columns
        self.feature_columns = list(X_encoded.columns)

        # Step 4: Scale features
        X_scaled = self.scaler.fit_transform(X_encoded)

        # Step 5: Encode target labels
        y_encoded = self.label_encoder.fit_transform(y_raw)

        self.is_fitted = True
        return X_scaled, y_encoded

    def transform(self, df: pd.DataFrame) -> np.ndarray:
        """Transform new data using fitted scaler and feature schema."""
        if not self.is_fitted and not self.feature_columns:
            raise RuntimeError("Preprocessor has not been fitted or loaded yet.")

        engineered_df = NetworkFeatureEngineer.extract_features(df)
        X_raw = engineered_df.drop(columns=["label"], errors="ignore")

        # One-hot encode
        X_encoded = pd.get_dummies(X_raw, columns=self.CATEGORICAL_COLUMNS, drop_first=False)

        # Align columns with training feature columns (fill missing with 0, drop unexpected)
        aligned_df = pd.DataFrame(0, index=X_encoded.index, columns=self.feature_columns)
        for col in self.feature_columns:
            if col in X_encoded.columns:
                aligned_df[col] = X_encoded[col]

        # Scale
        X_scaled = self.scaler.transform(aligned_df)
        return X_scaled

    def transform_single(self, sample_dict: Dict) -> np.ndarray:
        """Transform a single flow dictionary into model input array."""
        df = pd.DataFrame([sample_dict])
        return self.transform(df)

    def inverse_transform_labels(self, y_pred: np.ndarray) -> np.ndarray:
        """Convert integer predictions back to class name strings."""
        return self.label_encoder.inverse_transform(y_pred)

    def save(self, models_dir: Union[Path, str]) -> None:
        """Save scaler, label encoder, and feature column list."""
        path = Path(models_dir)
        path.mkdir(parents=True, exist_ok=True)

        joblib.dump(self.scaler, path / "scaler.joblib")
        joblib.dump(self.label_encoder, path / "label_encoder.joblib")

        with open(path / "feature_columns.json", "w", encoding="utf-8") as f:
            json.dump(self.feature_columns, f, indent=2)

    def load(self, models_dir: Union[Path, str]) -> None:
        """Load fitted scaler, label encoder, and feature columns."""
        path = Path(models_dir)
        scaler_file = path / "scaler.joblib"
        encoder_file = path / "label_encoder.joblib"
        cols_file = path / "feature_columns.json"

        if not scaler_file.exists() or not encoder_file.exists() or not cols_file.exists():
            raise FileNotFoundError(f"Missing preprocessor artifacts in {path}")

        self.scaler = joblib.load(scaler_file)
        self.label_encoder = joblib.load(encoder_file)
        with open(cols_file, "r", encoding="utf-8") as f:
            self.feature_columns = json.load(f)
        self.is_fitted = True
