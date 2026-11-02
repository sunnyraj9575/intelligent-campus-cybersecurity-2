"""
Unit tests for Feature Engineering and Preprocessing.
"""

import pandas as pd
import pytest
from src.dataset_generator import CampusDatasetGenerator
from src.feature_engineering import NetworkFeatureEngineer
from src.preprocessor import CampusThreatPreprocessor


def test_feature_engineering_metrics():
    df = pd.DataFrame([{
        "src_bytes": 1000,
        "dst_bytes": 200,
        "src_pkts": 10,
        "dst_pkts": 2,
        "syn_flag_count": 5,
        "ack_flag_count": 2,
        "src_subnet": "dorms",
        "dst_subnet": "server_farm",
        "port_entropy": 0.85,
        "duration": 0.05,
        "pkt_rate": 200.0,
        "avg_pkt_size": 100.0,
    }])

    enriched = NetworkFeatureEngineer.extract_features(df)
    assert enriched["byte_ratio"].iloc[0] == 5.0
    assert enriched["pkt_ratio"].iloc[0] == 5.0
    assert enriched["is_cross_subnet_sensitive"].iloc[0] == 1


def test_preprocessor_fit_transform():
    generator = CampusDatasetGenerator(random_state=42)
    df = generator.generate(total_samples=100)

    preprocessor = CampusThreatPreprocessor()
    X, y = preprocessor.fit_transform(df, target_col="label")

    assert X.shape[0] == len(df)
    assert len(y) == len(df)
    assert preprocessor.is_fitted
    assert len(preprocessor.feature_columns) > 0


def test_preprocessor_single_sample_transform():
    generator = CampusDatasetGenerator(random_state=42)
    train_df = generator.generate(total_samples=100)

    preprocessor = CampusThreatPreprocessor()
    preprocessor.fit_transform(train_df, target_col="label")

    sample_dict = train_df.iloc[0].drop(labels=["label"]).to_dict()
    X_single = preprocessor.transform_single(sample_dict)
    assert X_single.shape[0] == 1
    assert X_single.shape[1] == len(preprocessor.feature_columns)
