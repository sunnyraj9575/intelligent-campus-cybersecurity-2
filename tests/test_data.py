"""
Unit tests for Campus Dataset Generator.
"""

import pytest
from src.dataset_generator import CampusDatasetGenerator


def test_dataset_generator_shape_and_classes():
    generator = CampusDatasetGenerator(random_state=42)
    df = generator.generate(total_samples=100)

    assert len(df) > 0
    assert "label" in df.columns
    assert "byte_ratio" in df.columns

    # Verify key threat classes are present
    labels = set(df["label"].unique())
    assert "Benign" in labels
    assert "DDoS_Flood" in labels
    assert "Port_Scan" in labels
    assert "Brute_Force" in labels


def test_dataset_generator_single_sample():
    generator = CampusDatasetGenerator(random_state=42)
    df = generator.generate(total_samples=1)
    assert len(df) == 1
    assert "label" in df.columns
