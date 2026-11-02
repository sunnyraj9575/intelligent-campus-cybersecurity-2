"""
Feature engineering module for Campus Cyber Security Threat Detection.
Extracts domain-specific network telemetry features.
"""

from typing import List
import numpy as np
import pandas as pd


class NetworkFeatureEngineer:
    """Computes advanced cyber threat indicators from raw network flow logs."""

    @staticmethod
    def extract_features(df: pd.DataFrame) -> pd.DataFrame:
        """Enrich flow DataFrame with domain-specific cybersecurity metrics."""
        data = df.copy()

        # 1. Asymmetry and Flow Ratio Metrics
        data["byte_ratio"] = np.round(
            data["src_bytes"] / np.maximum(data["dst_bytes"], 1.0), 4
        )
        data["pkt_ratio"] = np.round(
            data["src_pkts"] / np.maximum(data["dst_pkts"], 1.0), 4
        )

        # 2. Flag Asymmetry (SYN flood / scan indicators)
        syn_count = data.get("syn_flag_count", 0)
        ack_count = data.get("ack_flag_count", 0)
        data["syn_to_ack_ratio"] = np.round(
            syn_count / np.maximum(ack_count, 1.0), 4
        )

        # 3. Connection and Packet Characteristics
        total_pkts = data["src_pkts"] + data["dst_pkts"]
        total_bytes = data["src_bytes"] + data["dst_bytes"]
        data["bytes_per_pkt"] = np.round(
            total_bytes / np.maximum(total_pkts, 1.0), 4
        )

        # 4. Campus Subnet Topology Risk Indicators
        # Crossing from high churn / public subnets (guest_wifi, dorms) to sensitive (admin, server_farm)
        high_risk_sources = ["guest_wifi", "dorms", "external"]
        sensitive_targets = ["admin", "server_farm"]

        data["is_cross_subnet_sensitive"] = (
            data["src_subnet"].isin(high_risk_sources)
            & data["dst_subnet"].isin(sensitive_targets)
        ).astype(int)

        data["is_outbound_exfiltration_risk"] = (
            data["src_subnet"].isin(["admin", "server_farm"])
            & (data["dst_subnet"] == "external")
        ).astype(int)

        # 5. Composite Threat Signal
        # Port scan flag: high port entropy + short duration + zero dst_pkts
        data["port_scan_signal"] = np.round(
            data["port_entropy"] * (1.0 / (data["duration"] + 0.05)), 4
        )

        # DoS signal: high packet rate + low avg packet size
        data["flood_intensity"] = np.round(
            data["pkt_rate"] / (data["avg_pkt_size"] + 10.0), 4
        )

        return data
