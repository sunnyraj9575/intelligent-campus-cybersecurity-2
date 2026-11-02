"""
Integration tests for Detector, Incident Advisor, and Threat Classification.
"""

import pytest
from src.detector import CampusThreatDetector
from src.incident_advisor import IncidentAdvisor


def test_incident_advisor_rules():
    advisory = IncidentAdvisor.get_advisory("DDoS_Flood")
    assert advisory["severity"] == "Critical"
    assert advisory["mitre_id"] == "T1498"
    assert "iptables" in advisory["firewall_rule"]

    benign_adv = IncidentAdvisor.get_advisory("Benign")
    assert benign_adv["severity"] == "Info"
    assert benign_adv["mitre_id"] == "N/A"


def test_detector_single_prediction():
    detector = CampusThreatDetector()
    flow = {
        "duration": 0.05,
        "protocol_type": "TCP",
        "service": "HTTPS",
        "conn_state": "SF",
        "src_bytes": 450,
        "dst_bytes": 1200,
        "src_pkts": 12,
        "dst_pkts": 10,
        "pkt_rate": 440.0,
        "byte_rate": 33000.0,
        "avg_pkt_size": 75.0,
        "failed_logins": 0,
        "port_entropy": 0.15,
        "payload_entropy": 4.2,
        "syn_flag_count": 1,
        "rst_flag_count": 0,
        "ack_flag_count": 9,
        "src_subnet": "dorms",
        "dst_subnet": "server_farm",
        "is_guest_network": 0,
    }

    result = detector.detect_single(flow)
    assert "prediction" in result
    assert "confidence" in result
    assert "advisory" in result
    assert result["confidence"] >= 0.0 and result["confidence"] <= 1.0


def test_detector_stream_simulation():
    detector = CampusThreatDetector()
    event = detector.simulate_stream_event()
    assert "prediction" in event
    assert "src_ip" in event
    assert "dst_ip" in event
    assert "advisory" in event
