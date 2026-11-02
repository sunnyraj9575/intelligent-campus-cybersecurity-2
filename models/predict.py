"""
CLI Prediction script for Campus Threat Detection System.
"""

import argparse
import json
import sys
from pathlib import Path
import pandas as pd

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from src.detector import CampusThreatDetector


def interactive_mode(detector: CampusThreatDetector):
    """Run interactive prompt to classify a network flow."""
    print("\n" + "=" * 60)
    print("INTERACTIVE NETWORK FLOW THREAT PREDICTOR")
    print("=" * 60)
    print("Enter flow attributes (or press ENTER to use default sample):")

    def ask(prompt, default, cast_type=str):
        val = input(f"{prompt} [{default}]: ").strip()
        if not val:
            return default
        try:
            return cast_type(val)
        except Exception:
            return default

    flow = {
        "duration": ask("Duration (seconds)", 0.05, float),
        "protocol_type": ask("Protocol (TCP/UDP/ICMP)", "TCP"),
        "service": ask("Service (HTTP/HTTPS/SSH/DNS/FTP)", "HTTPS"),
        "conn_state": ask("Connection State (SF/S0/REJ/RSTO)", "SF"),
        "src_bytes": ask("Source Bytes", 450, int),
        "dst_bytes": ask("Destination Bytes", 1200, int),
        "src_pkts": ask("Source Packets", 12, int),
        "dst_pkts": ask("Destination Packets", 10, int),
        "pkt_rate": ask("Packet Rate (pkts/sec)", 440.0, float),
        "byte_rate": ask("Byte Rate (bytes/sec)", 33000.0, float),
        "avg_pkt_size": ask("Average Packet Size", 75.0, float),
        "failed_logins": ask("Failed Logins count", 0, int),
        "port_entropy": ask("Port Entropy (0.0 - 1.0)", 0.15, float),
        "payload_entropy": ask("Payload Entropy (0.0 - 8.0)", 4.2, float),
        "syn_flag_count": ask("SYN Flags count", 1, int),
        "rst_flag_count": ask("RST Flags count", 0, int),
        "ack_flag_count": ask("ACK Flags count", 9, int),
        "src_subnet": ask("Source Subnet (dorms/labs/admin/guest_wifi/external)", "dorms"),
        "dst_subnet": ask("Destination Subnet (server_farm/admin/labs/external)", "server_farm"),
        "is_guest_network": ask("Is Guest Network (0/1)", 0, int),
    }

    result = detector.detect_single(flow)
    print("\n" + "=" * 60)
    print(f"PREDICTED CLASSIFICATION: {result['prediction']}")
    print(f"THREAT STATUS: {'MALICIOUS ATTACK' if result['is_threat'] else 'BENIGN TRAFFIC'}")
    print(f"CONFIDENCE: {result['confidence'] * 100:.2f}%")
    print(f"SEVERITY: {result['advisory']['severity']}")
    print(f"MITRE ATT&CK: {result['advisory']['mitre_id']} - {result['advisory']['mitre_name']}")
    print(f"RECOMMENDED ACTION: {result['advisory']['recommended_action']}")
    print("=" * 60)


def simulate_mode(detector: CampusThreatDetector, count: int):
    """Simulate streaming campus flows."""
    print("\n" + "=" * 80)
    print(f"SIMULATING {count} LIVE CAMPUS NETWORK FLOWS THROUGH ML DETECTOR")
    print("=" * 80)
    print(f"{'TIMESTAMP':<12} | {'SRC IP':<15} -> {'DST IP':<15} | {'PREDICTION':<18} | {'CONF':<7} | {'SEVERITY'}")
    print("-" * 80)

    for _ in range(count):
        res = detector.simulate_stream_event()
        t_str = res["timestamp"].split("T")[1][:8]
        src = res["src_ip"]
        dst = res["dst_ip"]
        pred = res["prediction"]
        conf = f"{res['confidence']*100:.1f}%"
        sev = res["advisory"]["severity"]
        print(f"{t_str:<12} | {src:<15} -> {dst:<15} | {pred:<18} | {conf:<7} | {sev}")
    print("=" * 80)


def batch_mode(detector: CampusThreatDetector, file_path: str, output_path: str | None):
    """Classify a CSV file of flows."""
    in_file = Path(file_path)
    if not in_file.exists():
        print(f"Error: File not found {in_file}")
        sys.exit(1)

    print(f"Loading {in_file}...")
    df = pd.read_csv(in_file)
    result_df = detector.detect_batch(df)

    out_file = Path(output_path) if output_path else in_file.parent / f"classified_{in_file.name}"
    result_df.to_csv(out_file, index=False)
    print(f"Classified {len(result_df)} records. Saved audit log to {out_file}")
    print("\nThreat Summary:")
    print(result_df["predicted_threat"].value_counts())


def main():
    parser = argparse.ArgumentParser(description="Campus Cyber Threat Detection CLI")
    parser.add_argument("--interactive", action="store_true", help="Launch interactive single flow classifier")
    parser.add_argument("--simulate", type=int, default=0, help="Simulate N streaming campus flows")
    parser.add_argument("--file", type=str, help="Path to CSV file with network flow logs to classify")
    parser.add_argument("--output", type=str, help="Output path for classified CSV")

    args = parser.parse_args()
    detector = CampusThreatDetector()

    if args.interactive:
        interactive_mode(detector)
    elif args.simulate > 0:
        simulate_mode(detector, args.simulate)
    elif args.file:
        batch_mode(detector, args.file, args.output)
    else:
        # Default behavior: run 5-flow simulation
        simulate_mode(detector, 5)


if __name__ == "__main__":
    main()
