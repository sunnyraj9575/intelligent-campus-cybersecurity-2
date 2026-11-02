"""
Quick demonstration runner for Intelligent Campus Cyber Security Threat Detection System.
"""

import sys
import time
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(PROJECT_ROOT))

from src.detector import CampusThreatDetector


def main():
    print("=" * 80)
    print("INTELLIGENT CAMPUS CYBER SECURITY THREAT DETECTION - LIVE DEMO")
    print("=" * 80)
    print("Initializing threat detector and loading champion Random Forest model...\n")

    detector = CampusThreatDetector()

    print(f"Model: {detector.model.__class__.__name__}")
    print(f"Monitored Threat Classes: {', '.join(detector.classes)}")
    print(f"Features: {len(detector.preprocessor.feature_columns)}")
    print("-" * 80)

    print("\nSimulating 6 live network flows crossing campus subnets:\n")
    print(f"{'TIME':<10} | {'SOURCE IP':<15} -> {'DEST IP':<15} | {'CLASSIFICATION':<18} | {'CONF':<7} | {'SEVERITY'}")
    print("-" * 80)

    for i in range(6):
        event = detector.simulate_stream_event()
        t = event["timestamp"].split("T")[1][:8]
        src = event["src_ip"]
        dst = event["dst_ip"]
        pred = event["prediction"]
        conf = f"{event['confidence']*100:.1f}%"
        sev = event["advisory"]["severity"]
        print(f"{t:<10} | {src:<15} -> {dst:<15} | {pred:<18} | {conf:<7} | {sev}")
        time.sleep(0.3)

    print("-" * 80)
    print("\nSample MITRE ATT&CK Mitigation Advisory for Detected Threat:")
    adv = event["advisory"]
    print(f"  Threat: {event['prediction']}")
    print(f"  MITRE ID: {adv['mitre_id']} ({adv['mitre_name']})")
    print(f"  Containment Tier: {adv['containment_tier']}")
    print(f"  Action: {adv['recommended_action']}")
    print(f"  Firewall Rule: \n    {adv['firewall_rule'].replace(chr(10), chr(10) + '    ')}")
    print("=" * 80)
    print("\nTo launch the interactive Security Operations Center (SOC) dashboard, run:")
    print("  python dashboard/app.py")
    print("  or double-click 'start_dashboard.bat'")
    print("=" * 80)


if __name__ == "__main__":
    main()
