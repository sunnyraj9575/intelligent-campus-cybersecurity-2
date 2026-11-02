"""
Realistic Campus Cyber Security Network Flow Dataset Generator.
Generates synthetic yet statistically representative network flows modeling both
benign academic network operations and sophisticated cyber attacks targeting university infrastructure.
"""

from pathlib import Path
from typing import Dict, List, Tuple
import numpy as np
import pandas as pd


class CampusDatasetGenerator:
    """Generates synthetic campus network flow records with realistic threat signatures."""

    def __init__(self, random_state: int = 42):
        self.rng = np.random.default_rng(random_state)
        self.subnets = ["dorms", "labs", "admin", "server_farm", "guest_wifi", "external"]
        self.protocols = ["TCP", "UDP", "ICMP"]
        self.services = ["HTTP", "HTTPS", "SSH", "DNS", "FTP", "SMTP", "RDP", "ICMP_ECHO", "OTHER"]
        self.conn_states = ["SF", "S0", "REJ", "RSTO", "RSTR"]

    def _sample_benign(self, n: int) -> pd.DataFrame:
        """Sample benign campus traffic (web browsing, streaming, academic portals, library, research)."""
        duration = self.rng.exponential(scale=12.0, size=n) + 0.05
        src_pkts = self.rng.integers(5, 500, size=n)
        dst_pkts = np.maximum(1, (src_pkts * self.rng.uniform(0.6, 2.5, size=n)).astype(int))

        avg_pkt_size = self.rng.normal(loc=580, scale=180, size=n).clip(64, 1460)
        src_bytes = (src_pkts * avg_pkt_size * self.rng.uniform(0.3, 0.9, size=n)).astype(int)
        dst_bytes = (dst_pkts * avg_pkt_size * self.rng.uniform(0.8, 1.8, size=n)).astype(int)

        pkt_rate = (src_pkts + dst_pkts) / np.maximum(duration, 0.01)
        byte_rate = (src_bytes + dst_bytes) / np.maximum(duration, 0.01)

        src_subnets = self.rng.choice(
            ["dorms", "labs", "guest_wifi", "admin", "external"],
            size=n,
            p=[0.40, 0.25, 0.15, 0.10, 0.10],
        )
        dst_subnets = self.rng.choice(
            ["server_farm", "external", "labs", "admin"],
            size=n,
            p=[0.45, 0.40, 0.10, 0.05],
        )

        services = self.rng.choice(
            ["HTTPS", "HTTP", "DNS", "SSH", "SMTP", "RDP", "OTHER"],
            size=n,
            p=[0.55, 0.20, 0.12, 0.05, 0.04, 0.02, 0.02],
        )

        protocols = np.where(services == "DNS", "UDP", "TCP")
        conn_states = self.rng.choice(["SF", "RSTO"], size=n, p=[0.97, 0.03])

        return pd.DataFrame({
            "duration": np.round(duration, 4),
            "protocol_type": protocols,
            "service": services,
            "conn_state": conn_states,
            "src_bytes": src_bytes,
            "dst_bytes": dst_bytes,
            "src_pkts": src_pkts,
            "dst_pkts": dst_pkts,
            "pkt_rate": np.round(pkt_rate, 2),
            "byte_rate": np.round(byte_rate, 2),
            "avg_pkt_size": np.round(avg_pkt_size, 2),
            "failed_logins": np.zeros(n, dtype=int),
            "port_entropy": np.round(self.rng.uniform(0.05, 0.35, size=n), 4),
            "payload_entropy": np.round(self.rng.uniform(2.8, 5.2, size=n), 4),
            "syn_flag_count": np.ones(n, dtype=int),
            "rst_flag_count": self.rng.choice([0, 1], size=n, p=[0.95, 0.05]),
            "ack_flag_count": (src_pkts * self.rng.uniform(0.7, 1.0, size=n)).astype(int),
            "src_subnet": src_subnets,
            "dst_subnet": dst_subnets,
            "is_guest_network": (src_subnets == "guest_wifi").astype(int),
            "label": "Benign",
        })

    def _sample_ddos(self, n: int) -> pd.DataFrame:
        """Sample Denial of Service flood targeting university registration/LMS server farm."""
        duration = self.rng.uniform(0.01, 1.8, size=n)
        src_pkts = self.rng.integers(800, 15000, size=n)
        dst_pkts = self.rng.integers(0, 15, size=n)  # Victim cannot respond adequately

        avg_pkt_size = self.rng.normal(loc=68, scale=12, size=n).clip(40, 120)  # Small flood packets
        src_bytes = (src_pkts * avg_pkt_size).astype(int)
        dst_bytes = (dst_pkts * 54).astype(int)

        pkt_rate = (src_pkts + dst_pkts) / np.maximum(duration, 0.01)
        byte_rate = (src_bytes + dst_bytes) / np.maximum(duration, 0.01)

        src_subnets = self.rng.choice(["external", "dorms", "guest_wifi"], size=n, p=[0.70, 0.20, 0.10])
        dst_subnets = np.full(n, "server_farm")

        protocols = self.rng.choice(["TCP", "UDP", "ICMP"], size=n, p=[0.65, 0.25, 0.10])
        services = np.where(protocols == "TCP", "HTTPS", np.where(protocols == "UDP", "DNS", "ICMP_ECHO"))
        conn_states = self.rng.choice(["S0", "REJ"], size=n, p=[0.85, 0.15])

        return pd.DataFrame({
            "duration": np.round(duration, 4),
            "protocol_type": protocols,
            "service": services,
            "conn_state": conn_states,
            "src_bytes": src_bytes,
            "dst_bytes": dst_bytes,
            "src_pkts": src_pkts,
            "dst_pkts": dst_pkts,
            "pkt_rate": np.round(pkt_rate, 2),
            "byte_rate": np.round(byte_rate, 2),
            "avg_pkt_size": np.round(avg_pkt_size, 2),
            "failed_logins": np.zeros(n, dtype=int),
            "port_entropy": np.round(self.rng.uniform(0.1, 0.45, size=n), 4),
            "payload_entropy": np.round(self.rng.uniform(1.0, 3.2, size=n), 4),
            "syn_flag_count": src_pkts,  # Massive SYN flood
            "rst_flag_count": self.rng.integers(0, 5, size=n),
            "ack_flag_count": dst_pkts,
            "src_subnet": src_subnets,
            "dst_subnet": dst_subnets,
            "is_guest_network": (src_subnets == "guest_wifi").astype(int),
            "label": "DDoS_Flood",
        })

    def _sample_brute_force(self, n: int) -> pd.DataFrame:
        """Sample Brute Force password guessing against SSH, FTP, or campus administrative portal."""
        duration = self.rng.uniform(0.8, 6.0, size=n)
        failed_logins = self.rng.integers(4, 28, size=n)  # Key indicator
        src_pkts = (failed_logins * self.rng.integers(6, 14, size=n)).astype(int)
        dst_pkts = (failed_logins * self.rng.integers(5, 12, size=n)).astype(int)

        avg_pkt_size = self.rng.normal(loc=195, scale=45, size=n).clip(80, 400)
        src_bytes = (src_pkts * avg_pkt_size).astype(int)
        dst_bytes = (dst_pkts * 120).astype(int)

        pkt_rate = (src_pkts + dst_pkts) / np.maximum(duration, 0.01)
        byte_rate = (src_bytes + dst_bytes) / np.maximum(duration, 0.01)

        src_subnets = self.rng.choice(["dorms", "guest_wifi", "external"], size=n, p=[0.40, 0.35, 0.25])
        dst_subnets = self.rng.choice(["admin", "labs", "server_farm"], size=n, p=[0.50, 0.35, 0.15])

        services = self.rng.choice(["SSH", "FTP", "RDP", "HTTPS"], size=n, p=[0.45, 0.25, 0.15, 0.15])
        conn_states = self.rng.choice(["REJ", "RSTO", "SF"], size=n, p=[0.60, 0.30, 0.10])

        return pd.DataFrame({
            "duration": np.round(duration, 4),
            "protocol_type": np.full(n, "TCP"),
            "service": services,
            "conn_state": conn_states,
            "src_bytes": src_bytes,
            "dst_bytes": dst_bytes,
            "src_pkts": src_pkts,
            "dst_pkts": dst_pkts,
            "pkt_rate": np.round(pkt_rate, 2),
            "byte_rate": np.round(byte_rate, 2),
            "avg_pkt_size": np.round(avg_pkt_size, 2),
            "failed_logins": failed_logins,
            "port_entropy": np.round(self.rng.uniform(0.05, 0.20, size=n), 4),
            "payload_entropy": np.round(self.rng.uniform(3.5, 5.0, size=n), 4),
            "syn_flag_count": failed_logins,
            "rst_flag_count": self.rng.integers(1, 8, size=n),
            "ack_flag_count": dst_pkts,
            "src_subnet": src_subnets,
            "dst_subnet": dst_subnets,
            "is_guest_network": (src_subnets == "guest_wifi").astype(int),
            "label": "Brute_Force",
        })

    def _sample_port_scan(self, n: int) -> pd.DataFrame:
        """Sample reconnaissance port scanning across university network segments."""
        duration = self.rng.uniform(0.001, 0.35, size=n)
        src_pkts = self.rng.integers(1, 5, size=n)  # Probe packets
        dst_pkts = self.rng.choice([0, 1], size=n, p=[0.75, 0.25])

        avg_pkt_size = self.rng.normal(loc=54, scale=6, size=n).clip(40, 70)
        src_bytes = (src_pkts * avg_pkt_size).astype(int)
        dst_bytes = (dst_pkts * 40).astype(int)

        pkt_rate = (src_pkts + dst_pkts) / np.maximum(duration, 0.005)
        byte_rate = (src_bytes + dst_bytes) / np.maximum(duration, 0.005)

        src_subnets = self.rng.choice(["dorms", "labs", "guest_wifi", "external"], size=n, p=[0.35, 0.30, 0.20, 0.15])
        dst_subnets = self.rng.choice(["admin", "server_farm", "labs"], size=n, p=[0.45, 0.35, 0.20])

        services = np.full(n, "OTHER")
        protocols = self.rng.choice(["TCP", "UDP"], size=n, p=[0.85, 0.15])
        conn_states = self.rng.choice(["S0", "REJ"], size=n, p=[0.70, 0.30])

        # High port entropy is the classic watermark for port scanning
        port_entropy = np.round(self.rng.uniform(0.82, 0.99, size=n), 4)

        return pd.DataFrame({
            "duration": np.round(duration, 4),
            "protocol_type": protocols,
            "service": services,
            "conn_state": conn_states,
            "src_bytes": src_bytes,
            "dst_bytes": dst_bytes,
            "src_pkts": src_pkts,
            "dst_pkts": dst_pkts,
            "pkt_rate": np.round(pkt_rate, 2),
            "byte_rate": np.round(byte_rate, 2),
            "avg_pkt_size": np.round(avg_pkt_size, 2),
            "failed_logins": np.zeros(n, dtype=int),
            "port_entropy": port_entropy,
            "payload_entropy": np.round(self.rng.uniform(0.8, 2.5, size=n), 4),
            "syn_flag_count": src_pkts,
            "rst_flag_count": self.rng.choice([0, 1], size=n, p=[0.7, 0.3]),
            "ack_flag_count": dst_pkts,
            "src_subnet": src_subnets,
            "dst_subnet": dst_subnets,
            "is_guest_network": (src_subnets == "guest_wifi").astype(int),
            "label": "Port_Scan",
        })

    def _sample_web_attack(self, n: int) -> pd.DataFrame:
        """Sample SQL Injection, XSS, and exploit attempts targeting campus portals."""
        duration = self.rng.exponential(scale=1.5, size=n) + 0.1
        src_pkts = self.rng.integers(6, 40, size=n)
        dst_pkts = self.rng.integers(4, 30, size=n)

        avg_pkt_size = self.rng.normal(loc=720, scale=180, size=n).clip(200, 1500)
        src_bytes = (src_pkts * avg_pkt_size * self.rng.uniform(1.2, 2.5, size=n)).astype(int)
        dst_bytes = (dst_pkts * 420).astype(int)

        pkt_rate = (src_pkts + dst_pkts) / np.maximum(duration, 0.05)
        byte_rate = (src_bytes + dst_bytes) / np.maximum(duration, 0.05)

        src_subnets = self.rng.choice(["external", "dorms", "guest_wifi"], size=n, p=[0.55, 0.30, 0.15])
        dst_subnets = self.rng.choice(["server_farm", "admin"], size=n, p=[0.75, 0.25])

        services = self.rng.choice(["HTTPS", "HTTP"], size=n, p=[0.70, 0.30])
        conn_states = self.rng.choice(["SF", "REJ", "RSTO"], size=n, p=[0.50, 0.35, 0.15])

        # High payload entropy due to encoded SQL payloads, hex/percent encoding, scripts
        payload_entropy = np.round(self.rng.uniform(5.8, 7.8, size=n), 4)

        return pd.DataFrame({
            "duration": np.round(duration, 4),
            "protocol_type": np.full(n, "TCP"),
            "service": services,
            "conn_state": conn_states,
            "src_bytes": src_bytes,
            "dst_bytes": dst_bytes,
            "src_pkts": src_pkts,
            "dst_pkts": dst_pkts,
            "pkt_rate": np.round(pkt_rate, 2),
            "byte_rate": np.round(byte_rate, 2),
            "avg_pkt_size": np.round(avg_pkt_size, 2),
            "failed_logins": self.rng.choice([0, 1, 2], size=n, p=[0.7, 0.2, 0.1]),
            "port_entropy": np.round(self.rng.uniform(0.08, 0.28, size=n), 4),
            "payload_entropy": payload_entropy,
            "syn_flag_count": np.ones(n, dtype=int),
            "rst_flag_count": self.rng.choice([0, 1], size=n, p=[0.8, 0.2]),
            "ack_flag_count": (src_pkts * 0.9).astype(int),
            "src_subnet": src_subnets,
            "dst_subnet": dst_subnets,
            "is_guest_network": (src_subnets == "guest_wifi").astype(int),
            "label": "Web_Attack",
        })

    def _sample_botnet_c2(self, n: int) -> pd.DataFrame:
        """Sample compromised lab computer or dorm laptop communicating with Botnet Command & Control."""
        duration = self.rng.normal(loc=1.2, scale=0.3, size=n).clip(0.2, 3.5)  # Periodic beacon
        src_pkts = self.rng.integers(4, 25, size=n)
        dst_pkts = self.rng.integers(3, 20, size=n)

        avg_pkt_size = self.rng.normal(loc=310, scale=80, size=n).clip(120, 600)
        src_bytes = (src_pkts * avg_pkt_size).astype(int)
        dst_bytes = (dst_pkts * avg_pkt_size * 0.8).astype(int)

        pkt_rate = (src_pkts + dst_pkts) / np.maximum(duration, 0.05)
        byte_rate = (src_bytes + dst_bytes) / np.maximum(duration, 0.05)

        src_subnets = self.rng.choice(["labs", "dorms"], size=n, p=[0.60, 0.40])
        dst_subnets = np.full(n, "external")

        services = self.rng.choice(["DNS", "HTTPS", "OTHER"], size=n, p=[0.35, 0.45, 0.20])
        protocols = np.where(services == "DNS", "UDP", "TCP")
        conn_states = self.rng.choice(["SF", "RSTO"], size=n, p=[0.90, 0.10])

        # High payload entropy from encrypted C2 communication
        payload_entropy = np.round(self.rng.uniform(6.5, 7.95, size=n), 4)

        return pd.DataFrame({
            "duration": np.round(duration, 4),
            "protocol_type": protocols,
            "service": services,
            "conn_state": conn_states,
            "src_bytes": src_bytes,
            "dst_bytes": dst_bytes,
            "src_pkts": src_pkts,
            "dst_pkts": dst_pkts,
            "pkt_rate": np.round(pkt_rate, 2),
            "byte_rate": np.round(byte_rate, 2),
            "avg_pkt_size": np.round(avg_pkt_size, 2),
            "failed_logins": np.zeros(n, dtype=int),
            "port_entropy": np.round(self.rng.uniform(0.12, 0.35, size=n), 4),
            "payload_entropy": payload_entropy,
            "syn_flag_count": np.ones(n, dtype=int),
            "rst_flag_count": self.rng.choice([0, 1], size=n, p=[0.9, 0.1]),
            "ack_flag_count": (src_pkts * 0.85).astype(int),
            "src_subnet": src_subnets,
            "dst_subnet": dst_subnets,
            "is_guest_network": np.zeros(n, dtype=int),
            "label": "Botnet_C2",
        })

    def _sample_data_exfiltration(self, n: int) -> pd.DataFrame:
        """Sample unauthorized confidential academic/financial database exfiltration off-campus."""
        duration = self.rng.exponential(scale=65.0, size=n) + 15.0  # Prolonged transfer
        src_pkts = self.rng.integers(2000, 45000, size=n)
        dst_pkts = (src_pkts * self.rng.uniform(0.15, 0.35, size=n)).astype(int)

        avg_pkt_size = self.rng.normal(loc=1380, scale=80, size=n).clip(1200, 1460)  # Max MTU frames
        src_bytes = (src_pkts * avg_pkt_size).astype(int)  # Megabytes to Gigabytes
        dst_bytes = (dst_pkts * 64).astype(int)  # Minimal ACK return stream

        pkt_rate = (src_pkts + dst_pkts) / np.maximum(duration, 1.0)
        byte_rate = (src_bytes + dst_bytes) / np.maximum(duration, 1.0)

        src_subnets = self.rng.choice(["admin", "server_farm", "labs"], size=n, p=[0.55, 0.35, 0.10])
        dst_subnets = np.full(n, "external")

        services = self.rng.choice(["HTTPS", "SSH", "FTP", "OTHER"], size=n, p=[0.50, 0.25, 0.15, 0.10])
        conn_states = np.full(n, "SF")

        # Compressed/encrypted archive entropy
        payload_entropy = np.round(self.rng.uniform(7.2, 7.99, size=n), 4)

        return pd.DataFrame({
            "duration": np.round(duration, 4),
            "protocol_type": np.full(n, "TCP"),
            "service": services,
            "conn_state": conn_states,
            "src_bytes": src_bytes,
            "dst_bytes": dst_bytes,
            "src_pkts": src_pkts,
            "dst_pkts": dst_pkts,
            "pkt_rate": np.round(pkt_rate, 2),
            "byte_rate": np.round(byte_rate, 2),
            "avg_pkt_size": np.round(avg_pkt_size, 2),
            "failed_logins": np.zeros(n, dtype=int),
            "port_entropy": np.round(self.rng.uniform(0.02, 0.15, size=n), 4),
            "payload_entropy": payload_entropy,
            "syn_flag_count": np.ones(n, dtype=int),
            "rst_flag_count": np.zeros(n, dtype=int),
            "ack_flag_count": (src_pkts * 0.95).astype(int),
            "src_subnet": src_subnets,
            "dst_subnet": dst_subnets,
            "is_guest_network": np.zeros(n, dtype=int),
            "label": "Data_Exfiltration",
        })

    def generate(self, total_samples: int = 15000) -> pd.DataFrame:
        """Generate balanced yet realistic multiclass dataset."""
        weights = {
            "Benign": 0.50,
            "DDoS_Flood": 0.10,
            "Brute_Force": 0.10,
            "Port_Scan": 0.10,
            "Web_Attack": 0.08,
            "Botnet_C2": 0.06,
            "Data_Exfiltration": 0.06,
        }

        if total_samples <= len(weights):
            # Choose random class according to distribution
            labels = list(weights.keys())
            probs = list(weights.values())
            chosen_label = self.rng.choice(labels, p=probs)
            sampler_map = {
                "Benign": self._sample_benign,
                "DDoS_Flood": self._sample_ddos,
                "Brute_Force": self._sample_brute_force,
                "Port_Scan": self._sample_port_scan,
                "Web_Attack": self._sample_web_attack,
                "Botnet_C2": self._sample_botnet_c2,
                "Data_Exfiltration": self._sample_data_exfiltration,
            }
            df = sampler_map[chosen_label](total_samples)
            df["byte_ratio"] = np.round(df["src_bytes"] / np.maximum(df["dst_bytes"], 1.0), 4)
            return df

        frames = []
        for label, fraction in weights.items():
            count = max(1, int(total_samples * fraction))
            if label == "Benign":
                df = self._sample_benign(count)
            elif label == "DDoS_Flood":
                df = self._sample_ddos(count)
            elif label == "Brute_Force":
                df = self._sample_brute_force(count)
            elif label == "Port_Scan":
                df = self._sample_port_scan(count)
            elif label == "Web_Attack":
                df = self._sample_web_attack(count)
            elif label == "Botnet_C2":
                df = self._sample_botnet_c2(count)
            elif label == "Data_Exfiltration":
                df = self._sample_data_exfiltration(count)
            frames.append(df)

        full_df = pd.concat(frames, ignore_index=True)
        # Compute derived network flow features
        full_df["byte_ratio"] = np.round(
            full_df["src_bytes"] / np.maximum(full_df["dst_bytes"], 1.0), 4
        )

        # Shuffle thoroughly
        full_df = full_df.sample(frac=1.0, random_state=42).reset_index(drop=True)
        return full_df


def generate_and_save_dataset(
    output_path: Path | str,
    total_samples: int = 15000,
    random_state: int = 42,
) -> pd.DataFrame:
    """Generate dataset and save to CSV file."""
    generator = CampusDatasetGenerator(random_state=random_state)
    df = generator.generate(total_samples=total_samples)

    out = Path(output_path)
    out.parent.mkdir(parents=True, exist_ok=True)
    df.to_csv(out, index=False)
    print(f"Generated {len(df)} campus network flow records saved to {out}")
    print("\nClass Distribution:")
    print(df["label"].value_counts())
    return df
