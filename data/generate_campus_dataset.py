"""
CLI script to generate campus cyber security dataset.
"""

import sys
from pathlib import Path

# Add project root to sys.path
PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from src.config_loader import load_config
from src.dataset_generator import generate_and_save_dataset


def main():
    config = load_config()
    raw_path = PROJECT_ROOT / config["dataset"]["raw_path"]
    samples = config["dataset"].get("sample_size", 15000)
    seed = config["dataset"].get("random_state", 42)

    print("=" * 70)
    print("Generating Intelligent Campus Cyber Security Dataset...")
    print(f"Target file: {raw_path}")
    print(f"Samples: {samples} | Random Seed: {seed}")
    print("=" * 70)

    generate_and_save_dataset(output_path=raw_path, total_samples=samples, random_state=seed)
    print("\nDataset generation completed successfully!")


if __name__ == "__main__":
    main()
