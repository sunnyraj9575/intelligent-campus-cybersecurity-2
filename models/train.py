"""
CLI training runner for Intelligent Campus Threat Detection System.
"""

import sys
from pathlib import Path

# Add project root to sys.path
PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from src.train_pipeline import TrainingPipeline


def main():
    print("=" * 80)
    print("STARTING CAMPUS CYBER THREAT DETECTION MODEL TRAINING PIPELINE")
    print("=" * 80)
    pipeline = TrainingPipeline()
    summary = pipeline.run()
    print("\nTraining completed successfully! Champion model is ready for real-time inference.")


if __name__ == "__main__":
    main()
