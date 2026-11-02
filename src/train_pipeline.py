"""
Training and evaluation pipeline for Intelligent Campus Threat Detection.
"""

import json
from pathlib import Path
from typing import Any, Dict
import joblib
import pandas as pd
from sklearn.model_selection import train_test_split

from src.config_loader import get_project_root, load_config
from src.evaluator import ModelEvaluator
from src.models import get_model_registry
from src.preprocessor import CampusThreatPreprocessor


class TrainingPipeline:
    """Orchestrates end-to-end dataset loading, preprocessing, model training, and evaluation."""

    def __init__(self, config_path: Path | str | None = None):
        self.config = load_config(config_path)
        self.root = get_project_root()
        self.preprocessor = CampusThreatPreprocessor()

    def run(self) -> Dict[str, Any]:
        """Execute complete training pipeline."""
        raw_csv = self.root / self.config["dataset"]["raw_path"]
        processed_train = self.root / self.config["dataset"]["train_path"]
        processed_test = self.root / self.config["dataset"]["test_path"]
        models_dir = self.root / "models" / "saved"
        models_dir.mkdir(parents=True, exist_ok=True)

        if not raw_csv.exists():
            raise FileNotFoundError(f"Raw dataset not found at {raw_csv}. Run data generation first.")

        print(f"Loading raw dataset from {raw_csv}...")
        df = pd.read_csv(raw_csv)
        print(f"Loaded {len(df)} samples across {df['label'].nunique()} classes.")

        # Stratified Train-Test Split
        test_size = self.config["dataset"].get("test_size", 0.25)
        seed = self.config["dataset"].get("random_state", 42)
        train_df, test_df = train_test_split(
            df, test_size=test_size, random_state=seed, stratify=df["label"]
        )

        # Save processed splits
        processed_train.parent.mkdir(parents=True, exist_ok=True)
        train_df.to_csv(processed_train, index=False)
        test_df.to_csv(processed_test, index=False)
        print(f"Train split: {len(train_df)} samples | Test split: {len(test_df)} samples")

        # Fit preprocessor on training set
        print("Preprocessing features (feature engineering, one-hot encoding, scaling)...")
        X_train, y_train = self.preprocessor.fit_transform(train_df, target_col="label")
        X_test = self.preprocessor.transform(test_df)
        y_test = self.preprocessor.label_encoder.transform(test_df["label"])

        # Save preprocessor artifacts
        self.preprocessor.save(models_dir)
        print(f"Preprocessor artifacts saved to {models_dir}")

        # Train and Evaluate Models
        models = get_model_registry(self.config)
        classes = list(self.preprocessor.label_encoder.classes_)
        feature_names = self.preprocessor.feature_columns

        results: Dict[str, Any] = {}
        best_model_name = None
        best_f1 = -1.0
        best_model_obj = None

        print("\n" + "=" * 80)
        print(f"{'MODEL':<22} | {'ACCURACY':<10} | {'PRECISION':<10} | {'RECALL':<10} | {'F1-MACRO':<10}")
        print("=" * 80)

        for name, model in models.items():
            print(f"Training {name:<20}...", end="\r")
            model.fit(X_train, y_train)

            metrics = ModelEvaluator.evaluate(
                model=model,
                X_test=X_test,
                y_test=y_test,
                target_names=classes,
                feature_names=feature_names,
            )
            results[name] = metrics

            acc = metrics["accuracy"]
            prec = metrics["precision_macro"]
            rec = metrics["recall_macro"]
            f1 = metrics["f1_macro"]

            print(f"{name:<22} | {acc:<10.4f} | {prec:<10.4f} | {rec:<10.4f} | {f1:<10.4f}")

            # Keep track of best model
            if f1 > best_f1:
                best_f1 = f1
                best_model_name = name
                best_model_obj = model

        print("=" * 80)
        print(f"\nChampion Model: {best_model_name} with F1-Macro score of {best_f1:.4f}")

        # Save Best Model
        best_model_path = models_dir / "best_model.joblib"
        joblib.dump(best_model_obj, best_model_path)
        print(f"Saved champion model to {best_model_path}")

        # Save full evaluation summary
        summary = {
            "champion_model": best_model_name,
            "classes": classes,
            "feature_count": len(feature_names),
            "benchmark_results": results,
            "best_model_metrics": results[best_model_name],
        }

        with open(models_dir / "metrics_summary.json", "w", encoding="utf-8") as f:
            json.dump(summary, f, indent=2)

        print(f"Metrics summary written to {models_dir / 'metrics_summary.json'}")
        return summary
