"""
Evaluation metrics and reporting for Supervised Threat Detection models.
"""

from typing import Any, Dict, List
import numpy as np
import pandas as pd
from sklearn.metrics import (
    accuracy_score,
    classification_report,
    confusion_matrix,
    f1_score,
    precision_score,
    recall_score,
    roc_auc_score,
)


class ModelEvaluator:
    """Evaluates multi-class supervised threat detection performance."""

    @staticmethod
    def evaluate(
        model: Any,
        X_test: np.ndarray,
        y_test: np.ndarray,
        target_names: List[str],
        feature_names: List[str] | None = None,
    ) -> Dict[str, Any]:
        """Compute full evaluation suite for a trained model."""
        y_pred = model.predict(X_test)

        acc = float(accuracy_score(y_test, y_pred))
        prec_macro = float(precision_score(y_test, y_pred, average="macro", zero_division=0))
        rec_macro = float(recall_score(y_test, y_pred, average="macro", zero_division=0))
        f1_macro = float(f1_score(y_test, y_pred, average="macro", zero_division=0))
        f1_weighted = float(f1_score(y_test, y_pred, average="weighted", zero_division=0))

        # Confusion Matrix
        cm = confusion_matrix(y_test, y_pred).tolist()

        # Detailed per-class metrics
        report = classification_report(
            y_test, y_pred, target_names=target_names, output_dict=True, zero_division=0
        )

        # ROC-AUC if probability estimates are supported
        roc_auc = None
        if hasattr(model, "predict_proba"):
            try:
                y_prob = model.predict_proba(X_test)
                roc_auc = float(roc_auc_score(y_test, y_prob, multi_class="ovr", average="macro"))
            except Exception:
                roc_auc = None

        # Feature Importance (if model is tree-based)
        feature_importance = []
        if hasattr(model, "feature_importances_") and feature_names:
            importances = model.feature_importances_
            indices = np.argsort(importances)[::-1][:15]
            for idx in indices:
                feature_importance.append({
                    "feature": feature_names[idx],
                    "importance": round(float(importances[idx]), 4),
                })

        return {
            "accuracy": round(acc, 4),
            "precision_macro": round(prec_macro, 4),
            "recall_macro": round(rec_macro, 4),
            "f1_macro": round(f1_macro, 4),
            "f1_weighted": round(f1_weighted, 4),
            "roc_auc": round(roc_auc, 4) if roc_auc is not None else "N/A",
            "confusion_matrix": cm,
            "classes": target_names,
            "per_class_report": report,
            "feature_importance": feature_importance,
        }
