"""
Evaluation and Metrics reporting script.
Displays detailed per-class metrics, confusion matrices, and feature importances.
"""

import json
import sys
from pathlib import Path
import pandas as pd

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))


def main():
    metrics_path = PROJECT_ROOT / "models" / "saved" / "metrics_summary.json"
    if not metrics_path.exists():
        print(f"Metrics summary not found at {metrics_path}. Please train models first: python models/train.py")
        sys.exit(1)

    with open(metrics_path, "r", encoding="utf-8") as f:
        summary = json.load(f)

    print("=" * 85)
    print("INTELLIGENT CAMPUS CYBER SECURITY THREAT DETECTION - EVALUATION REPORT")
    print("=" * 85)
    print(f"Champion Model Selected: {summary['champion_model']}")
    print(f"Total Threat Classes: {len(summary['classes'])} ({', '.join(summary['classes'])})")
    print(f"Total Network Features: {summary['feature_count']}")
    print("-" * 85)

    print("\n[1] ALL MODELS BENCHMARK COMPARISON:")
    print(f"{'MODEL':<24} | {'ACCURACY':<10} | {'PRECISION':<10} | {'RECALL':<10} | {'F1-MACRO':<10} | {'ROC-AUC':<10}")
    print("-" * 85)
    for model_name, metrics in summary["benchmark_results"].items():
        acc = metrics["accuracy"]
        prec = metrics["precision_macro"]
        rec = metrics["recall_macro"]
        f1 = metrics["f1_macro"]
        roc = metrics.get("roc_auc", "N/A")
        roc_str = f"{roc:.4f}" if isinstance(roc, (float, int)) else str(roc)
        star = " * [Champion]" if model_name == summary["champion_model"] else ""
        print(f"{model_name:<24} | {acc:<10.4f} | {prec:<10.4f} | {rec:<10.4f} | {f1:<10.4f} | {roc_str:<10}{star}")

    best_metrics = summary["best_model_metrics"]

    print("\n[2] CHAMPION MODEL DETAILED PER-CLASS CLASSIFICATION REPORT:")
    print(f"{'THREAT CLASS':<22} | {'PRECISION':<10} | {'RECALL':<10} | {'F1-SCORE':<10} | {'SUPPORT':<8}")
    print("-" * 70)
    for cls_name in summary["classes"]:
        cls_data = best_metrics["per_class_report"].get(cls_name, {})
        p = cls_data.get("precision", 0.0)
        r = cls_data.get("recall", 0.0)
        f = cls_data.get("f1-score", 0.0)
        s = int(cls_data.get("support", 0))
        print(f"{cls_name:<22} | {p:<10.4f} | {r:<10.4f} | {f:<10.4f} | {s:<8}")

    print("\n[3] TOP 10 DISCRIMINATIVE NETWORK FEATURES (RANDOM FOREST GINI IMPORTANCE):")
    print(f"{'RANK':<5} | {'FEATURE NAME':<32} | {'IMPORTANCE SCORE'}")
    print("-" * 60)
    for i, item in enumerate(best_metrics.get("feature_importance", [])[:10], 1):
        print(f"#{i:<4} | {item['feature']:<32} | {item['importance']:.4f}")

    print("\n" + "=" * 85)


if __name__ == "__main__":
    main()
