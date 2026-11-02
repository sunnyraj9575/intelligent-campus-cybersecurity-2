"""
Model architectures and factory for Campus Cyber Threat Classification.
"""

from typing import Any, Dict
from sklearn.ensemble import HistGradientBoostingClassifier, RandomForestClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.neural_network import MLPClassifier
from sklearn.tree import DecisionTreeClassifier


def get_model_registry(config: Dict[str, Any] | None = None) -> Dict[str, Any]:
    """Return dictionary of initialized supervised machine learning models."""
    cfg = config.get("models", {}) if config else {}

    rf_cfg = cfg.get("random_forest", {})
    gb_cfg = cfg.get("gradient_boosting", {})
    dt_cfg = cfg.get("decision_tree", {})
    mlp_cfg = cfg.get("mlp", {})
    lr_cfg = cfg.get("logistic_regression", {})

    models = {
        "Random_Forest": RandomForestClassifier(
            n_estimators=rf_cfg.get("n_estimators", 120),
            max_depth=rf_cfg.get("max_depth", 18),
            min_samples_split=rf_cfg.get("min_samples_split", 4),
            class_weight=rf_cfg.get("class_weight", "balanced"),
            random_state=rf_cfg.get("random_state", 42),
            n_jobs=-1,
        ),
        "Gradient_Boosting": HistGradientBoostingClassifier(
            max_iter=gb_cfg.get("n_estimators", 100),
            max_depth=gb_cfg.get("max_depth", 6),
            learning_rate=gb_cfg.get("learning_rate", 0.1),
            random_state=gb_cfg.get("random_state", 42),
        ),
        "Decision_Tree": DecisionTreeClassifier(
            max_depth=dt_cfg.get("max_depth", 14),
            class_weight=dt_cfg.get("class_weight", "balanced"),
            random_state=dt_cfg.get("random_state", 42),
        ),
        "MLP_Neural_Net": MLPClassifier(
            hidden_layer_sizes=tuple(mlp_cfg.get("hidden_layer_sizes", [64, 32])),
            max_iter=mlp_cfg.get("max_iter", 200),
            random_state=mlp_cfg.get("random_state", 42),
        ),
        "Logistic_Regression": LogisticRegression(
            max_iter=lr_cfg.get("max_iter", 1000),
            class_weight=lr_cfg.get("class_weight", "balanced"),
            random_state=lr_cfg.get("random_state", 42),
        ),
    }

    return models
