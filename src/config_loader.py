"""
Configuration loader for Intelligent Campus Cyber Threat Detection System.
"""

from pathlib import Path
from typing import Any, Dict
import yaml

DEFAULT_CONFIG_PATH = Path(__file__).resolve().parent.parent / "config" / "config.yaml"


def load_config(config_path: Path | str | None = None) -> Dict[str, Any]:
    """Load configuration dictionary from YAML file."""
    path = Path(config_path) if config_path else DEFAULT_CONFIG_PATH
    if not path.exists():
        raise FileNotFoundError(f"Configuration file not found at: {path}")

    with open(path, "r", encoding="utf-8") as f:
        return yaml.safe_load(f)


def get_project_root() -> Path:
    """Return the root path of the project."""
    return Path(__file__).resolve().parent.parent
