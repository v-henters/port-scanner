from __future__ import annotations

from pathlib import Path
from typing import Optional, Dict

from pydantic import BaseModel, Field
import yaml


class Policy(BaseModel):
    """Policy controlling risk classification and weights."""

    # Ports that are generally acceptable in the environment (reduced risk)
    allowed_ports: list[int] = Field(default_factory=lambda: [80, 443])
    # Ports that are considered dangerous (increased risk)
    dangerous_ports: list[int] = Field(
        default_factory=lambda: [22, 23, 445, 3389, 3306, 5432, 6379]
    )
    # Ports that may be acceptable depending on context (reserved for future use)
    conditional_ports: list[int] = Field(default_factory=list)

    # Base score by service category
    service_weights: Dict[str, float] = Field(
        default_factory=lambda: {
            "admin": 50.0,
            "db": 45.0,
            "internal": 35.0,
            "web": 25.0,
            "unknown": 15.0,
        }
    )

    # Extra score added if version/product revealed
    version_exposure_weight: float = 10.0


def load_policy(path: Optional[Path]) -> Policy:
    """Load policy from YAML path if provided, else return default Policy."""
    if not path:
        return Policy()
    p = Path(path)
    if not p.exists():
        return Policy()
    with p.open("r", encoding="utf-8") as f:
        data = yaml.safe_load(f) or {}
    return Policy(**data)
