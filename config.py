"""Compatibility entry point for CyberInvestigator Flask configuration profiles.

Applications may load this module directly with Flask's ``from_object`` API, or
import the same profiles from ``cyberinvestigator.config``.
"""

from cyberinvestigator.config import (
    CONFIG_BY_NAME,
    BaseConfig,
    DevelopmentConfig,
    ProductionConfig,
    TestingConfig,
)

__all__ = [
    "CONFIG_BY_NAME",
    "BaseConfig",
    "DevelopmentConfig",
    "ProductionConfig",
    "TestingConfig",
]
