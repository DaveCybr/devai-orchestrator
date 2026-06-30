"""Legacy import compatibility — delegates to modular validators package."""
from __future__ import annotations

from src.core.validators import VALIDATORS, validate_finding, list_validators

DeterministicValidator = None  # replaced by modular validators
