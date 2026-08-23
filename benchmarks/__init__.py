"""Reproducible benchmark tooling for the OpenBot pursuit controller.

The package deliberately depends only on the Python standard library so that a
frozen confirmation run does not acquire an avoidable analysis dependency.
"""

from .schema import SCHEMA_VERSION, ValidationError, load_study

__all__ = ["SCHEMA_VERSION", "ValidationError", "load_study"]

