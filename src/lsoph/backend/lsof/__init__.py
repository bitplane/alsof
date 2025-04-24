# Filename: src/lsoph/backend/lsof/__init__.py
"""Lsof backend package for lsoph."""

# Expose the main backend class at the package level
from .backend import Lsof  # Renamed from LsofBackend

# Define what gets imported with 'from lsoph.backend.lsof import *' (optional)
__all__ = ["Lsof"]  # Renamed from LsofBackend
