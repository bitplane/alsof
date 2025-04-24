# Filename: src/lsoph/backend/psutil/__init__.py
"""Psutil backend package for lsoph."""

# Expose the main backend class at the package level
from .backend import Psutil

# Define what gets imported with 'from lsoph.backend.psutil import *' (optional)
__all__ = ["Psutil"]
