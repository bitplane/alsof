# Filename: src/lsoph/monitor/__init__.py
"""
lsoph Monitor Package.

This package provides the core state management for monitored file access.
"""

# Expose the main classes at the package level
from ._fileinfo import FileInfo
from ._monitor import Monitor

# Define what gets imported with 'from lsoph.monitor import *' (optional)
__all__ = ["Monitor", "FileInfo"]
