# Filename: src/lsoph/backend/__init__.py
"""
LSOPH Backend Package.
"""

import logging
from typing import Type  # Use Type for Python 3.10+

# Import the base class
from .base import Backend

# Import specific backend implementations (now renamed)
from .lsof import Lsof
from .psutil import Psutil
from .strace import Strace

log = logging.getLogger("lsoph.backend")  # Logger for this package

# --- Backend Discovery ---

log.debug("Starting backend discovery...")
BACKENDS: dict[str, Type[Backend]] = {
    backend.__name__.lower(): backend
    for backend in (Lsof, Psutil, Strace)
    if backend.is_available()
}

__all__ = ["Backend", "BACKENDS"]
