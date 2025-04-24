# Filename: src/lsoph/util/fifo.py
"""Utility for creating and managing temporary FIFOs."""

import contextlib
import logging
import os
import pathlib
import tempfile
from collections.abc import Iterator  # Use collections.abc for Iterator

log = logging.getLogger(__name__)


@contextlib.contextmanager
def temp_fifo(prefix: str = "lsoph_pipe_") -> Iterator[str]:
    """
    Context manager to create a temporary FIFO within a temporary directory.

    Yields the absolute path to the created FIFO.
    Ensures the temporary directory and the FIFO are cleaned up on exit.

    Args:
        prefix: A prefix for the temporary directory name.

    Yields:
        str: The absolute path to the created FIFO.

    Raises:
        RuntimeError: If FIFO creation fails.
    """
    fifo_path: str | None = None
    with tempfile.TemporaryDirectory(prefix=prefix) as temp_dir_path:
        try:
            fifo_path = str(pathlib.Path(temp_dir_path) / "pipe.fifo")
            os.mkfifo(fifo_path, 0o600)  # Create FIFO with user-only permissions
            log.debug(f"Created temporary FIFO: {fifo_path}")
            yield fifo_path
        except OSError as e:
            # Log the error and raise a more specific runtime error
            log.exception(f"Failed to create FIFO in {temp_dir_path}: {e}")
            raise RuntimeError(f"Failed to create FIFO in {temp_dir_path}: {e}") from e
        except Exception as e:
            # Catch other potential errors during setup
            log.exception(f"Unexpected error setting up FIFO in {temp_dir_path}: {e}")
            raise RuntimeError(f"Failed to set up temporary FIFO: {e}") from e
        finally:
            # Cleanup is handled by TemporaryDirectory context manager exiting
            # We just log that it's happening (or would happen).
            if fifo_path:
                log.debug(f"Temporary FIFO {fifo_path} will be cleaned up.")
            else:
                log.debug("Temporary directory will be cleaned up (FIFO not created).")
