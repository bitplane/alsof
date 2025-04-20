#!/usr/bin/env python3

# Filename: pid.py (suggested)

import psutil
import logging
import os
import sys
import argparse
from typing import List, Optional

# --- Setup Logging ---
# Configure basic logging; callers can override this configuration.
# Set default level to WARNING to avoid spamming INFO messages when used as library.
logging.basicConfig(level=os.environ.get("LOGLEVEL", "WARNING").upper(),
                    format='%(levelname)s:%(name)s:%(message)s')
log = logging.getLogger(__name__)

# Renamed function from get_descendant_pids
def get_descendants(parent_pid: int) -> List[int]:
    """
    Retrieves a list of all descendant process IDs (PIDs) for a given parent PID
    (children, grandchildren, etc.).

    Uses the psutil library for cross-platform compatibility.

    Args:
        parent_pid: The Process ID of the parent process.

    Returns:
        A list of integer PIDs of the descendants.
        Returns an empty list if the parent process is not found, has no descendants,
        or if there's a permission error accessing the process.
    """
    descendant_pids: List[int] = []
    try:
        parent = psutil.Process(parent_pid)
        # Use recursive=True to get all descendants
        descendant_procs = parent.children(recursive=True)
        descendant_pids = [proc.pid for proc in descendant_procs]
        log.debug(f"Found descendants for PID {parent_pid}: {descendant_pids}")

    except psutil.NoSuchProcess:
        # Log warning, return empty list - expected if PID is gone
        log.warning(f"Process with PID {parent_pid} not found.")
    except psutil.AccessDenied:
        # Log warning, return empty list - permission issue
        log.warning(f"Access denied when trying to get descendants of PID {parent_pid}.")
    except Exception as e:
        # Catch any other unexpected psutil errors
        log.error(f"An unexpected error occurred getting descendants for PID {parent_pid}: {e}")

    return descendant_pids

# --- Main Execution Function ---

def main(argv: Optional[List[str]] = None) -> int:
    """
    Command-line entry point. Takes a PID and prints descendant PIDs.
    """
    parser = argparse.ArgumentParser(
        description="List all descendant PIDs (children, grandchildren, etc.) for a given parent PID.",
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument(
        "pid",
        type=int,
        help="The PID of the parent process."
    )
    parser.add_argument(
        '--log',
        default='WARNING',
        choices=['DEBUG', 'INFO', 'WARNING', 'ERROR', 'CRITICAL'],
        help='Set the logging level (default: WARNING)'
    )

    args = parser.parse_args(argv) # Parses sys.argv[1:] if argv is None

    # Configure logging level based on argument for standalone execution
    logging.getLogger().setLevel(args.log.upper())

    try:
        # Call the renamed function
        descendant_pids = get_descendants(args.pid)

        # Print only the PIDs to stdout, one per line
        for pid in descendant_pids:
            print(pid)

        return 0 # Success

    except Exception as e:
        # Catch any unexpected errors during execution
        log.critical(f"An unexpected error occurred in main: {e}", exc_info=True)
        return 1

# --- Script Entry Point ---

if __name__ == "__main__":
    sys.exit(main())
