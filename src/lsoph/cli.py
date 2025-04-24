#!/usr/bin/env python3
# Filename: src/lsoph/cli.py
import argparse
import asyncio
import logging
import os
import shlex
import sys
from collections.abc import Callable, Coroutine
from typing import Any

# Import backend modules AND their backend classes
from lsoph.backend import lsof, psutil, strace

# Import the corrected base backend class
from lsoph.backend.base import Backend
from lsoph.backend.lsof import LsofBackend
from lsoph.backend.psutil import PsutilBackend
from lsoph.backend.strace import StraceBackend
from lsoph.log import LOG_QUEUE, setup_logging
from lsoph.monitor import Monitor
from lsoph.ui.app import LsophApp

# --- Type Definitions ---
BackendFactory = Callable[[Monitor], Backend]
BackendCoroutine = Coroutine[Any, Any, None]

# --- Logging Setup ---
# Logging setup is handled by log.py


# --- Argument Parsing ---
# Map backend names to their class constructors
BACKEND_CONSTRUCTORS: dict[str, Callable[[Monitor], Backend]] = {
    "strace": StraceBackend,
    "lsof": LsofBackend,
    "psutil": PsutilBackend,
}
# Keep lsof as default maybe? Or psutil? Let's stick with lsof for now.
DEFAULT_BACKEND = "lsof"


def parse_arguments(
    argv: list[str] | None = None,
) -> argparse.Namespace:
    """Parses command-line arguments for lsoph."""
    parser = argparse.ArgumentParser(
        description="Monitors file access for a command or process using various backends.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=f"Available backends: {', '.join(BACKEND_CONSTRUCTORS.keys())}\n"
        f"Default backend: {DEFAULT_BACKEND}\n\n"
        "Examples:\n"
        "  lsoph -p 1234 5678         # Attach to PIDs using default backend (lsof)\n"
        "  lsoph -b strace -- sleep 10 # Run 'sleep 10' using strace backend\n"
        "  lsoph -b psutil -c find .   # Run 'find .' using psutil backend",
    )
    parser.add_argument(
        "-b",
        "--backend",
        default=DEFAULT_BACKEND,
        choices=BACKEND_CONSTRUCTORS.keys(),
        help=f"Monitoring backend to use (default: {DEFAULT_BACKEND})",
    )
    parser.add_argument(
        "--log",
        default="INFO",
        choices=["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"],
        help="Set the logging level for the application (default: INFO)",
    )
    # Mutually exclusive group for attach (-p) or run (-c) mode
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument(
        "-p",
        "--pids",
        nargs="+",
        type=int,
        metavar="PID",
        help="Attach Mode: One or more existing process IDs (PIDs) to monitor.",
    )
    group.add_argument(
        "-c",
        "--command",
        nargs=argparse.REMAINDER,  # Capture all remaining args as the command
        metavar="COMMAND [ARG...]",
        help="Run Mode: The command and its arguments to launch and monitor.",
    )
    args = parser.parse_args(argv)

    # Validate command arguments
    if args.command is not None and not args.command:
        parser.error("argument -c/--command: requires a command to run.")

    # Warn if strace is used without root (it often needs it)
    if args.backend == "strace" and os.geteuid() != 0:
        print(
            "Warning: 'strace' backend typically requires root privileges.",
            file=sys.stderr,
        )
    return args


# --- Main Application Logic ---


def main(argv: list[str] | None = None) -> int:
    """
    Main entry point: Parses args, sets up logging, creates Monitor,
    instantiates backend, creates the specific backend coroutine,
    and launches the Textual UI.
    """
    try:
        args = parse_arguments(argv)
        # Setup logging using the dedicated function
        setup_logging(args.log)
        log = logging.getLogger("lsoph.cli")  # Get logger after setup
        log.info("Starting lsoph...")
        log.debug(f"Parsed arguments: {args}")

        # Get the constructor for the selected backend
        backend_constructor = BACKEND_CONSTRUCTORS.get(args.backend)
        if not backend_constructor:
            # This should not happen due to argparse choices, but check anyway
            log.critical(f"Invalid backend selected: {args.backend}")
            return 1

        # Determine mode (attach/run) and prepare arguments
        monitor_id: str
        target_pids: list[int] | None = None
        target_command: list[str] | None = None

        if args.pids:
            target_pids = args.pids
            monitor_id = f"pids_{'_'.join(map(str, args.pids))}"
            log.info(
                f"Mode: Attach PIDs. Target: {monitor_id}, Backend: {args.backend}"
            )
        elif args.command:
            target_command = args.command
            monitor_id = shlex.join(args.command)  # Safely join command parts for ID
            log.info(
                f"Mode: Run Command. Target: '{monitor_id}', Backend: {args.backend}"
            )
        else:
            # This should not happen due to argparse required group
            log.critical("Internal error: No command or PIDs specified after parsing.")
            return 1

        # Create the central Monitor instance
        monitor = Monitor(identifier=monitor_id)

        # Instantiate the selected backend
        try:
            backend_instance = backend_constructor(monitor)
            log.info(f"Instantiated backend: {args.backend}")
        except Exception as be_init_e:
            log.exception(f"Failed to initialize backend '{args.backend}': {be_init_e}")
            return 1

        # Create the specific coroutine to run (attach or run_command)
        backend_coro: BackendCoroutine
        if target_pids:
            backend_coro = backend_instance.attach(target_pids)
        elif target_command:
            backend_coro = backend_instance.run_command(target_command)
        else:
            # Should be unreachable
            log.critical("Internal error: Could not determine backend coroutine.")
            return 1

        # Launch the Textual application
        log.info("Launching Textual UI...")
        app_instance = LsophApp(
            monitor=monitor,
            log_queue=LOG_QUEUE,  # Pass the shared log queue
            backend_instance=backend_instance,  # Pass the backend instance
            backend_coroutine=backend_coro,  # Pass the coroutine to run
        )
        app_instance.run()  # This blocks until the UI exits
        log.info("Textual UI finished.")
        return 0  # Success

    except argparse.ArgumentError as e:
        # Handle argparse errors gracefully
        print(f"Argument Error: {e}", file=sys.stderr)
        return 2
    except Exception as e:
        # Catch any other unexpected errors during setup or run
        print(f"FATAL ERROR: {e}", file=sys.stderr)
        # Log exception if logging was successfully initialized
        if logging.getLogger().hasHandlers():
            logging.getLogger("lsoph.cli").exception(
                "Unhandled exception during execution."
            )
        return 1


if __name__ == "__main__":
    sys.exit(main())
