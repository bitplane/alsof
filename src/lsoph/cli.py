#!/usr/bin/env python3
# Filename: src/lsoph/cli.py
import argparse
import asyncio
import logging
import os
import shlex
import sys

# Use Python 3.10+ style hints
from typing import Any, Callable, Coroutine, Dict, List, Optional, Tuple

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
BACKEND_CONSTRUCTORS: Dict[str, Callable[[Monitor], Backend]] = {
    "strace": StraceBackend,
    "lsof": LsofBackend,
    "psutil": PsutilBackend,
}
# Keep lsof as default maybe? Or psutil? Let's stick with lsof for now.
DEFAULT_BACKEND = "lsof"


def parse_arguments(argv: Optional[List[str]] = None) -> argparse.Namespace:
    """Parses command-line arguments for lsoph."""
    parser = argparse.ArgumentParser(
        description="Monitors file access for a command or process using various backends.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=f"Available backends: {', '.join(BACKEND_CONSTRUCTORS.keys())}\n"
        f"Default backend: {DEFAULT_BACKEND}\n\n"
        "Examples:\n"
        "  lsoph -p 1234 5678          # Attach to PIDs using default backend (lsof)\n"
        "  lsoph -b strace -- sleep 10 # Run 'sleep 10' using strace backend\n"
        "  lsoph -b psutil -c find .   # Run 'find .' using psutil backend",  # Updated example
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
        nargs=argparse.REMAINDER,
        metavar="COMMAND [ARG...]",
        help="Run Mode: The command and its arguments to launch and monitor.",
    )
    args = parser.parse_args(argv)
    if args.command is not None and not args.command:
        parser.error("argument -c/--command: requires a command to run.")
    if args.backend == "strace" and os.geteuid() != 0:
        print(
            "Warning: 'strace' backend typically requires root privileges.",
            file=sys.stderr,
        )
    return args


# --- Backend Worker ---
# No longer needed


# --- Main Application Logic ---


def main(argv: Optional[List[str]] = None) -> int:
    """
    Main entry point: Parses args, sets up logging, creates Monitor,
    instantiates backend, creates the specific backend coroutine,
    and launches the Textual UI.
    """
    try:
        args = parse_arguments(argv)
        setup_logging(args.log)
        log = logging.getLogger("lsoph.cli")
        log.info("Starting lsoph...")
        log.debug(f"Parsed arguments: {args}")

        backend_constructor = BACKEND_CONSTRUCTORS.get(args.backend)
        if not backend_constructor:
            log.critical(f"Invalid backend selected: {args.backend}")
            return 1

        monitor_id: str
        target_pids: Optional[list[int]] = None
        target_command: Optional[list[str]] = None

        if args.pids:
            target_pids = args.pids
            monitor_id = f"pids_{'_'.join(map(str, args.pids))}"
            log.info(
                f"Mode: Attach PIDs. Target: {monitor_id}, Backend: {args.backend}"
            )
        elif args.command:
            target_command = args.command
            monitor_id = shlex.join(args.command)
            log.info(
                f"Mode: Run Command. Target: '{monitor_id}', Backend: {args.backend}"
            )
        else:
            log.critical("Internal error: No command or PIDs specified after parsing.")
            return 1

        monitor = Monitor(identifier=monitor_id)

        try:
            backend_instance = backend_constructor(monitor)
            log.info(f"Instantiated backend: {args.backend}")
        except Exception as be_init_e:
            log.exception(f"Failed to initialize backend '{args.backend}': {be_init_e}")
            return 1

        backend_coro: BackendCoroutine
        if target_pids:
            backend_coro = backend_instance.attach(target_pids)
        elif target_command:
            backend_coro = backend_instance.run_command(target_command)
        else:
            log.critical("Internal error: Could not determine backend coroutine.")
            return 1

        log.info("Launching Textual UI...")
        app_instance = LsophApp(
            monitor=monitor,
            log_queue=LOG_QUEUE,
            backend_instance=backend_instance,
            backend_coroutine=backend_coro,
        )
        app_instance.run()
        log.info("Textual UI finished.")
        return 0

    except argparse.ArgumentError as e:
        print(f"Argument Error: {e}", file=sys.stderr)
        return 2
    except Exception as e:
        print(f"FATAL ERROR: {e}", file=sys.stderr)
        if logging.getLogger().hasHandlers():
            logging.getLogger("lsoph.cli").exception(
                "Unhandled exception during execution."
            )
        return 1


if __name__ == "__main__":
    sys.exit(main())
