#!/usr/bin/env python3
# Filename: src/lsoph/cli.py
import argparse
import asyncio
import logging
import os
import shlex
import sys
from collections.abc import Coroutine
from typing import Any, Type

# Import backend base class and the discovered backends dictionary
from lsoph.backend import BACKENDS, Backend  # Import BACKENDS dict

# Import TRACE_LEVEL_NUM if needed, or just rely on setup_logging
from lsoph.log import LOG_QUEUE, setup_logging
from lsoph.monitor import Monitor
from lsoph.ui.app import LsophApp


def parse_arguments(
    backends: dict[str, Backend] = BACKENDS,
    argv: list[str] = sys.argv,
) -> argparse.Namespace:
    """Parses command-line arguments for lsoph."""
    log = logging.getLogger("lsoph.cli.args")
    backends = list(b for b in backends if backends[b].is_available())

    if not backends:
        print(
            f"All backends unavailable: {', '.join(BACKENDS)}",
            file=sys.stderr,
        )
        sys.exit(1)

    default_backend = backends[0]

    parser = argparse.ArgumentParser(
        description="Monitors file access for a command or process using various backends.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=f"Available backends: {', '.join(backends)}\n"
        f"Default backend: {default_backend}\n\n"
        "Examples:\n"
        "  lsoph -p 1234 5678       # Attach to PIDs using default backend\n"
        "  lsoph -b strace sleep 10 # Run 'sleep 10' using strace backend\n"
        "  lsoph -b psutil find .   # Run 'find .' using psutil backend",
    )
    parser.add_argument(
        "-b",
        "--backend",
        default=default_backend,
        choices=backends,
        help=f"Monitoring backend to use (default: {default_backend})",
    )
    parser.add_argument(
        "--log",
        default="INFO",
        choices=["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL", "TRACE"],
        help="Set the logging level (default: INFO)",
    )
    parser.add_argument(
        "--log-file",
        metavar="PATH",
        type=str,
        default=None,
        help="Write logs to the specified file in addition to the TUI.",
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

    return args


# --- Main Application Logic ---


def main(argv: list[str] | None = None) -> int:
    """
    Main entry point: Parses args, sets up logging, creates Monitor,
    instantiates backend, creates the specific backend coroutine,
    and launches the Textual UI.
    """
    temp_args = parse_arguments(BACKENDS, argv)
    setup_logging(temp_args.log, temp_args.log_file)
    log = logging.getLogger("lsoph.cli")  # Get main cli logger

    try:
        args = temp_args
        log.info("Starting lsoph...")
        log.debug(f"Parsed arguments: {args}")

        # Get the constructor for the selected backend from the discovered dict

        # Determine mode (attach/run) and prepare arguments
        monitor_id: str
        target_pids: list[int] | None = None
        target_command: list[str] | None = None

        if args.pids:
            target_pids = args.pids
            monitor_id = f"pids_{'_'.join(map(str, args.pids))}"
            log.info(f"Mode: Attach PIDs. Backend: {args.backend}")
        else:
            target_command = args.command
            monitor_id = shlex.join(args.command)
            log.info(f"Mode: Run Command. Backend: {args.backend}")

        # Create the central Monitor instance
        monitor = Monitor(identifier=monitor_id)
        backend = BACKENDS[args.backend](monitor)

        # Create the specific coroutine to run (attach or run_command)
        backend_coro = (
            backend.attach(target_pids)
            if target_pids
            else backend.run_command(target_command)
        )

        # Launch the Textual application
        log.info("Launching Textual UI...")
        app_instance = LsophApp(
            monitor=monitor,
            log_queue=LOG_QUEUE,
            backend_instance=backend,
            backend_coroutine=backend_coro,
        )
        app_instance.run()  # This blocks until the UI exits
        log.info("Textual UI finished.")
        return 0

    except argparse.ArgumentError as e:
        # Handle argparse errors gracefully (already printed by argparse)
        log.error(f"Argument Error: {e}")
        return 2
    except Exception as e:
        log.critical(f"FATAL ERROR: {e}", exc_info=True)
        raise


if __name__ == "__main__":
    sys.exit(main())
