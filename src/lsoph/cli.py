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
from lsoph.log import LOG_QUEUE, setup_logging
from lsoph.monitor import Monitor
from lsoph.ui.app import LsophApp


def parse_arguments(
    available_backends: dict[str, Type[Backend]],  # Takes the dict as input
    argv: list[str] | None = None,
) -> argparse.Namespace:
    """Parses command-line arguments for lsoph."""
    log = logging.getLogger("lsoph.cli.args")  # Use specific logger
    backend_choices = sorted(list(available_backends.keys()))

    if not backend_choices:
        # Handle case where no backends are available (should also be caught in main)
        print(
            "Error: No monitoring backends are available on this system.",
            file=sys.stderr,
        )
        print(
            "Please ensure dependencies like 'lsof', 'strace', or 'psutil' are installed.",
            file=sys.stderr,
        )
        sys.exit(1)  # Exit early if no backends

    # Determine default backend, preferring strace if available
    default_backend = (
        "strace"
        if "strace" in available_backends
        else ("lsof" if "lsof" in available_backends else backend_choices[0])
    )
    log.debug(f"Default backend determined as: {default_backend}")

    parser = argparse.ArgumentParser(
        description="Monitors file access for a command or process using various backends.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=f"Available backends: {', '.join(backend_choices)}\n"
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
        choices=backend_choices,  # Use dynamically discovered choices
        help=f"Monitoring backend to use (default: {default_backend})",
    )
    parser.add_argument(
        "--log",
        default="INFO",
        choices=["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL", "TRACE"],
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

    return args


# --- Main Application Logic ---


def main(argv: list[str] | None = None) -> int:
    """
    Main entry point: Parses args, sets up logging, creates Monitor,
    instantiates backend, creates the specific backend coroutine,
    and launches the Textual UI.
    """
    # Setup logging first to capture discovery messages from backend init
    temp_log_level = os.environ.get("LSOPH_LOG_LEVEL", "INFO").upper()
    setup_logging(temp_log_level)
    log = logging.getLogger("lsoph.cli")  # Get main cli logger

    # Check if any backends were discovered during import
    # Uses the BACKENDS dict imported from lsoph.backend
    if not BACKENDS:
        # The backend __init__ should have logged a warning.
        print("Error: No monitoring backends available. Exiting.", file=sys.stderr)
        return 1  # Indicate failure

    try:
        # Parse arguments using the discovered backends
        args = parse_arguments(BACKENDS, argv)

        # Re-setup logging with the level specified in args
        setup_logging(args.log)
        log.info("Starting lsoph...")
        log.debug(f"Parsed arguments: {args}")

        # Get the constructor for the selected backend from the discovered dict
        backend_class = BACKENDS.get(args.backend)
        if not backend_class:
            # This should not happen due to argparse choices, but check anyway
            log.critical(
                f"Selected backend '{args.backend}' not found in available backends."
            )
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
            backend_instance = backend_class(monitor)
            log.info(f"Instantiated backend: {args.backend}")
        except Exception as be_init_e:
            log.exception(f"Failed to initialize backend '{args.backend}': {be_init_e}")
            return 1

        # Create the specific coroutine to run (attach or run_command)
        backend_coro: Coroutine[Any, Any, None]
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
        # Handle argparse errors gracefully (already printed by argparse)
        log.error(f"Argument Error: {e}")
        return 2
    except Exception as e:
        # Catch any other unexpected errors during setup or run
        log.critical(f"FATAL ERROR: {e}", exc_info=True)
        # Also print to stderr in case logging failed
        print(f"FATAL ERROR: {e}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
