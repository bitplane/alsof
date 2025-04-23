#!/usr/bin/env python3
# Filename: src/lsoph/cli.py
import argparse
import logging
import os
import shlex
import sys
from collections import deque
from typing import Callable, List, Optional, Tuple, Union  # Added Optional, Tuple

# Import backend modules dynamically
from lsoph.backend import lsof, psutil, strace
from lsoph.monitor import Monitor
from lsoph.ui.app import FileApp  # Assuming FileApp is the main UI class

# --- Type Definitions ---
# Function signature for backend attach/run functions
BackendFuncType = Callable[[Union[List[int], List[str]], Monitor], None]
# Type for arguments passed to backend functions (either PIDs or command list)
BackendArgsType = Union[List[int], List[str]]
# Function signature for the worker function that runs the backend
BackendWorkerFuncType = Callable[[BackendFuncType, Monitor, BackendArgsType], None]


# --- Logging Setup ---

# Global deque for log messages to be displayed in the UI
# Needs to be accessible by the handler and the UI App instance
LOG_QUEUE = deque(maxlen=1000)  # Max 1000 lines in memory


class TextualLogHandler(logging.Handler):
    """A logging handler that puts formatted messages into a deque for Textual."""

    def __init__(self, log_queue: deque):
        super().__init__()
        self.log_queue = log_queue
        # Define a standard format for log messages within the handler
        formatter = logging.Formatter(
            "%(asctime)s %(name)s: %(message)s", datefmt="%H:%M:%S"
        )
        self.setFormatter(formatter)

    def emit(self, record: logging.LogRecord):
        """Formats the log record and adds it to the queue with Rich markup."""
        try:
            # Get the plain message and timestamp
            plain_msg = f"{record.name}: {record.getMessage()}"
            timestamp = self.formatter.formatTime(record, self.formatter.datefmt)

            # Apply Rich markup based on log level
            markup = ""
            if record.levelno >= logging.CRITICAL:
                markup = f"{timestamp} [bold red]{plain_msg}[/bold red]"
            elif record.levelno >= logging.ERROR:
                markup = f"{timestamp} [red]{plain_msg}[/red]"
            elif record.levelno >= logging.WARNING:
                markup = f"{timestamp} [yellow]{plain_msg}[/yellow]"
            elif record.levelno >= logging.INFO:
                markup = f"{timestamp} [green]{plain_msg}[/green]"
            elif record.levelno >= logging.DEBUG:
                markup = f"{timestamp} [dim]{plain_msg}[/dim]"
            else:  # Default for lower levels
                markup = f"{timestamp} {plain_msg}"

            # Append the marked-up string to the shared queue
            self.log_queue.append(markup)
        except Exception:
            # Handle potential errors during formatting or queue append
            self.handleError(record)


def setup_logging(level_name: str = "INFO"):
    """Configures the root logger to use the TextualLogHandler."""
    log_level = getattr(logging, level_name.upper(), logging.INFO)
    root_logger = logging.getLogger()  # Get the root logger
    root_logger.setLevel(log_level)

    # Remove any existing handlers (e.g., from basicConfig in imports)
    for handler in root_logger.handlers[:]:
        root_logger.removeHandler(handler)

    # Add our custom handler that writes to the global LOG_QUEUE
    textual_handler = TextualLogHandler(LOG_QUEUE)
    root_logger.addHandler(textual_handler)

    # Optionally add a stderr handler for critical errors in case TUI fails
    # stream_handler = logging.StreamHandler(sys.stderr)
    # stream_handler.setLevel(logging.ERROR)
    # stream_formatter = logging.Formatter("%(levelname)s:%(name)s:%(message)s")
    # stream_handler.setFormatter(stream_formatter)
    # root_logger.addHandler(stream_handler)

    logging.getLogger("lsoph").info(f"Logging configured at level {level_name}.")


# --- Argument Parsing ---

# Map backend names to their attach and run functions
BACKENDS: Dict[str, Tuple[BackendFuncType, BackendFuncType]] = {
    "strace": (strace.attach, strace.run),
    "lsof": (lsof.attach, lsof.run),
    "psutil": (psutil.attach, psutil.run),
}
DEFAULT_BACKEND = "lsof"  # Changed default, lsof is often more readily available


def parse_arguments(argv: Optional[List[str]] = None) -> argparse.Namespace:
    """Parses command-line arguments for lsoph."""
    parser = argparse.ArgumentParser(
        description="Monitors file access for a command or process using various backends.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=f"Available backends: {', '.join(BACKENDS.keys())}\n"
        f"Default backend: {DEFAULT_BACKEND}\n\n"
        "Examples:\n"
        "  lsoph -p 1234 5678          # Attach to PIDs using default backend (lsof)\n"
        "  lsoph -b strace -- sleep 10 # Run 'sleep 10' using strace backend\n"
        "  lsoph --log DEBUG -c find . # Run 'find .' with debug logging",
    )
    parser.add_argument(
        "-b",
        "--backend",
        default=DEFAULT_BACKEND,
        choices=BACKENDS.keys(),
        help=f"Monitoring backend to use (default: {DEFAULT_BACKEND})",
    )
    parser.add_argument(
        "--log",
        default="INFO",
        choices=["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"],
        help="Set the logging level for the application (default: INFO)",
    )

    # --- Mutually Exclusive Group for Target ---
    # The user must specify either PIDs to attach to OR a command to run.
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument(
        "-p",
        "--pids",
        nargs="+",  # Expect one or more PIDs
        type=int,
        metavar="PID",
        help="Attach Mode: One or more existing process IDs (PIDs) to monitor.",
    )
    group.add_argument(
        "-c",
        "--command",
        # Use REMAINDER to capture the command and all its arguments
        nargs=argparse.REMAINDER,
        metavar="COMMAND [ARG...]",
        help="Run Mode: The command and its arguments to launch and monitor.",
    )

    args = parser.parse_args(argv)

    # --- Post-parsing Validation ---
    # Ensure command is not empty if -c is used (REMAINDER can be empty)
    if args.command is not None and not args.command:
        parser.error("argument -c/--command: requires a command to run.")

    # Check permissions if strace is selected
    if args.backend == "strace" and os.geteuid() != 0:
        # Use print directly as logging might not be fully set up yet
        print(
            "Warning: 'strace' backend typically requires root privileges.",
            file=sys.stderr,
        )

    return args


# --- Backend Worker ---


def run_backend_worker(
    backend_func: BackendFuncType,
    monitor_instance: Monitor,
    target_args: BackendArgsType,
):
    """
    Target function executed in a background thread/worker by the UI.
    Calls the selected backend's attach or run function.
    """
    # Use a logger specific to the backend execution context
    # This logger will inherit handlers from the root logger configured in main()
    worker_log = logging.getLogger(f"lsoph.backend.{backend_func.__module__}")
    try:
        worker_log.info(f"Backend worker starting function: {backend_func.__name__}")
        # Execute the actual backend function (e.g., strace.attach, lsof.run)
        backend_func(target_args, monitor_instance)
        worker_log.info(f"Backend function {backend_func.__name__} finished.")
    except Exception as e:
        # Log exceptions occurring within the backend function itself
        worker_log.exception(
            f"Unexpected error in backend worker ({backend_func.__name__}): {e}"
        )
        # Optionally, notify the UI or handle the error further


# --- Main Application Logic ---


def main(argv: Optional[List[str]] = None) -> int:
    """
    Main entry point: Parses args, sets up logging, creates Monitor,
    determines backend, and launches the Textual UI.
    """
    try:
        # 1. Parse Arguments
        args = parse_arguments(argv)

        # 2. Setup Logging
        setup_logging(args.log)
        log = logging.getLogger("lsoph.cli")  # Get logger instance after setup
        log.info("Starting lsoph...")
        log.debug(f"Parsed arguments: {args}")

        # 3. Determine Backend Function and Arguments
        selected_backend_funcs = BACKENDS.get(args.backend)
        if (
            not selected_backend_funcs
        ):  # Should be caught by argparse choices, but check anyway
            log.critical(f"Invalid backend selected: {args.backend}")
            return 1
        backend_attach_func, backend_run_func = selected_backend_funcs

        backend_func_to_run: BackendFuncType
        backend_target_args: BackendArgsType
        monitor_id: str

        if args.pids:
            backend_func_to_run = backend_attach_func
            backend_target_args = args.pids
            monitor_id = f"pids_{'_'.join(map(str, args.pids))}"
            log.info(
                f"Mode: Attach PIDs. Target: {monitor_id}, Backend: {args.backend}"
            )
        elif args.command:
            backend_func_to_run = backend_run_func
            backend_target_args = args.command
            monitor_id = shlex.join(args.command)  # Create ID from command string
            log.info(
                f"Mode: Run Command. Target: '{monitor_id}', Backend: {args.backend}"
            )
        else:
            # Should be unreachable due to required mutually exclusive group
            log.critical("Internal error: No command or PIDs specified after parsing.")
            return 1

        # 4. Create Monitor Instance
        monitor = Monitor(identifier=monitor_id)

        # 5. Launch Textual UI
        log.info("Launching Textual UI...")
        # Pass necessary components to the UI application
        app_instance = FileApp(
            monitor=monitor,
            log_queue=LOG_QUEUE,  # Pass the global log queue
            backend_func=backend_func_to_run,
            backend_args=backend_target_args,
            backend_worker_func=run_backend_worker,  # Pass the worker function itself
        )
        app_instance.run()  # Blocks until the UI exits
        log.info("Textual UI finished.")
        return 0

    except argparse.ArgumentError as e:
        print(f"Argument Error: {e}", file=sys.stderr)
        return 2  # Standard exit code for command line syntax errors
    except Exception as e:
        # Catch-all for unexpected errors during setup or UI launch
        # Use print as logging might not be working if setup failed
        print(f"FATAL ERROR: {e}", file=sys.stderr)
        # Log exception if logging was successfully configured
        if logging.getLogger().hasHandlers():
            logging.getLogger("lsoph.cli").exception(
                "Unhandled exception during execution."
            )
        return 1


if __name__ == "__main__":
    sys.exit(main())
