#!/usr/bin/env python3
import argparse
import logging
import os
import shlex
import sys
from collections import deque
from typing import Callable, List, Union

from lsoph.backend import lsof, psutil, strace
from lsoph.monitor import Monitor
from lsoph.ui.app import FileApp

# Define the type for backend functions and arguments
BackendFuncType = Callable[[Union[List[int], List[str]], Monitor], None]
BackendArgsType = Union[List[int], List[str]]


class TextualLogHandler(logging.Handler):
    """A logging handler that puts messages into a deque for Textual."""

    def __init__(self, log_queue: deque):
        super().__init__()
        self.log_queue = log_queue
        formatter = logging.Formatter(
            "%(asctime)s %(name)s: %(message)s", datefmt="%H:%M:%S"
        )
        self.setFormatter(formatter)

    def emit(self, record: logging.LogRecord):
        """Emit a record, formatting it as a string with Rich markup."""
        try:
            plain_msg = f"{record.name}: {record.getMessage()}"
            timestamp = self.formatter.formatTime(record, self.formatter.datefmt)
            markup = ""
            if record.levelno == logging.CRITICAL:
                markup = f"{timestamp} [bold red]{plain_msg}[/bold red]"
            elif record.levelno == logging.ERROR:
                markup = f"{timestamp} [red]{plain_msg}[/red]"
            elif record.levelno == logging.WARNING:
                markup = f"{timestamp} [yellow]{plain_msg}[/yellow]"
            elif record.levelno == logging.INFO:
                markup = f"{timestamp} [green]{plain_msg}[/green]"
            elif record.levelno == logging.DEBUG:
                markup = f"{timestamp} [dim]{plain_msg}[/dim]"
            else:
                markup = f"{timestamp} {plain_msg}"
            self.log_queue.append(markup)
        except Exception:
            self.handleError(record)


# Get root logger instance ONCE
log = logging.getLogger("lsoph.cli")

BACKENDS = {
    "strace": (strace.attach, strace.run),
    "lsof": (lsof.attach, lsof.run),
    "psutil": (psutil.attach, psutil.run),
}
DEFAULT_BACKEND = list(BACKENDS)[0]


# This function is now the target for the Textual worker
def run_backend_worker(
    backend_func: BackendFuncType,
    monitor_instance: Monitor,
    target_args: BackendArgsType,
):
    """Target function to run the selected backend in a background worker/thread."""
    # Use a logger specific to the backend execution context
    # Note: This logger will inherit handlers from the root logger configured in main()
    worker_log = logging.getLogger(f"lsoph.backend.{backend_func.__module__}")
    try:
        worker_log.info("Starting backend function in background worker...")
        backend_func(target_args, monitor_instance)
        worker_log.info("Backend function finished.")
    except Exception as e:
        # Log exceptions occurring within the backend function
        worker_log.exception(f"Unexpected error in backend worker: {e}")


def main(argv: list[str] | None = None) -> int:
    """
    Parses command line arguments, sets up logging and monitor,
    and launches the UI, passing backend details for later execution.
    """
    parser = argparse.ArgumentParser(
        description="Monitors file access for a command or process.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=f"Available backends: {', '.join(BACKENDS.keys())}\n"
        "Example: lsoph -b strace -- find . -maxdepth 1",
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
        help="Set the logging level (default: INFO)",
    )
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument(
        "-c",
        "--command",
        nargs=argparse.REMAINDER,
        help="Launch: The target command and its arguments.",
    )
    group.add_argument(
        "-p",
        "--pids",
        nargs="+",
        type=int,
        metavar="PID",
        help="Attach: One or more existing process IDs (PIDs) to attach to.",
    )

    args = parser.parse_args(argv)

    # --- Centralized Logging Setup ---
    log_level = args.log.upper()
    log_queue = deque(maxlen=1000)  # Max 1000 lines in memory

    # Configure root logger ONCE
    root_logger = logging.getLogger()  # Get the root logger
    root_logger.setLevel(log_level)

    # Remove any handlers potentially added by basicConfig in imported modules
    for handler in root_logger.handlers[:]:
        root_logger.removeHandler(handler)

    # Add our custom handler for the TUI
    textual_handler = TextualLogHandler(log_queue)
    root_logger.addHandler(textual_handler)

    # Optionally, add a handler for critical errors to stderr just in case TUI fails
    # stream_handler = logging.StreamHandler(sys.stderr)
    # stream_handler.setLevel(logging.ERROR)
    # stream_formatter = logging.Formatter("%(levelname)s:%(name)s:%(message)s")
    # stream_handler.setFormatter(stream_formatter)
    # root_logger.addHandler(stream_handler)

    log.info(f"Log level set to {log_level}. Logging configured.")
    # --- End Logging Setup ---

    # --- Setup Monitoring ---
    target_command: list[str] | None = None
    attach_ids: list[int] | None = None
    monitor_id = "monitor_session"
    backend_func_to_run: BackendFuncType | None = None
    backend_target_args: BackendArgsType | None = None

    selected_backend_funcs = BACKENDS.get(args.backend)
    if not selected_backend_funcs:
        log.critical(f"Selected backend '{args.backend}' not found.")
        return 1
    backend_attach_func, backend_run_func = selected_backend_funcs

    if args.command:
        if not args.command:
            parser.error("argument -c/--command: expected one or more arguments")
        target_command = args.command
        monitor_id = shlex.join(target_command)
        backend_func_to_run = backend_run_func
        backend_target_args = target_command
        log.info(f"Mode: Run Command. Target: {monitor_id}")
    elif args.pids:
        attach_ids = args.pids
        monitor_id = f"pids_{'_'.join(map(str, attach_ids))}"
        backend_func_to_run = backend_attach_func
        backend_target_args = attach_ids
        log.info(f"Mode: Attach PIDs. Target: {monitor_id}")
    else:
        log.critical("Internal error: No command or PIDs specified.")
        return 1

    if os.geteuid() != 0 and args.backend == "strace":
        log.warning("Running strace backend without root. Permissions errors likely.")

    monitor = Monitor(identifier=monitor_id)

    # --- Prepare Backend Info for App ---
    if not backend_func_to_run or backend_target_args is None:
        log.critical("Could not determine backend function or arguments.")
        return 1

    # --- Launch UI ---
    log.info("Attempting to launch UI...")
    exit_code = 0
    try:
        # Pass monitor, log_queue, AND backend details to the App
        app_instance = FileApp(
            monitor=monitor,
            log_queue=log_queue,
            backend_func=backend_func_to_run,
            backend_args=backend_target_args,
            backend_worker_func=run_backend_worker,  # Pass the actual worker function
        )
        app_instance.run()
        log.info("UI main function finished.")

    except Exception as e:
        print(f"FATAL UI ERROR: {e}", file=sys.stderr)  # Print direct to stderr
        logging.exception(
            f"An unexpected error occurred launching or running the UI: {e}"
        )
        exit_code = 1

    return exit_code


if __name__ == "__main__":
    sys.exit(main())
