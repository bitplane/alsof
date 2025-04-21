#!/usr/bin/env python3
import argparse
import logging
import os
import shlex
import sys
import threading
from collections import deque

from alsof.backend import lsof, strace
from alsof.monitor import Monitor
from alsof.ui import app


class TextualLogHandler(logging.Handler):
    """A logging handler that puts messages into a deque for Textual."""

    def __init__(self, log_queue: deque):
        super().__init__()
        self.log_queue = log_queue
        # Define a formatter that includes timestamp
        formatter = logging.Formatter(
            "%(asctime)s %(name)s: %(message)s",
            datefmt="%H:%M:%S",  # Example format: HH:MM:SS
        )
        self.setFormatter(formatter)

    def emit(self, record: logging.LogRecord):
        """Emit a record, formatting it as a string with Rich markup."""
        try:
            # msg = self.format(record)
            markup = ""
            # Apply color markup *after* formatting to keep timestamp uncolored initially
            # Or include timestamp in color? Let's keep timestamp default color.
            plain_msg = f"{record.name}: {record.getMessage()}"  # Get message without timestamp for coloring
            timestamp = self.formatter.formatTime(record, self.formatter.datefmt)

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
            else:  # Default, no markup
                markup = f"{timestamp} {plain_msg}"  # Use plain_msg here too

            # Append the MARKUP STRING to the queue
            self.log_queue.append(markup)

        except Exception:
            self.handleError(record)


# Basic config will be overridden by setup later if log level arg is used
# Set root logger level, but handler format controls output appearance
logging.basicConfig(
    level=os.environ.get("LOGLEVEL", "INFO").upper()
    # format="%(name)s: %(message)s" # Format now handled by TextualLogHandler
)
log = logging.getLogger("alsof.cli")

BACKENDS = {"strace": (strace.attach, strace.run), "lsof": (lsof.attach, lsof.run)}

DEFAULT_BACKEND = list(BACKENDS)[0]


def _run_backend_thread(
    backend_func: callable,  # Use lowercase callable
    monitor_instance: Monitor,
    target_args: list[str] | list[int],  # Use built-in list and |
):
    """Target function to run the selected backend in a thread."""
    thread_log = logging.getLogger(f"alsof.backend.{backend_func.__name__}")
    try:
        thread_log.info("Starting backend function in background thread...")
        backend_func(target_args, monitor_instance)
        thread_log.info("Backend function finished.")
    except Exception as e:
        thread_log.exception(f"Unexpected error in backend thread: {e}")


def main(argv: list[str] | None = None) -> int:  # Use built-in list and |
    """
    Parses command line arguments, starts the selected backend in a thread,
    and attempts to launch the UI.
    """
    parser = argparse.ArgumentParser(
        description="Monitors file access for a command or process.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=f"Available backends: {', '.join(BACKENDS.keys())}\n"
        "Example: alsof -b strace -- find . -maxdepth 1",
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

    # --- Setup Logging Handler ---
    log_level = args.log.upper()
    log_queue = deque(maxlen=1000)  # Max 1000 lines in memory

    # Configure root logger
    root_logger = logging.getLogger()
    root_logger.setLevel(log_level)

    # Remove existing handlers (like default StreamHandler) to avoid duplicate console output
    for handler in root_logger.handlers[:]:
        root_logger.removeHandler(handler)

    # Add our custom handler
    textual_handler = TextualLogHandler(log_queue)
    # The handler now defines its own format including timestamp
    root_logger.addHandler(textual_handler)

    log.info(f"Log level set to {log_level}. Logging to Textual UI via queue.")

    # --- Setup Monitoring ---
    target_command: list[str] | None = None
    attach_ids: list[int] | None = None
    monitor_id = "monitor_session"
    backend_attach_func: callable | None = None
    backend_run_func: callable | None = None
    backend_target_args: list[str] | list[int] | None = None

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

    # --- Start Backend Thread ---
    if not backend_func_to_run or backend_target_args is None:
        log.critical("Could not determine backend function or arguments.")
        return 1

    backend_thread = threading.Thread(
        target=_run_backend_thread,
        args=(backend_func_to_run, monitor, backend_target_args),
        name=f"{args.backend}_backend",
        daemon=True,
    )

    try:
        log.info(f"Starting backend thread: {backend_thread.name}")
        backend_thread.start()
    except Exception as e:
        log.exception(f"Failed to start backend thread: {e}")
        return 1

    # --- Launch UI ---
    log.info("Attempting to launch UI...")
    exit_code = 0
    try:
        # Import app.main locally to avoid circular dependencies if app imports cli stuff

        log.info("Launching app.main()...")
        # Pass the monitor instance AND the log queue to the app
        app.main(monitor=monitor, log_queue=log_queue)
        log.info("UI main function finished.")

    except Exception as e:
        # Log critical UI errors to stderr since Textual might be down
        print(f"FATAL UI ERROR: {e}", file=sys.stderr)
        logging.exception(
            f"An unexpected error occurred launching or running the UI: {e}"
        )
        exit_code = 1
    finally:
        if backend_thread.is_alive():
            log.info("Main thread exiting, backend daemon thread will terminate.")

    return exit_code


if __name__ == "__main__":
    sys.exit(main())
