#!/usr/bin/env python3
import argparse
import logging
import os
import shlex
import sys
import threading
from collections import deque
from typing import Callable, List, Optional, Union

from alsof import app, strace
from alsof.monitor import Monitor


class TextualLogHandler(logging.Handler):
    """A logging handler that puts messages into a deque."""

    def __init__(self, log_queue: deque):
        super().__init__()
        self.log_queue = log_queue

    def emit(self, record: logging.LogRecord):
        """Emit a record."""
        try:
            msg = self.format(record)
            self.log_queue.append(msg)
        except Exception:
            self.handleError(record)


# Basic config will be overridden by setup later if log level arg is used
logging.basicConfig(
    level=os.environ.get("LOGLEVEL", "WARNING").upper(), format="%(name)s: %(message)s"
)  # Simplified format for app log
log = logging.getLogger("alsof.cli")

BACKENDS = {"strace": (strace.attach, strace.run)}

DEFAULT_BACKEND = list(BACKENDS)[0]


def _run_backend_thread(
    backend_func: Callable,
    monitor_instance: Monitor,
    target_args: Union[List[str], List[int]],
):
    """Target function to run the selected backend in a thread."""
    thread_log = logging.getLogger(f"alsof.backend.{backend_func.__name__}")
    try:
        thread_log.info("Starting backend function in background thread...")
        backend_func(target_args, monitor_instance)
        thread_log.info("Backend function finished.")
    except Exception as e:
        thread_log.exception(f"Unexpected error in backend thread: {e}")


def main(argv: Optional[List[str]] = None) -> int:
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
    # Log file argument - consider adding later if needed
    # parser.add_argument('--log-file', default=None, help='Redirect logs to a file.')

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
    # Optional: Add a formatter if desired, otherwise uses root logger's effective format
    # formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
    # textual_handler.setFormatter(formatter)
    root_logger.addHandler(textual_handler)

    # Optional: Add a handler just for stderr/file if needed *in addition* to Textual
    # console_handler = logging.StreamHandler(sys.stderr)
    # console_handler.setLevel(log_level)
    # console_formatter = logging.Formatter('%(asctime)s %(levelname)s:%(name)s:%(message)s')
    # console_handler.setFormatter(console_formatter)
    # root_logger.addHandler(console_handler)

    log.info(f"Log level set to {log_level}. Logging to Textual UI via queue.")

    # --- Setup Monitoring ---
    target_command: Optional[List[str]] = None
    attach_ids: Optional[List[int]] = None
    monitor_id = "monitor_session"
    backend_attach_func: Optional[Callable] = None
    backend_run_func: Optional[Callable] = None
    backend_target_args: Optional[Union[List[str], List[int]]] = None

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
