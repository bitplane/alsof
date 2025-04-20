#!/usr/bin/env python3

# Filename: cli.py

import argparse
import logging
import os
import shlex
import sys
import threading
import time
from typing import Callable, Dict, List, Optional, Tuple, Union

from alsof import strace  # Import the adapter module
from alsof import app
from alsof.monitor import Monitor

# --- Setup Logging ---
logging.basicConfig(
    level=os.environ.get("LOGLEVEL", "WARNING").upper(),
    format="%(levelname)s:%(name)s:%(message)s",
)
# Use package-aware logger name
log = logging.getLogger("alsof.cli")

# --- Backend Registry ---
AttachFuncType = Callable[[List[int], Monitor], None]
RunFuncType = Callable[[List[str], Monitor], None]
BackendTuple = Tuple[AttachFuncType, RunFuncType]

BACKENDS: Dict[str, BackendTuple] = {}
if (
    hasattr(strace, "attach")
    and callable(strace.attach)
    and hasattr(strace, "run")
    and callable(strace.run)
):
    BACKENDS["strace"] = (strace.attach, strace.run)
    log.info("Registered strace backend.")
else:
    # This log might not appear if basicConfig level is WARNING
    log.warning(
        "Could not register strace backend (missing or non-callable attach/run functions)."
    )

DEFAULT_BACKEND = next(iter(BACKENDS.keys())) if BACKENDS else None

# --- Backend Execution Thread ---


def _run_backend_thread(
    backend_func: Callable,
    monitor_instance: Monitor,
    target_args: Union[List[str], List[int]],
):
    """Target function to run the selected backend in a thread."""
    # Setup logging within the thread if necessary, or rely on root config
    thread_log = logging.getLogger(f"{__name__}.backend")
    try:
        thread_log.info(
            f"Starting backend function {backend_func.__name__} in background thread..."
        )
        # We assume the backend function (run or attach) handles its own exceptions
        # and logging, and blocks until monitoring stops or fails.
        backend_func(
            target_args, monitor_instance
        )  # Call the actual run/attach function
        thread_log.info(f"Backend function {backend_func.__name__} finished.")
    except Exception as e:
        # Log any unexpected errors from the backend function itself
        thread_log.exception(
            f"Unexpected error in backend thread {backend_func.__name__}: {e}"
        )


# --- Main Execution Function ---


def main(argv: Optional[List[str]] = None) -> int:
    """
    Parses command line arguments, starts the selected backend in a thread,
    and attempts to launch the UI.
    """
    # Configure root logger level based on default or env var initially
    initial_log_level = os.environ.get("LOGLEVEL", "INFO").upper()
    if initial_log_level not in ["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"]:
        initial_log_level = "INFO"
    # Use basicConfig defaults, but ensure level is set.
    # Note: Subsequent calls to basicConfig might not reconfigure if handlers exist.
    # Consider using logging.getLogger().setLevel() after parsing args instead.
    logging.basicConfig(
        level=initial_log_level, format="%(asctime)s %(levelname)s:%(name)s:%(message)s"
    )
    log.info(f"Initial log level set to {initial_log_level}")  # Use module logger

    if not BACKENDS or DEFAULT_BACKEND is None:
        log.critical("No monitoring backends available!")
        return 1

    parser = argparse.ArgumentParser(
        description="Monitors file access for a command or process.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=f"Available backends: {', '.join(BACKENDS.keys())}\n"
        "Example: alsof -b strace -- find . -maxdepth 1",  # Updated example
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
        default="INFO",  # Default to INFO when run from CLI
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

    # Reconfigure root logger level based on args NOW
    logging.getLogger().setLevel(args.log.upper())
    log.info(f"Log level set to {args.log.upper()}")  # Use module logger

    # --- Setup Monitoring ---
    target_command: Optional[List[str]] = None
    attach_ids: Optional[List[int]] = None
    monitor_id = "monitor_session"
    backend_attach_func: Optional[AttachFuncType] = None
    backend_run_func: Optional[RunFuncType] = None
    backend_target_args: Optional[Union[List[str], List[int]]] = None

    selected_backend_funcs = BACKENDS.get(args.backend)
    if not selected_backend_funcs:
        # This case should be prevented by argparse choices, but check anyway
        log.critical(f"Selected backend '{args.backend}' not found in BACKENDS dict.")
        return 1
    backend_attach_func, backend_run_func = selected_backend_funcs

    if args.command:
        # REMAINDER captures everything after the known args,
        # need to ensure it doesn't capture flags meant for argparse if -c isn't last.
        # This simple check assumes -c IS last or only flags before it are --log/--backend
        if not args.command:
            parser.error("argument -c/--command: expected one or more arguments")
        target_command = args.command
        monitor_id = shlex.join(target_command)  # Create ID from command
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
        # Should be caught by argparse group 'required=True'
        log.critical("Internal error: No command or PIDs specified.")
        return 1

    # Check permissions only if using strace backend
    if os.geteuid() != 0 and args.backend == "strace":
        log.warning(
            "Running strace backend without root. strace/psutil may fail or lack permissions."
        )

    # Create the Monitor instance
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
        app.main(monitor=monitor)
        log.info("UI main function finished.")
    except Exception as e:
        log.exception(f"An unexpected error occurred launching or running the UI: {e}")
        exit_code = 1
    finally:
        # Ensure backend thread is considered finished if main loop exits
        if backend_thread.is_alive():
            log.info("Main thread exiting, backend daemon thread will terminate.")
            # We don't explicitly stop the backend thread here, rely on daemon status

    return exit_code


# --- Script Entry Point ---

if __name__ == "__main__":
    # Ensure necessary modules are importable from current dir or PYTHONPATH
    # e.g., monitor.py, strace.py, strace_cmd.py, versioned.py
    # Assumes running from project root or installed package
    sys.exit(main())
