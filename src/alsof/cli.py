#!/usr/bin/env python3

# Filename: cli.py

import argparse
import logging
import os
import shlex
import sys
import threading
import time
from typing import Callable, List, Optional, Union

from alsof import strace
from alsof.monitor import Monitor

logging.basicConfig(
    level=os.environ.get("LOGLEVEL", "WARNING").upper(),
    format="%(levelname)s:%(name)s:%(message)s",
)
log = logging.getLogger(__name__)  # Logger for this module


BACKENDS = {"strace": (strace.attach, strace.run)}

DEFAULT_BACKEND = next(iter(BACKENDS.keys())) if BACKENDS else None


def _run_backend_thread(
    backend_func: Callable,  # Type hint could be more specific Union[attach_type, run_type]
    monitor_instance: Monitor,
    target_args: Union[List[str], List[int]],  # Either command list or pid list
):
    """Target function to run the selected backend in a thread."""
    try:
        log.info(
            f"Starting backend function {backend_func.__name__} in background thread..."
        )
        # We assume the backend function (run or attach) handles its own exceptions
        # and logging, and blocks until monitoring stops or fails.
        backend_func(target_args, monitor_instance)  # type: ignore # Ignore type check if Callable is too generic
        log.info(f"Backend function {backend_func.__name__} finished.")
    except Exception as e:
        # Log any unexpected errors from the backend function itself
        log.exception(
            f"Unexpected error in backend thread {backend_func.__name__}: {e}"
        )


# --- Main Execution Function ---


def main(argv: Optional[List[str]] = None) -> int:
    """
    Parses command line arguments, starts the selected backend in a thread,
    and attempts to launch the UI.
    """
    # Configure logging level based on potential command-line arg or default
    # This gets potentially reconfigured after parsing args.
    initial_log_level = os.environ.get("LOGLEVEL", "INFO").upper()
    if initial_log_level not in ["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"]:
        initial_log_level = "INFO"
    logging.basicConfig(
        level=initial_log_level, format="%(asctime)s %(levelname)s:%(name)s:%(message)s"
    )
    log.info(f"Initial log level set to {initial_log_level}")

    if not BACKENDS or DEFAULT_BACKEND is None:
        log.critical("No monitoring backends available!")
        return 1

    parser = argparse.ArgumentParser(
        description="Monitors file access for a command or process.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=f"Available backends: {', '.join(BACKENDS.keys())}\n"
        "Example: python3 %(prog)s -b strace -- find . -maxdepth 1",
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

    # Simpler arg parsing assuming REMAINDER works correctly after known args
    args = parser.parse_args(argv)

    # Reconfigure logging level based on args NOW
    logging.getLogger().setLevel(args.log.upper())
    log.info(f"Log level set to {args.log.upper()}")

    # --- Setup Monitoring ---
    target_command: Optional[List[str]] = None
    attach_ids: Optional[List[int]] = None
    monitor_id = "monitor_session"
    backend_attach_func: Optional[Callable] = None
    backend_run_func: Optional[Callable] = None
    backend_target_args: Optional[Union[List[str], List[int]]] = None

    selected_backend_funcs = BACKENDS.get(args.backend)
    if not selected_backend_funcs:
        # This case should be prevented by argparse choices, but check anyway
        log.critical(f"Selected backend '{args.backend}' not found in BACKENDS dict.")
        return 1
    backend_attach_func, backend_run_func = selected_backend_funcs

    if args.command:
        # argparse.REMAINDER includes the '-c' if it wasn't handled specially.
        # We need to handle the case where REMAINDER might be empty if only '-c' is given
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
        daemon=True,  # Allow main thread to exit even if backend is running
    )

    try:
        log.info(f"Starting backend thread: {backend_thread.name}")
        backend_thread.start()
    except Exception as e:
        log.exception(f"Failed to start backend thread: {e}")
        return 1

    # --- Launch UI (Placeholder) ---
    log.info("Attempting to launch UI...")
    try:
        # Assume app.py exists and has a main function accepting the monitor
        import app

        log.info("Launching app.main()...")
        # We assume app.main() blocks until the UI exits
        # Pass monitor and potentially the backend thread if UI needs to manage it?
        app.main(monitor=monitor)
        log.info("UI main function finished.")

    except ImportError:
        log.warning("UI module 'app.py' not found.")
        log.info("Backend monitoring running in background. Press Ctrl+C to stop.")
        # Keep main thread alive while backend runs
        try:
            while backend_thread.is_alive():
                time.sleep(0.5)  # Check periodically, allows Ctrl+C
        except KeyboardInterrupt:
            log.info("\nCtrl+C detected in main loop. Signaling backend.")
            # How to signal backend thread? Need a shared flag or event.
            # For now, daemon thread will just exit abruptly.
            return 130
        except Exception as e:
            log.exception(f"Error while waiting for backend thread: {e}")
            return 1

    except Exception as e:
        log.exception(f"An unexpected error occurred launching or running the UI: {e}")
        if backend_thread.is_alive():
            log.info("UI crashed, waiting for backend thread to finish (or Ctrl+C)...")
            try:
                while backend_thread.is_alive():
                    time.sleep(0.5)
            except KeyboardInterrupt:
                return 130
            except Exception:
                pass
        return 1

    return 0  # Success if UI exits cleanly


# --- Script Entry Point ---

if __name__ == "__main__":
    # Ensure necessary modules are importable from current dir or PYTHONPATH
    # e.g., monitor.py, strace.py, strace_cmd.py, versioned.py
    sys.exit(main())
