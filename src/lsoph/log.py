# Filename: src/lsoph/log.py
"""Logging setup for the lsoph application."""

import logging
import sys
from collections import deque
from typing import Optional  # Added Optional type hint

# --- Define TRACE level ---
TRACE_LEVEL_NUM = 5
logging.addLevelName(TRACE_LEVEL_NUM, "TRACE")


def trace(self, message, *args, **kws):
    # Yes, logger takes its '*args' as 'args'.
    if self.isEnabledFor(TRACE_LEVEL_NUM):
        self._log(TRACE_LEVEL_NUM, message, args, **kws)


logging.Logger.trace = trace
# --- End TRACE level definition ---


# Global deque for log messages to be displayed in the TUI
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
            elif record.levelno >= TRACE_LEVEL_NUM:
                markup = f"{timestamp} [dim white on grey11]{plain_msg}[/]"  # Example: very dim
            else:
                markup = f"{timestamp} {plain_msg}"

            # Append the marked-up string to the shared queue
            self.log_queue.append(markup)
        except Exception:
            self.handleError(record)


# --- Ensure this function signature matches the call in cli.py ---
def setup_logging(
    level_name: str = "INFO", log_file: Optional[str] = None
):  # Added log_file parameter
    """
    Configures the root logger to use the TextualLogHandler and optionally a FileHandler.
    """
    # --- Recognize TRACE level ---
    level_name_upper = level_name.upper()
    if level_name_upper == "TRACE":
        log_level = TRACE_LEVEL_NUM
    else:
        log_level = getattr(logging, level_name_upper, logging.INFO)
    # ---------------------------

    root_logger = logging.getLogger()  # Get the root logger
    root_logger.setLevel(log_level)  # Set root logger level

    # Remove any existing handlers (e.g., from basicConfig in imports)
    for handler in root_logger.handlers[:]:
        root_logger.removeHandler(handler)

    # Create a standard formatter for the FileHandler
    log_formatter = logging.Formatter(
        "%(asctime)s %(levelname)-8s %(name)-25s %(message)s", datefmt="%H:%M:%S"
    )

    # 1. Add our custom handler that writes to the TUI LOG_QUEUE
    textual_handler = TextualLogHandler(LOG_QUEUE)
    textual_handler.setLevel(log_level)
    # Note: TextualLogHandler uses its own internal formatting with Rich markup
    root_logger.addHandler(textual_handler)

    # 2. Add FileHandler if a path is provided
    if log_file:
        try:
            file_handler = logging.FileHandler(log_file, mode="a", encoding="utf-8")
            file_handler.setLevel(log_level)  # Set level for file handler too
            file_handler.setFormatter(log_formatter)  # Use standard formatter
            root_logger.addHandler(file_handler)
            # Use logging here *after* handler is added
            logging.getLogger("lsoph").info(f"Logging to file: {log_file}")
        except OSError as e:
            # Log error to stderr if file handler fails
            print(f"Error: Could not open log file '{log_file}': {e}", file=sys.stderr)
            # Also try logging it, although it might only go to TUI handler
            logging.getLogger("lsoph").error(
                f"Failed to open log file '{log_file}': {e}"
            )

    # Use the root logger to log the configuration message
    logging.getLogger("lsoph").info(
        f"Logging configured at level {logging.getLevelName(log_level)}."
    )
