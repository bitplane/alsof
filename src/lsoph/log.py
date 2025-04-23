# Filename: src/lsoph/log.py
"""Logging setup for the lsoph application."""

import logging
import sys
from collections import deque

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

    # Use the root logger to log the configuration message
    logging.getLogger("lsoph").info(f"Logging configured at level {level_name}.")
