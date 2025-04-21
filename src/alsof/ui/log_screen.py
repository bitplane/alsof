# Filename: screens/log_screen.py
"""Modal screen for displaying application logs."""

import logging
import sys # Import sys for stderr
import os # Import os for linesep potentially (though write handles newlines)
from collections import deque

from rich.text import Text # Required if Text objects are ever put in queue
from textual.binding import Binding
from textual.containers import VerticalScroll
from textual.screen import ModalScreen
# Import RichLog instead of Log
from textual.widgets import RichLog
from textual.app import ComposeResult # Import ComposeResult

log = logging.getLogger(__name__) # Use module-specific logger

class LogScreen(ModalScreen[None]):
    """A modal screen to display application logs using RichLog."""

    BINDINGS = [
        Binding("escape,q,ctrl+l", "app.pop_screen", "Close Logs", show=True),
        Binding("c", "clear_log", "Clear", show=True),
    ]

    def __init__(self, log_queue: deque):
        self.log_queue = log_queue
        self._timer = None
        super().__init__()

    def compose(self) -> ComposeResult:
        """Create child widgets for the log screen."""
        with VerticalScroll(id="log-container"):
            # Use RichLog instead of Log
            # RichLog implicitly handles markup
            yield RichLog(id="app-log", max_lines=2000, auto_scroll=True, wrap=False, highlight=True) # Added highlight, wrap=False

    def on_mount(self) -> None:
        """Called when the screen is mounted."""
        log_widget = self.query_one(RichLog) # Query for RichLog
        log.debug(
            f"LogScreen mounted. Processing {len(self.log_queue)} existing log messages."
        )
        # --- Debug Print Added ---
        try:
            # Print queue length directly to stderr for debugging
            print(f"DEBUG: LogScreen on_mount: Queue length={len(self.log_queue)}", file=sys.stderr)
        except Exception as e:
            print(f"DEBUG: Error printing queue state: {e}", file=sys.stderr)
        # --- End Debug Print ---

        existing_logs = list(self.log_queue)
        if existing_logs:
            # Write each line individually
            for line in existing_logs:
                log_widget.write(line) # Write handles markup string and adds newline
        self._timer = self.set_interval(1 / 10, self._check_log_queue)

    def on_unmount(self) -> None:
        """Called when the screen is unmounted."""
        if self._timer:
            self._timer.stop()
            log.debug("LogScreen unmounted. Stopped log queue timer.")

    def _check_log_queue(self) -> None:
        """Periodically check the log queue and write new lines."""
        try:
             log_widget = self.query_one(RichLog) # Query for RichLog
             count = 0
             lines_to_write = []
             while self.log_queue:
                 try:
                     # Get markup string from queue
                     record = self.log_queue.popleft()
                     lines_to_write.append(record)
                     count += 1
                 except IndexError:
                     break
             # Write collected lines individually
             if lines_to_write:
                 for line in lines_to_write:
                     log_widget.write(line) # Write handles markup string and adds newline
                 # log.debug(f"Processed {count} new log messages from queue.")
        except Exception as e:
             # Avoid logging error *to the queue* if queue processing fails
             print(f"ERROR: Error processing log queue: {e}", file=sys.stderr)


    def action_clear_log(self) -> None:
        """Action to clear the log display."""
        try:
             log_widget = self.query_one(RichLog) # Query for RichLog
             log_widget.clear()
             self.notify("Logs cleared.", timeout=1)
        except Exception as e:
             log.error(f"Error clearing log: {e}", exc_info=True) # Log normally here
             self.notify("Error clearing log.", severity="error", timeout=3)
