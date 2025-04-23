# Filename: src/lsoph/ui/log_screen.py
"""Modal screen for displaying application logs."""

import logging
import sys
from collections import deque

from textual.app import ComposeResult
from textual.binding import Binding
from textual.containers import Container, VerticalScroll  # Added Container
from textual.screen import ModalScreen
from textual.widgets import RichLog, Static  # Added Static

log = logging.getLogger("lsoph.ui.log")


class LogScreen(ModalScreen[None]):
    """A modal screen to display application logs using RichLog."""

    BINDINGS = [
        Binding(
            "escape,q,l,ctrl+l", "app.pop_screen", "Close Logs", show=True
        ),  # Use same keys
        Binding("c", "clear_log", "Clear", show=True),
        Binding("up,k", "scroll_up", "Scroll Up", show=False),
        Binding("down,j", "scroll_down", "Scroll Down", show=False),
        Binding("pageup", "page_up", "Page Up", show=False),
        Binding("pagedown", "page_down", "Page Down", show=False),
        Binding("home", "scroll_home", "Scroll Home", show=False),
        Binding("end", "scroll_end", "Scroll End", show=False),
    ]

    # Add CSS for layout within the modal container
    DEFAULT_CSS = """
    LogScreen > Container {
        border: thick $accent;
        padding: 1 2; /* Add padding */
        width: 80%;
        height: 80%;
        background: $surface;
        /* Use grid for simple header/log layout */
        grid-size: 1;
        grid-rows: auto 1fr; /* Header row, Log row takes remaining space */
        grid-gutter: 1;
    }

    #log-header {
        height: auto;
        margin-bottom: 1;
    }

    #log-scroll-container {
        border: round $panel; /* Add border to log area */
    }

    #app-log {
        /* Ensure log fills its container */
        width: 100%;
        height: 100%;
    }
    """

    def __init__(self, log_queue: deque):
        self.log_queue = log_queue
        self._timer = None
        super().__init__()

    def compose(self) -> ComposeResult:
        """Create child widgets for the log screen."""
        # Use a container for centering and styling the modal content
        with Container(id="log-modal-container"):
            yield Static("[bold]Application Log[/]", id="log-header")
            # Use VerticalScroll for the log content area
            with VerticalScroll(id="log-scroll-container"):
                yield RichLog(
                    id="app-log",
                    max_lines=2000,  # Keep a reasonable buffer
                    auto_scroll=True,
                    wrap=False,  # Keep wrap false for potentially long lines
                    highlight=True,
                    markup=True,  # Enable Rich markup
                )

    def on_mount(self) -> None:
        """Called when the screen is mounted. Populates with existing logs and starts timer."""
        log_widget = self.query_one(RichLog)
        log.debug(
            f"LogScreen mounted. Processing {len(self.log_queue)} existing log messages."
        )
        try:
            # Write existing logs from the queue
            existing_logs = list(self.log_queue)  # Copy queue items
            if existing_logs:
                for line in existing_logs:
                    log_widget.write(line)  # Write each line
                log_widget.scroll_end(
                    animate=False
                )  # Scroll to bottom after initial load
            # Start timer to check for new logs periodically
            self._timer = self.set_interval(
                1 / 10, self._check_log_queue
            )  # Check 10 times/sec
        except Exception as e:
            log.exception(f"Error during LogScreen mount: {e}")
            # Try to display error in the log widget itself
            try:
                log_widget.write(f"[bold red]Error mounting log screen: {e}[/]")
            except Exception:
                pass

    def on_unmount(self) -> None:
        """Called when the screen is unmounted. Stops the timer."""
        if self._timer:
            try:
                self._timer.stop()
                log.debug("LogScreen unmounted. Stopped log queue timer.")
            except Exception as e:
                log.error(f"Error stopping log screen timer: {e}")
        self._timer = None

    def _check_log_queue(self) -> None:
        """Periodically check the log queue and write new lines to RichLog."""
        try:
            log_widget = self.query_one(RichLog)
            lines_to_write = []
            # Efficiently drain the queue
            while True:
                try:
                    record = self.log_queue.popleft()
                    lines_to_write.append(record)
                except IndexError:
                    break  # Queue is empty
            # Write collected lines
            if lines_to_write:
                for line in lines_to_write:
                    log_widget.write(line)
                # Optional: only scroll if auto_scroll is enabled or user is at bottom
                # if log_widget.auto_scroll: log_widget.scroll_end(animate=False)
        except Exception as e:
            # Avoid logging error *to the queue* if queue processing fails
            print(f"ERROR: Error processing log queue: {e}", file=sys.stderr)

    def action_clear_log(self) -> None:
        """Action to clear the log display."""
        try:
            log_widget = self.query_one(RichLog)
            log_widget.clear()
            self.notify("Logs cleared.", timeout=1)
            log.info("Log display cleared by user.")
        except Exception as e:
            log.exception("Error clearing log display.")
            self.notify("Error clearing log.", severity="error", timeout=3)

    # --- Scrolling Actions ---
    def action_scroll_up(self) -> None:
        self.query_one(RichLog).scroll_up(animate=False)

    def action_scroll_down(self) -> None:
        self.query_one(RichLog).scroll_down(animate=False)

    def action_page_up(self) -> None:
        self.query_one(RichLog).scroll_page_up(animate=False)

    def action_page_down(self) -> None:
        self.query_one(RichLog).scroll_page_down(animate=False)

    def action_scroll_home(self) -> None:
        self.query_one(RichLog).scroll_home(animate=False)

    def action_scroll_end(self) -> None:
        self.query_one(RichLog).scroll_end(animate=False)
