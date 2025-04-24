# Filename: src/lsoph/ui/log_screen.py
"""Full-screen display for application logs."""

import logging
import sys
from collections import deque

from textual.app import ComposeResult
from textual.binding import Binding
from textual.containers import VerticalScroll  # Keep if needed by RichLog internally
from textual.screen import Screen
from textual.timer import Timer
from textual.widgets import Footer, Header, RichLog, Static

log = logging.getLogger("lsoph.ui.log")


class LogScreen(Screen):
    """A full screen to display application logs using RichLog."""

    BINDINGS = [
        Binding("escape,q,l,ctrl+l", "app.pop_screen", "Close Logs", show=True),
        Binding("c", "clear_log", "Clear", show=True),
        # Keep scrolling bindings if needed, RichLog handles basic scrolling
        Binding("up,k", "scroll_up()", "Scroll Up", show=False),
        Binding("down,j", "scroll_down()", "Scroll Down", show=False),
        Binding("pageup", "page_up()", "Page Up", show=False),
        Binding("pagedown", "page_down()", "Page Down", show=False),
        Binding("home", "scroll_home()", "Scroll Home", show=False),
        Binding("end", "scroll_end()", "Scroll End", show=False),
    ]

    def __init__(self, log_queue: deque):
        self.log_queue = log_queue
        self._timer: Timer | None = None
        super().__init__()

    def compose(self) -> ComposeResult:
        """Create child widgets for the log screen."""
        yield Header()
        # Directly yield the RichLog, making it fill the screen body
        yield RichLog(
            id="app-log",
            max_lines=2000,  # Limit stored lines for performance
            auto_scroll=True,  # Keep scrolled to bottom by default
            wrap=False,  # Disable wrapping for log lines
            highlight=True,  # Enable syntax highlighting
            markup=True,  # Enable Rich markup
        )
        yield Footer()

    def on_mount(self) -> None:
        """Called when the screen is mounted. Populates with existing logs and starts timer."""
        try:
            log_widget = self.query_one(RichLog)
            log.debug(
                f"LogScreen mounted. Processing {len(self.log_queue)} existing log messages."
            )

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
            try:
                # Try writing error to the log widget itself
                log_widget.write(f"[bold red]Error mounting log screen: {e}[/]")
            except Exception:
                pass  # Ignore errors during error reporting

    def on_unmount(self) -> None:
        """Called when the screen is unmounted. Stops the timer."""
        if self._timer:
            try:
                self._timer.stop()
                log.debug("LogScreen unmounted. Stopped log queue timer.")
            except Exception as e:
                log.error(f"Error stopping log screen timer: {e}")
        self._timer = None  # Clear the timer reference

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

            # Write collected lines in one go if any exist
            if lines_to_write:
                for line in lines_to_write:
                    log_widget.write(line)
                # Optionally scroll to end only if new lines were added and auto_scroll is desired
                # log_widget.scroll_end(animate=False)
        except Exception as e:
            # Log error to stderr as the log screen itself might be broken
            print(f"ERROR: Error processing log queue: {e}", file=sys.stderr)
            # Optionally stop the timer to prevent repeated errors
            # if self._timer: self._timer.stop()

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
    # RichLog handles scrolling internally, but bindings can target its methods
    def action_scroll_up(self) -> None:
        try:
            self.query_one(RichLog).scroll_up(animate=False)
        except Exception:
            pass  # Ignore errors if widget not found

    def action_scroll_down(self) -> None:
        try:
            self.query_one(RichLog).scroll_down(animate=False)
        except Exception:
            pass

    def action_page_up(self) -> None:
        try:
            self.query_one(RichLog).scroll_page_up(animate=False)
        except Exception:
            pass

    def action_page_down(self) -> None:
        try:
            self.query_one(RichLog).scroll_page_down(animate=False)
        except Exception:
            pass

    def action_scroll_home(self) -> None:
        try:
            self.query_one(RichLog).scroll_home(animate=False)
        except Exception:
            pass

    def action_scroll_end(self) -> None:
        try:
            self.query_one(RichLog).scroll_end(animate=False)
        except Exception:
            pass
