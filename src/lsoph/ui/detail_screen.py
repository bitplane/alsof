# Filename: src/lsoph/ui/detail_screen.py
"""Full-screen display for file event history."""

import datetime
import logging
from typing import Any

from rich.text import Text
from textual.app import ComposeResult
from textual.binding import Binding
from textual.containers import Vertical
from textual.screen import Screen
from textual.widgets import Footer, Header, RichLog, Static

from lsoph.monitor import FileInfo
from lsoph.util.short_path import short_path

log = logging.getLogger("lsoph.ui.detail")


class DetailScreen(Screen):
    """Screen to display event history and details for a specific file."""

    BINDINGS = [
        Binding("escape,q,d,enter", "app.pop_screen", "Close", show=True),
        # Keep scrolling bindings for RichLog accessibility
        Binding("up,k", "scroll_up()", "Scroll Up", show=False),
        Binding("down,j", "scroll_down()", "Scroll Down", show=False),
        Binding("pageup", "page_up()", "Page Up", show=False),
        Binding("pagedown", "page_down()", "Page Down", show=False),
        Binding("home", "scroll_home()", "Scroll Home", show=False),
        Binding("end", "scroll_end()", "Scroll End", show=False),
    ]

    def __init__(self, file_info: FileInfo):
        self.file_info = file_info
        super().__init__()

    def compose(self) -> ComposeResult:
        """Create child widgets for the detail screen."""
        yield Header()
        # Use a Vertical container to stack the header and log
        with Vertical(id="detail-content"):
            yield Static(self._create_header_text(), id="detail-header")
            yield RichLog(
                id="event-log",
                max_lines=2000,  # Limit stored lines for performance
                markup=True,  # Enable Rich markup
                highlight=True,  # Enable syntax highlighting
                wrap=False,  # Disable wrapping for log lines
                auto_scroll=True,  # Keep scrolled to bottom initially
            )
        yield Footer()

    def _create_header_text(self) -> Text:
        """Creates the header text displayed above the log."""
        path_display = short_path(self.file_info.path, 100)  # Allow more space
        status = self.file_info.status.upper()
        style = ""
        # Apply styling based on status
        if self.file_info.status == "error":
            style = "bold red"
        elif self.file_info.is_open:
            style = "bold green"
        elif self.file_info.status == "deleted":
            style = "strike"

        header = Text.assemble(
            "Details for: ", (path_display, "bold"), " | Status: ", (status, style)
        )
        return header

    def on_mount(self) -> None:
        """Called when the screen is mounted. Populates the log."""
        try:
            log_widget = self.query_one(RichLog)
            # Update the static header widget as well
            self.query_one("#detail-header", Static).update(self._create_header_text())

            history = self.file_info.event_history
            log.debug(
                f"DetailScreen on_mount: Populating with {len(history)} history events."
            )

            if not history:
                log_widget.write("No event history recorded for this file.")
                return

            # Add header row for clarity
            log_widget.write(
                Text.assemble(
                    ("Timestamp".ljust(12), "bold blue"),  # Pad timestamp
                    " | ",
                    ("Event".ljust(8), "bold blue"),  # Pad event type
                    " | ",
                    ("Result".ljust(4), "bold blue"),  # Pad result
                    " | ",
                    ("Details", "bold blue"),
                )
            )
            log_widget.write("-" * 80)  # Separator

            # Write each event from history
            for event in history:
                # Format timestamp
                ts_raw = event.get("ts", 0)
                ts_str = f"{ts_raw:.3f}"  # Default format
                try:
                    if isinstance(ts_raw, (int, float)) and ts_raw > 0:
                        # Format as H:M:S.ms if possible
                        ts_str = datetime.datetime.fromtimestamp(ts_raw).strftime(
                            "%H:%M:%S.%f"
                        )[
                            :-3
                        ]  # Trim to milliseconds
                except (TypeError, ValueError, OSError) as ts_err:
                    log.warning(f"Could not format timestamp {ts_raw}: {ts_err}")
                ts_formatted = ts_str.ljust(12)  # Pad to align

                # Format event type
                etype = str(event.get("type", "?")).upper().ljust(8)  # Pad

                # Format result (OK/FAIL)
                success = event.get("success", False)
                result_markup = "[green]OK[/]" if success else "[red]FAIL[/]"
                # Calculate padding needed based on visible length (OK=2, FAIL=4)
                visible_len = len(Text.from_markup(result_markup).plain)
                padding = " " * max(0, (4 - visible_len))
                result_padded = f"{result_markup}{padding}"  # Pad

                # Format details dictionary
                details_dict: dict[str, Any] = event.get("details", {})
                # Filter out redundant/internal keys
                filtered_details = {
                    k: v
                    for k, v in details_dict.items()
                    if k not in ["syscall", "type", "success", "ts", "error_msg"]
                }
                # Add error name if present and failed
                error_name = details_dict.get("error_name")
                if error_name and not success:
                    filtered_details["ERROR"] = f"[red]{error_name}[/]"

                # Create string representation of details
                details_str = ", ".join(
                    # Use repr() for values to show quotes around strings etc.
                    f"{k}={v!r}"
                    for k, v in filtered_details.items()
                )
                # Shorten details string if too long, replacing newlines
                details_display = short_path(
                    details_str.replace("\n", "\\n"), 80
                )  # Allow more detail space

                # Write the formatted line to the log widget
                log_widget.write(
                    f"{ts_formatted} | {etype} | {result_padded} | {details_display}"
                )

            # Scroll to the end after populating
            log_widget.scroll_end(animate=False)

        except Exception as e:
            log.exception(f"Error populating detail screen for {self.file_info.path}")
            try:
                # Try to display error in the log widget itself
                self.query_one(RichLog).write(
                    f"[bold red]Error loading details:\n{e}[/]"
                )
            except Exception:
                pass  # Ignore errors during error reporting
            self.notify("Error loading details.", severity="error")

    # --- Scrolling Actions ---
    # These actions simply call the corresponding methods on the RichLog widget
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
