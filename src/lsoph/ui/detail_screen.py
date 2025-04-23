# Filename: src/lsoph/ui/detail_screen.py
"""Modal screen for displaying file event history."""

import datetime
import logging
from typing import Any, Dict  # Added Dict, Any

from rich.text import Text
from textual.app import ComposeResult
from textual.binding import Binding
from textual.containers import Container, VerticalScroll  # Added VerticalScroll
from textual.screen import ModalScreen
from textual.widgets import Label, RichLog, Static  # Added Static

from lsoph.monitor import FileInfo
from lsoph.util.short_path import short_path

log = logging.getLogger("lsoph.ui.detail")


class DetailScreen(ModalScreen[None]):
    """Screen to display event history and details for a specific file."""

    BINDINGS = [
        Binding(
            "escape,q,d,enter", "app.pop_screen", "Close", show=True
        ),  # Use same keys as main screen action
        Binding("up,k", "scroll_up", "Scroll Up", show=False),
        Binding("down,j", "scroll_down", "Scroll Down", show=False),
        Binding("pageup", "page_up", "Page Up", show=False),
        Binding("pagedown", "page_down", "Page Down", show=False),
        Binding("home", "scroll_home", "Scroll Home", show=False),
        Binding("end", "scroll_end", "Scroll End", show=False),
    ]

    # Add CSS for layout within the modal container
    DEFAULT_CSS = """
    DetailScreen > Container {
        border: thick $accent;
        padding: 1 2; /* Add padding */
        width: 90%;
        height: 80%;
        background: $surface;
        /* Use grid for layout */
        grid-size: 2;
        grid-gutter: 1 2;
        grid-rows: auto 1fr; /* Header row, Log row takes remaining space */
    }

    #detail-header {
        grid-column: 1 / 3; /* Span both columns */
        height: auto;
        margin-bottom: 1;
    }

    #event-log-container {
        grid-column: 1 / 3; /* Span both columns */
        border: round $panel; /* Add border to log area */
    }

    #event-log {
        /* Ensure log fills its container */
        width: 100%;
        height: 100%;
    }
    """

    def __init__(self, file_info: FileInfo):
        self.file_info = file_info
        super().__init__()

    def compose(self) -> ComposeResult:
        """Create child widgets for the detail screen using a grid layout."""
        with Container(
            id="detail-modal-container"
        ):  # Outer container for centering/sizing
            # Header section
            yield Static(self._create_header_text(), id="detail-header")
            # Log section within a scrollable container
            with VerticalScroll(id="event-log-container"):
                yield RichLog(
                    id="event-log",
                    max_lines=2000,  # Increase buffer slightly
                    markup=True,
                    highlight=True,
                    wrap=False,  # Keep wrap false for tabular data
                )

    def _create_header_text(self) -> Text:
        """Creates the header text with file path and status."""
        path_display = short_path(
            self.file_info.path, 80
        )  # Limit path length in header
        status = self.file_info.status.upper()
        style = ""
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
                    ("Timestamp", "bold blue"),
                    " | ",
                    ("Event", "bold blue"),
                    "   | ",  # Padded
                    ("Result", "bold blue"),
                    " | ",  # Padded
                    ("Details", "bold blue"),
                )
            )
            log_widget.write("-" * 80)  # Separator

            for event in history:
                # Format Timestamp
                ts_raw = event.get("ts", 0)
                ts_str = f"{ts_raw:.3f}"  # Default to raw float if formatting fails
                try:
                    if isinstance(ts_raw, (int, float)) and ts_raw > 0:
                        # Format to H:M:S.ms
                        ts_str = datetime.datetime.fromtimestamp(ts_raw).strftime(
                            "%H:%M:%S.%f"
                        )[:-3]
                except (TypeError, ValueError, OSError) as ts_err:
                    log.warning(f"Could not format timestamp {ts_raw}: {ts_err}")
                ts_formatted = ts_str.ljust(12)  # Pad timestamp

                # Format Event Type
                etype = str(event.get("type", "?")).upper().ljust(8)  # Pad event type

                # Format Success/Fail
                success = event.get("success", False)
                result_str = "[green]OK[/]" if success else "[red]FAIL[/]"
                # Pad result string for alignment
                visible_len = len(Text.from_markup(result_str).plain)
                padding = " " * max(0, (4 - visible_len))  # Pad to 4 chars wide
                result_padded = f"{result_str}{padding}"

                # Format Details (excluding the type/success/ts already shown)
                details_dict: Dict[str, Any] = event.get("details", {})
                # Filter out keys already displayed or internal keys
                filtered_details = {
                    k: v
                    for k, v in details_dict.items()
                    if k
                    not in [
                        "syscall",
                        "type",
                        "success",
                        "ts",
                        "error_msg",
                    ]  # Keep error_name
                }
                # Special handling for error_name
                error_name = details_dict.get("error_name")
                if error_name and not success:
                    filtered_details["ERROR"] = f"[red]{error_name}[/]"

                details_str = ", ".join(
                    f"{k}={v!r}" for k, v in filtered_details.items()
                )
                details_display = short_path(
                    details_str.replace("\n", "\\n"), 60
                )  # Shorten details

                # Write the formatted line
                log_widget.write(
                    f"{ts_formatted} | {etype} | {result_padded} | {details_display}"
                )

            # Scroll to the bottom after populating
            log_widget.scroll_end(animate=False)

        except Exception as e:
            log.exception(f"Error populating detail screen for {self.file_info.path}")
            # Attempt to write error to the log widget itself
            try:
                self.query_one(RichLog).write(
                    f"[bold red]Error loading details:\n{e}[/]"
                )
            except Exception:
                pass  # Ignore if log widget query fails here
            self.notify("Error loading details.", severity="error")

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
