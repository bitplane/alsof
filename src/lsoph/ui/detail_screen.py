# Filename: src/lsoph/ui/detail_screen.py
"""Full-screen display for file event history."""

import datetime
import logging
from typing import Any, Dict

from rich.text import Text
from textual.app import ComposeResult
from textual.binding import Binding

# Removed Container import
from textual.containers import Vertical  # Use Vertical for simple layout
from textual.screen import Screen  # Changed from ModalScreen to Screen
from textual.widgets import Footer, Header, RichLog, Static  # Added Header, Footer

from lsoph.monitor import FileInfo
from lsoph.util.short_path import short_path

log = logging.getLogger("lsoph.ui.detail")


class DetailScreen(Screen):  # Changed base class to Screen
    """Screen to display event history and details for a specific file."""

    BINDINGS = [
        Binding("escape,q,d,enter", "app.pop_screen", "Close", show=True),
        # Keep scrolling bindings
        Binding("up,k", "scroll_up()", "Scroll Up", show=False),
        Binding("down,j", "scroll_down()", "Scroll Down", show=False),
        Binding("pageup", "page_up()", "Page Up", show=False),
        Binding("pagedown", "page_down()", "Page Down", show=False),
        Binding("home", "scroll_home()", "Scroll Home", show=False),
        Binding("end", "scroll_end()", "Scroll End", show=False),
    ]

    # Remove DEFAULT_CSS related to modal container sizing
    # DEFAULT_CSS = """..."""

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
                max_lines=2000,
                markup=True,
                highlight=True,
                wrap=False,
            )
        yield Footer()

    def _create_header_text(self) -> Text:
        """Creates the header text displayed above the log."""
        path_display = short_path(self.file_info.path, 100)  # Allow more space
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
            # Update the static header widget as well, in case state changed
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
                    ("Timestamp", "bold blue"),
                    " | ",
                    ("Event", "bold blue"),
                    "   | ",
                    ("Result", "bold blue"),
                    " | ",
                    ("Details", "bold blue"),
                )
            )
            log_widget.write("-" * 80)  # Separator

            for event in history:
                ts_raw = event.get("ts", 0)
                ts_str = f"{ts_raw:.3f}"
                try:
                    if isinstance(ts_raw, (int, float)) and ts_raw > 0:
                        ts_str = datetime.datetime.fromtimestamp(ts_raw).strftime(
                            "%H:%M:%S.%f"
                        )[:-3]
                except (TypeError, ValueError, OSError) as ts_err:
                    log.warning(f"Could not format timestamp {ts_raw}: {ts_err}")
                ts_formatted = ts_str.ljust(12)

                etype = str(event.get("type", "?")).upper().ljust(8)

                success = event.get("success", False)
                result_str = "[green]OK[/]" if success else "[red]FAIL[/]"
                visible_len = len(Text.from_markup(result_str).plain)
                padding = " " * max(0, (4 - visible_len))
                result_padded = f"{result_str}{padding}"

                details_dict: Dict[str, Any] = event.get("details", {})
                filtered_details = {
                    k: v
                    for k, v in details_dict.items()
                    if k not in ["syscall", "type", "success", "ts", "error_msg"]
                }
                error_name = details_dict.get("error_name")
                if error_name and not success:
                    filtered_details["ERROR"] = f"[red]{error_name}[/]"

                details_str = ", ".join(
                    f"{k}={v!r}" for k, v in filtered_details.items()
                )
                details_display = short_path(
                    details_str.replace("\n", "\\n"), 80
                )  # Allow more detail space

                log_widget.write(
                    f"{ts_formatted} | {etype} | {result_padded} | {details_display}"
                )

            log_widget.scroll_end(animate=False)

        except Exception as e:
            log.exception(f"Error populating detail screen for {self.file_info.path}")
            try:
                self.query_one(RichLog).write(
                    f"[bold red]Error loading details:\n{e}[/]"
                )
            except Exception:
                pass
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
