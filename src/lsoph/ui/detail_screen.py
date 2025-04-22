# Filename: ui/detail_screen.py
"""Modal screen for displaying file event history."""

import datetime
import logging

from rich.text import Text
from textual.app import ComposeResult
from textual.binding import Binding
from textual.containers import Container
from textual.screen import ModalScreen
from textual.widgets import Label, RichLog

from lsoph.monitor import FileInfo
from lsoph.util.short_path import short_path

log = logging.getLogger(__name__)


class DetailScreen(ModalScreen[None]):
    """Screen to display event history for a specific file."""

    BINDINGS = [Binding("escape,q", "app.pop_screen", "Close", show=True)]

    def __init__(self, file_info: FileInfo):
        self.file_info = file_info
        super().__init__()

    def compose(self) -> ComposeResult:
        """Create child widgets for the detail screen."""
        yield Container(
            Label(f"Event History for: {self.file_info.path}"),
            RichLog(
                id="event-log",
                max_lines=1000,
                markup=True,
                highlight=True,
                wrap=False,
            ),
            id="detail-container",
        )

    def on_mount(self) -> None:
        """Called when the screen is mounted. Populates the log."""
        try:
            log_widget = self.query_one(RichLog)
            history = self.file_info.event_history
            log.debug(f"DetailScreen on_mount: History length = {len(history)}")
            if not history:
                log_widget.write("No event history recorded.")
                return

            for event in history:
                ts_raw = event.get("ts", 0)
                try:
                    if isinstance(ts_raw, (int, float)) and ts_raw > 0:
                        ts = datetime.datetime.fromtimestamp(ts_raw).strftime(
                            "%H:%M:%S.%f"
                        )[:-3]
                    else:
                        ts = str(ts_raw)[:17].ljust(17)
                except (TypeError, ValueError, OSError) as ts_err:
                    log.warning(f"Could not format timestamp {ts_raw}: {ts_err}")
                    ts = str(ts_raw)[:17].ljust(17)

                etype = str(event.get("type", "?")).ljust(8)
                success = (
                    "[green]OK[/]" if event.get("success", False) else "[red]FAIL[/]"
                )
                # Calculate padding based on plain text length
                visible_len = len(Text.from_markup(success).plain)
                padding = " " * max(0, (7 - visible_len))
                success_padded = f"{success}{padding}"

                details = str(event.get("details", {}))
                details_display = short_path(details.replace("\n", "\\n"), 60)

                log_widget.write(
                    f"{ts} | {etype} | {success_padded} | {details_display}"
                )

        except Exception as e:
            log.error(f"Error populating detail screen: {e}", exc_info=True)
            self.notify("Error loading details.", severity="error")
