# Filename: ui/detail_screen.py
"""Modal screen for displaying file event history."""

import datetime
import logging

from rich.text import Text
from textual.app import ComposeResult
from textual.binding import Binding
from textual.containers import Container
from textual.screen import ModalScreen

# --- CHANGE: Import RichLog instead of Log ---
from textual.widgets import Label, RichLog

# Import necessary types and functions
from alsof.monitor import FileInfo

# Assuming utils is one level up from ui? Adjust if needed.
# If utils is alsof.util, use that. Let's assume alsof.util
from alsof.util.short_path import short_path

log = logging.getLogger(__name__)  # Use module-specific logger


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
            # --- CHANGE: Use RichLog ---
            RichLog(
                id="event-log",
                max_lines=1000,
                markup=True,  # RichLog accepts markup=True
                highlight=True,  # Optional: Enable syntax highlighting
                wrap=False,  # Optional: Set wrapping preference
            ),
            # ---------------------------
            id="detail-container",
        )

    def on_mount(self) -> None:
        """Called when the screen is mounted. Populates the log."""
        try:
            # --- CHANGE: Query RichLog ---
            log_widget = self.query_one(RichLog)
            # -----------------------------
            history = self.file_info.event_history
            log.debug(f"DetailScreen on_mount: History length = {len(history)}")
            if not history:
                log_widget.write("No event history recorded.")  # Use write for RichLog
                return

            # Add header row - write handles adding newline
            log_widget.write("Timestamp         | Type     | Success | Details")
            log_widget.write(
                "-----------------|----------|---------|------------------------------------------------------------"
            )

            # Add event rows
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
                # RichLog will correctly render this markup string
                success = (
                    "[green]OK[/]" if event.get("success", False) else "[red]FAIL[/]"
                )
                # Calculate padding based on plain text length
                visible_len = len(Text.from_markup(success).plain)
                padding = " " * max(
                    0, (7 - visible_len)
                )  # Ensure padding isn't negative
                success_padded = f"{success}{padding}"

                details = str(event.get("details", {}))
                details_display = short_path(details.replace("\n", "\\n"), 60)

                # Use write, which handles the markup string correctly
                log_widget.write(
                    f"{ts} | {etype} | {success_padded} | {details_display}"
                )

        except Exception as e:
            log.error(f"Error populating detail screen: {e}", exc_info=True)
            self.notify("Error loading details.", severity="error")
