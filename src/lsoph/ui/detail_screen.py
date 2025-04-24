# Filename: src/lsoph/ui/detail_screen.py
"""Screen to display file event history using a DataTable."""

import datetime
import logging
from typing import Any

from rich.text import Text
from textual.app import ComposeResult
from textual.binding import Binding
from textual.containers import Vertical
from textual.screen import Screen
from textual.widgets import DataTable, Footer, Static

from lsoph.monitor import FileInfo
from lsoph.util.short_path import short_path

# Import the emoji map from the emoji module
from .emoji import DEFAULT_EMOJI, EVENT_EMOJI_MAP, STATUS_EMOJI_MAP

log = logging.getLogger("lsoph.ui.detail")


class DetailScreen(Screen):
    """Screen to display event history and details for a specific file using DataTable."""

    BINDINGS = [
        Binding("escape,q,d,enter", "app.pop_screen", "Close", show=True),
    ]

    def __init__(self, file_info: FileInfo):
        self.file_info = file_info
        super().__init__()

    def compose(self) -> ComposeResult:
        """Create child widgets for the detail screen."""
        with Vertical(id="detail-content"):
            yield Static(self._create_header_text(), id="detail-header")
            yield DataTable(id="event-table", cursor_type="row", zebra_stripes=True)
        yield Footer()

    def _create_header_text(self) -> Text:
        """Creates the header text displayed above the table."""
        path_display = short_path(self.file_info.path, 100)
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
        """Called when the screen is mounted. Populates the DataTable."""
        try:
            table = self.query_one(DataTable)
            # Update the static header widget
            self.query_one("#detail-header", Static).update(self._create_header_text())

            # Add columns to the DataTable
            table.add_column("Timestamp", key="ts", width=12)
            table.add_column("Event", key="event", width=8)
            table.add_column("Result", key="result", width=6)
            # Add new column for Emoji Meaning
            table.add_column("Action", key="action", width=10)
            table.add_column(
                "Details", key="details", width=70
            )  # Adjusted width slightly

            history = self.file_info.event_history
            log.debug(
                f"DetailScreen on_mount: Populating table with {len(history)} history events."
            )

            if not history:
                table.add_row(
                    Text("No event history recorded for this file.", style="dim")
                )
                return

            # Reverse map for finding meaning from emoji (handle potential duplicates if needed)
            # For simplicity, we'll look up based on event type directly.
            # emoji_to_meaning = {v: k for k, v in EVENT_EMOJI_MAP.items()}
            # status_emoji_to_meaning = {v: k for k, v in STATUS_EMOJI_MAP.items()}

            # Write each event from history as a row
            for event in history:
                # Format timestamp
                ts_raw = event.get("ts", 0)
                ts_str = f"{ts_raw:.3f}"
                try:
                    if isinstance(ts_raw, (int, float)) and ts_raw > 0:
                        ts_str = datetime.datetime.fromtimestamp(ts_raw).strftime(
                            "%H:%M:%S.%f"
                        )[:-3]
                except (TypeError, ValueError, OSError) as ts_err:
                    log.warning(f"Could not format timestamp {ts_raw}: {ts_err}")
                ts_text = Text(ts_str)

                # Format event type
                event_type_str = str(event.get("type", "?")).upper()
                etype_text = Text(event_type_str)

                # Format result (OK/FAIL)
                success = event.get("success", True)  # Default to True if missing
                result_text = (
                    Text("OK", style="green") if success else Text("FAIL", style="red")
                )

                # Determine Action/Meaning based on event type and success
                action_str = "???"
                if not success:
                    action_str = "Error"  # Consistent with emoji map
                else:
                    # Look up the event type in the map
                    # Find the key (meaning) corresponding to the emoji value
                    # This assumes EVENT_EMOJI_MAP values are unique for meanings we care about here
                    action_str = event_type_str  # Default to event type if no specific emoji meaning needed
                    # Example: Find 'Open' for '📂' - better to just use event_type_str?
                    # Let's just use the event type string directly for clarity.
                    # emoji_for_event = EVENT_EMOJI_MAP.get(event_type_str, DEFAULT_EMOJI)
                    # action_str = next((k for k, v in EVENT_EMOJI_MAP.items() if v == emoji_for_event), event_type_str)

                action_text = Text(action_str.capitalize())  # Capitalize for display

                # Format details dictionary
                details_dict: dict[str, Any] = event.get("details", {})
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
                        "target_path",
                        "source_path",
                    ]
                }
                error_name = details_dict.get("error_name")
                if error_name and not success:
                    filtered_details["ERROR"] = Text(error_name, style="red")

                details_parts = []
                for k, v in filtered_details.items():
                    if isinstance(v, Text):
                        details_parts.append(f"{k}={v.plain!r}")
                    else:
                        details_parts.append(f"{k}={v!r}")

                details_str = ", ".join(details_parts)
                details_display = short_path(
                    details_str.replace("\n", "\\n"), 70
                )  # Use adjusted width
                details_text = Text(details_display)

                # Add the row to the table including the new action column
                table.add_row(
                    ts_text, etype_text, result_text, action_text, details_text
                )

            # Focus the table after populating
            table.focus()

        except Exception as e:
            log.exception(
                f"Error populating detail screen table for {self.file_info.path}"
            )
            try:
                table = self.query_one(DataTable)
                table.clear()
                table.add_row(Text(f"Error loading details: {e}", style="bold red"))
            except Exception:
                pass
            self.notify("Error loading details.", severity="error")
