# Filename: src/lsoph/ui/detail_screen.py
"""Screen to display file event history using a DataTable."""

import datetime
import logging
from typing import Any

from rich.text import Text
from textual.app import ComposeResult
from textual.binding import Binding
from textual.containers import Vertical  # Keep Vertical for layout structure
from textual.screen import Screen
from textual.widgets import DataTable, Footer, Static  # Removed Header, Added DataTable

from lsoph.monitor import FileInfo
from lsoph.util.short_path import short_path

log = logging.getLogger("lsoph.ui.detail")


class DetailScreen(Screen):
    """Screen to display event history and details for a specific file using DataTable."""

    BINDINGS = [
        Binding("escape,q,d,enter", "app.pop_screen", "Close", show=True),
        # DataTable handles its own scrolling, so specific scroll bindings removed.
        # Keep other relevant bindings if needed.
    ]

    # Optional: Add CSS for the DataTable within this screen if needed
    # CSS = """
    # DetailScreen > Vertical > DataTable {
    #     height: 1fr; /* Make table fill available space */
    #     border: round $panel;
    # }
    # """

    def __init__(self, file_info: FileInfo):
        self.file_info = file_info
        super().__init__()

    def compose(self) -> ComposeResult:
        """Create child widgets for the detail screen."""
        # Removed Header widget
        # Use a Vertical container to stack the static header text and the table
        with Vertical(id="detail-content"):
            yield Static(self._create_header_text(), id="detail-header")
            # Replace RichLog with DataTable
            yield DataTable(id="event-table", cursor_type="row", zebra_stripes=True)
        yield Footer()

    def _create_header_text(self) -> Text:
        """Creates the header text displayed above the table."""
        # (This function remains the same as before)
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
            table.add_column("Result", key="result", width=6)  # Adjusted width
            table.add_column("Details", key="details", width=80)  # Allow more width

            history = self.file_info.event_history
            log.debug(
                f"DetailScreen on_mount: Populating table with {len(history)} history events."
            )

            if not history:
                table.add_row(
                    Text("No event history recorded for this file.", style="dim")
                )
                return

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
                ts_text = Text(ts_str)  # No padding needed in table cell

                # Format event type
                etype = str(event.get("type", "?")).upper()
                etype_text = Text(etype)

                # Format result (OK/FAIL)
                success = event.get("success", False)
                result_text = (
                    Text("OK", style="green") if success else Text("FAIL", style="red")
                )

                # Format details dictionary
                details_dict: dict[str, Any] = event.get("details", {})
                filtered_details = {
                    k: v
                    for k, v in details_dict.items()
                    # Exclude keys less relevant for direct display or redundant
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

                # Create string representation of details, handling Text objects
                details_parts = []
                for k, v in filtered_details.items():
                    if isinstance(v, Text):
                        # If value is already Text, use its plain form in the key=value string
                        # The Text object itself will handle styling when added to the cell later
                        details_parts.append(f"{k}={v.plain!r}")
                    else:
                        details_parts.append(f"{k}={v!r}")

                details_str = ", ".join(details_parts)
                details_display = short_path(details_str.replace("\n", "\\n"), 80)
                details_text = Text(details_display)  # Create Text object for the cell

                # Add the row to the table
                table.add_row(ts_text, etype_text, result_text, details_text)

            # Focus the table after populating
            table.focus()

        except Exception as e:
            log.exception(
                f"Error populating detail screen table for {self.file_info.path}"
            )
            try:
                # Try to display error in the table itself
                table = self.query_one(DataTable)
                table.clear()  # Clear any partial content
                table.add_row(Text(f"Error loading details: {e}", style="bold red"))
            except Exception:
                pass  # Ignore errors during error reporting
            self.notify("Error loading details.", severity="error")

    # Scrolling actions are removed as DataTable handles its own scrolling via arrow keys/PgUp/PgDn etc.
    # If custom scroll actions were needed, they would target the DataTable widget.
