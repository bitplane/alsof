# Filename: src/lsoph/ui/file_data_table.py
"""A specialized DataTable widget for displaying lsoph file info."""

import logging
import time
from typing import Any, Optional

from rich.text import Text
from textual import events
from textual.coordinate import Coordinate
from textual.widgets import DataTable
from textual.widgets.data_table import CellKey, RowKey

from lsoph.monitor import FileInfo
from lsoph.util.short_path import short_path

# Import the new emoji helper
from .emoji import get_emoji_history_string

log = logging.getLogger("lsoph.ui.table")


# --- Formatting Helper ---
# (Helper function _format_file_info_for_table remains the same)
def _format_file_info_for_table(
    info: FileInfo, available_width: int, current_time: float
) -> tuple[Text, Text, Text]:  # Returns visual components directly
    """Formats FileInfo into data suitable for DataTable.add_row/update_cell."""

    # --- Get Emoji History ---
    MAX_EMOJI_HISTORY = 5  # Keep consistent with column width
    emoji_history_str = get_emoji_history_string(info, MAX_EMOJI_HISTORY)
    # --- End Emoji History ---

    # Shorten path display *text* using the calculated available width
    # Ensure available_width is at least 1 for short_path
    # We still need to shorten text even if column width is flexible
    path_display = short_path(info.path, max(1, available_width))

    # Format age string
    age_seconds = current_time - info.last_activity_ts
    if age_seconds < 10:
        age_str = f"{age_seconds:.1f}s"
    elif age_seconds < 60:
        age_str = f"{int(age_seconds)}s"
    elif age_seconds < 3600:
        age_str = f"{int(age_seconds / 60)}m"
    else:
        age_str = f"{int(age_seconds / 3600)}h"

    # Determine style based on status and age (primarily for path/age)
    style = ""
    if info.status == "deleted":
        style = "strike"
    elif info.last_error_enoent:
        style = "dim strike"
    elif info.status == "error":
        style = "red"
    elif info.is_open:
        style = "green" if info.status == "active" else ""
    elif info.status == "active":
        style = "green"
    elif age_seconds > 60:
        style = "dim"

    # Create Text objects with styles
    # Use the emoji_history_str directly
    recent_text = Text(f" {emoji_history_str} ")  # Pad slightly
    path_text = Text(path_display, style=style)
    age_text = Text(age_str.rjust(4), style=style)

    return recent_text, path_text, age_text


# --- End Formatting Helper ---


class FileDataTable(DataTable):
    """A DataTable specialized for displaying and managing FileInfo."""

    RECENT_COL_WIDTH = 8  # Width for emoji history (e.g., 5 emojis + padding)
    AGE_COL_WIDTH = 5  # width of the age column
    SCROLLBAR_WIDTH = 2  # just a guess 🤷

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.cursor_type = "row"
        self.zebra_stripes = True
        self._current_row_keys: list[RowKey] = []

    def on_mount(self) -> None:
        """Set up columns on mount."""
        super().on_mount()
        self.add_column("Recent", key="history", width=self.RECENT_COL_WIDTH)
        self.add_column("Path", key="path")
        self.add_column("Age", key="age", width=self.AGE_COL_WIDTH)
        self.columns["path"].auto_width = False
        self.columns["path"].width = self._get_path_column_width()

    def _get_path_column_width(self):
        w = self.size.width - self.SCROLLBAR_WIDTH
        w -= len(self.columns) * 2
        return w - self.RECENT_COL_WIDTH - self.AGE_COL_WIDTH

    @property
    def selected_path(self) -> Optional[str]:
        """Returns the full path (RowKey value) of the currently selected row."""
        try:
            coordinate = self.cursor_coordinate
            if not self.is_valid_coordinate(coordinate):
                return None
            cell_key: Optional[CellKey] = self.coordinate_to_cell_key(coordinate)
            row_key_obj = cell_key.row_key if cell_key else None
            if row_key_obj is not None and row_key_obj.value is not None:
                return str(row_key_obj.value)
        except Exception as e:
            log.error(f"Error getting selected path from FileDataTable: {e}")
        return None

    def on_resize(self, event: events.Resize) -> None:
        self.columns["path"].width = self._get_path_column_width()

    def update_data(self, sorted_file_infos: list[FileInfo]) -> None:
        """
        Updates the table content based on the new list of sorted FileInfo objects.
        Relies on Textual's layout for Path column width.
        """
        current_time = time.time()

        # --- Preserve Cursor ---
        selected_key_before_update = self.selected_path
        selected_index_before_update = self.cursor_row

        # --- Calculate width available for TEXT shortening ---
        path_text_width = self._get_path_column_width()

        # --- Full Refresh Implementation ---
        self.clear()
        new_row_keys_in_order: list[RowKey] = []
        new_key_to_index_map: dict[RowKey, int] = {}

        for idx, info in enumerate(sorted_file_infos):
            row_key_value = info.path
            row_key = RowKey(row_key_value)

            # Format data for the row using the calculated width for path TEXT shortening
            recent_text, path_text, age_text = _format_file_info_for_table(
                info, path_text_width, current_time
            )
            row_data = (recent_text, path_text, age_text)

            try:
                self.add_row(*row_data, key=row_key_value)
                new_row_keys_in_order.append(row_key)
                new_key_to_index_map[row_key] = idx
            except KeyError:
                log.warning(f"Attempted to add duplicate row key: {row_key_value}")
            except Exception as add_exc:
                log.exception(f"Error adding row for key {row_key_value}: {add_exc}")

        self._current_row_keys = new_row_keys_in_order
        # --- End Full Refresh ---

        # --- Restore Cursor ---
        new_cursor_index = -1
        if selected_key_before_update:
            selected_rowkey_obj = RowKey(selected_key_before_update)
            if selected_rowkey_obj in new_key_to_index_map:
                new_cursor_index = new_key_to_index_map[selected_rowkey_obj]
            else:
                if self.row_count > 0:
                    potential_index = max(0, selected_index_before_update - 1)
                    new_cursor_index = min(potential_index, self.row_count - 1)

        if new_cursor_index != -1:
            try:
                if self.is_valid_row_index(new_cursor_index):
                    self.move_cursor(row=new_cursor_index, animate=False)
                else:
                    log.warning(
                        f"Calculated new cursor index {new_cursor_index} is invalid."
                    )
            except Exception as e:
                log.error(f"Error moving cursor to row {new_cursor_index}: {e}")
        # --- End Restore Cursor ---
