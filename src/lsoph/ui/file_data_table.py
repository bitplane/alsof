# Filename: src/lsoph/ui/file_data_table.py
"""A specialized DataTable widget for displaying lsoph file info."""

import logging
import time
from typing import Any, Optional

from rich.text import Text
from textual.coordinate import Coordinate
from textual.widgets import DataTable
from textual.widgets.data_table import CellKey, RowKey

from lsoph.monitor import FileInfo
from lsoph.util.short_path import short_path

# Import the new emoji helper
from .emoji import get_emoji_history_string

log = logging.getLogger("lsoph.ui.table")


# --- Formatting Helper ---
def _format_file_info_for_table(
    info: FileInfo, available_width: int, current_time: float
) -> tuple[Text, Text, Text]:  # Returns visual components directly
    """Formats FileInfo into data suitable for DataTable.add_row/update_cell."""

    # --- Get Emoji History ---
    # Define max length for emoji string
    MAX_EMOJI_HISTORY = 5
    emoji_history_str = get_emoji_history_string(info, MAX_EMOJI_HISTORY)
    # --- End Emoji History ---

    # Shorten path display *text* using the calculated available width
    # Ensure available_width is at least 1 for short_path
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
        style = "dim strike"  # File likely doesn't exist anymore
    elif info.status == "error":
        style = "red"
    elif info.is_open:
        # Apply green slightly differently if active vs just open
        style = "green" if info.status == "active" else ""  # Bold removed for now
    elif info.status == "active":  # Should be caught by is_open, but safety
        style = "green"
    # Highlight recent stat calls slightly? Maybe not needed with emoji history.
    # elif info.last_event_type == "STAT" and not info.is_open:
    #     style = "yellow"
    elif age_seconds > 60:  # Dim older entries
        style = "dim"

    # Create Text objects with styles
    # Pad emoji string slightly for visual separation
    # No specific style needed for emoji string itself, handled by content
    recent_text = Text(f" {emoji_history_str} ")
    path_text = Text(path_display, style=style)
    age_text = Text(age_str.rjust(4), style=style)  # Pad for alignment

    return recent_text, path_text, age_text


# --- End Formatting Helper ---


class FileDataTable(DataTable):
    """A DataTable specialized for displaying and managing FileInfo."""

    DEFAULT_PATH_WIDTH = 80  # Define a default initial width
    # Define fixed widths for non-path columns
    RECENT_COL_WIDTH = 8  # Width for emoji history (e.g., 5 emojis + padding)
    AGE_COL_WIDTH = 5

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.cursor_type = "row"
        self.zebra_stripes = True
        # Internal state tracking
        self._current_row_keys: list[RowKey] = []  # Stores keys in visual order

    def on_mount(self) -> None:
        """Set up columns on mount."""
        # Renamed first column, adjusted width
        self.add_column("Recent", key="history", width=self.RECENT_COL_WIDTH)
        # Set an initial width for Path column to prevent collapse
        self.add_column("Path", key="path", width=self.DEFAULT_PATH_WIDTH)
        self.add_column("Age", key="age", width=self.AGE_COL_WIDTH)

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
            # Keep error log for debugging selection issues
            log.error(f"Error getting selected path from FileDataTable: {e}")
        return None

    def update_data(self, sorted_file_infos: list[FileInfo]) -> None:
        """
        Updates the table content based on the new list of sorted FileInfo objects.
        Currently implements a full refresh, but designed for future partial updates.
        """
        current_time = time.time()

        # --- Preserve Cursor ---
        selected_key_before_update = self.selected_path
        selected_index_before_update = self.cursor_row

        # --- Calculate and Update Path Column Width ---
        other_cols_width = self.RECENT_COL_WIDTH + self.AGE_COL_WIDTH
        # Get container width, fallback to screen width if needed (though container is better)
        container_width = self.container_size.width or self.app.size.width
        # Estimate padding/separators (e.g., 1 space between each column + borders)
        # A simple estimate might be num_columns + 1
        padding_estimate = len(self.columns) + 1
        available_width_for_column = max(
            1, container_width - other_cols_width - padding_estimate
        )

        path_column = self.columns.get("path")
        if path_column and path_column.width != available_width_for_column:
            # Set the calculated width directly
            path_column.width = available_width_for_column
            log.debug(f"Updating path column width to {available_width_for_column}")
        elif not path_column:
            log.error("Path column not found in FileDataTable during width update!")
            return
        # --- End Width Calculation/Update ---

        # --- Full Refresh Implementation ---
        self.clear()
        new_row_keys_in_order: list[RowKey] = []
        new_key_to_index_map: dict[RowKey, int] = {}

        for idx, info in enumerate(sorted_file_infos):
            row_key_value = info.path
            row_key = RowKey(row_key_value)

            # Format data for the row using the calculated column width for path text shortening
            recent_text, path_text, age_text = _format_file_info_for_table(
                info, available_width_for_column, current_time
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
