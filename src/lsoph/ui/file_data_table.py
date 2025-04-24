# Filename: src/lsoph/ui/file_data_table.py
"""A specialized DataTable widget for displaying lsoph file info."""

import logging
import time
from typing import Any, Dict, List, Optional, Tuple  # Added Dict, Tuple, List

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

# Type alias for the visual data tuple (must match column order)
RowVisualData = Tuple[Text, Text, Text]


# --- Formatting Helper ---
def _format_file_info_for_table(
    info: FileInfo, available_width: int, current_time: float
) -> RowVisualData:  # Returns visual components directly
    """Formats FileInfo into data suitable for DataTable.add_row/update_cell."""

    # --- Get Emoji History ---
    MAX_EMOJI_HISTORY = 5  # Keep consistent with column width
    emoji_history_str = get_emoji_history_string(info, MAX_EMOJI_HISTORY)
    # --- End Emoji History ---

    # Shorten path display *text* using the calculated available width
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
    recent_text = Text(f" {emoji_history_str} ")  # Pad slightly
    path_text = Text(path_display, style=style)
    age_text = Text(age_str.rjust(4), style=style)

    return recent_text, path_text, age_text


# --- End Formatting Helper ---


class FileDataTable(DataTable):
    """
    A DataTable specialized for displaying and managing FileInfo.
    Uses full refresh for updates to maintain sort order, with robust cursor handling.
    """

    RECENT_COL_WIDTH = 8
    AGE_COL_WIDTH = 5
    SCROLLBAR_WIDTH = 2  # User's estimate
    COLUMN_PADDING = 2  # User's estimate

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.cursor_type = "row"
        self.zebra_stripes = True
        # Store row keys in the visual order they were *last added*
        # Used for cursor fallback logic
        self._current_visual_keys: List[RowKey] = []

    def on_mount(self) -> None:
        """Set up columns on mount."""
        super().on_mount()
        self.add_column("Recent", key="history", width=self.RECENT_COL_WIDTH)
        # Calculate and set initial path width using the helper
        initial_path_width = self._get_path_column_width()
        self.add_column("Path", key="path", width=initial_path_width)
        self.add_column("Age", key="age", width=self.AGE_COL_WIDTH)
        # Explicitly disable auto_width for the path column to respect our calculation
        self.columns["path"].auto_width = False
        log.debug(
            f"FileDataTable mounted. Initial path width set to {initial_path_width}"
        )

    def _get_path_column_width(self):
        """Calculates the desired width for the path column based on user's logic."""
        w = self.size.width - self.SCROLLBAR_WIDTH
        w -= len(self.columns) * self.COLUMN_PADDING
        calculated_width = w - self.RECENT_COL_WIDTH - self.AGE_COL_WIDTH
        return max(1, calculated_width)

    @property
    def selected_path(self) -> Optional[str]:
        """Returns the full path (RowKey value) of the currently selected row."""
        try:
            coordinate = self.cursor_coordinate
            if not self.is_valid_coordinate(coordinate):
                return None
            cell_key: Optional[CellKey] = self.coordinate_to_cell_key(coordinate)
            row_key_obj = cell_key.row_key if cell_key else None
            if row_key_obj and row_key_obj.value is not None:
                return str(row_key_obj.value)
        except Exception as e:
            log.error(f"Error getting selected path from FileDataTable: {e}")
        return None

    def on_resize(self, event: events.Resize) -> None:
        """Update path column width on resize."""
        new_width = self._get_path_column_width()
        path_column = self.columns.get("path")
        if path_column and path_column.width != new_width:
            path_column.width = new_width
            log.debug(
                f"*** FileDataTable RESIZE: New path width {new_width} (event size {event.size.width}) ***"
            )
            # Refresh might be needed if header/content doesn't redraw correctly automatically
            # self.refresh()

    def update_data(self, sorted_file_infos: list[FileInfo]) -> None:
        """
        Updates the table content using a full refresh to maintain sort order,
        and robustly restores the cursor position.
        """
        current_time = time.time()
        log.debug(f"Starting full refresh update with {len(sorted_file_infos)} items.")

        # --- Preserve Cursor State (Key and Index) ---
        selected_key_before_update: Optional[RowKey] = None
        selected_path_str = self.selected_path  # Get the string path
        if selected_path_str:
            selected_key_before_update = RowKey(selected_path_str)

        selected_index_before_update = self.cursor_row
        # Store the key order *before* clearing
        previous_visual_keys = list(
            self.rows.keys()
        )  # Get keys in current visual order

        log.debug(
            f"Cursor before update: Key='{selected_key_before_update}', Index={selected_index_before_update}"
        )

        # --- Calculate width for text formatting ---
        path_text_width = self._get_path_column_width()
        # Ensure column width is also up-to-date
        path_column = self.columns.get("path")
        if path_column and path_column.width != path_text_width:
            path_column.width = path_text_width

        # --- Full Refresh Implementation ---
        self.clear()
        new_visual_keys: List[RowKey] = []
        new_key_to_index_map: Dict[RowKey, int] = {}

        for idx, info in enumerate(sorted_file_infos):
            row_key_value = info.path
            row_key = RowKey(row_key_value)

            # Format data for the row using the current column width for path text shortening
            recent_text, path_text, age_text = _format_file_info_for_table(
                info, path_text_width, current_time
            )
            row_data = (recent_text, path_text, age_text)

            try:
                self.add_row(*row_data, key=row_key_value)
                new_visual_keys.append(row_key)  # Store keys in the new visual order
                new_key_to_index_map[row_key] = idx
            except KeyError:
                log.warning(f"Attempted to add duplicate row key: {row_key_value}")
            except Exception as add_exc:
                log.exception(f"Error adding row for key {row_key_value}: {add_exc}")

        self._current_visual_keys = (
            new_visual_keys  # Update internal state AFTER adding rows
        )
        # --- End Full Refresh ---

        # --- Restore Cursor ---
        target_key_to_select: Optional[RowKey] = None
        final_cursor_index = -1

        if selected_key_before_update:
            # Check if the originally selected key still exists in the new data
            if selected_key_before_update in new_key_to_index_map:
                target_key_to_select = selected_key_before_update
                log.debug(
                    f"Original selected key '{target_key_to_select.value}' still exists."
                )
            else:
                # Original key is gone (deleted/ignored). Find the key that was visually above it.
                log.debug(
                    f"Original selected key '{selected_key_before_update.value}' is gone."
                )
                # Use the key order from *before* the clear operation
                if (
                    selected_index_before_update > 0
                    and selected_index_before_update <= len(previous_visual_keys)
                ):
                    # Get the key that was visually at the index *above* the old selection
                    key_above_before_update = previous_visual_keys[
                        selected_index_before_update - 1
                    ]
                    log.debug(
                        f"Trying fallback key (was above): '{key_above_before_update.value}'"
                    )
                    # Check if *this* key still exists in the new data map
                    if key_above_before_update in new_key_to_index_map:
                        target_key_to_select = key_above_before_update
                    else:
                        log.debug(
                            f"Fallback key '{key_above_before_update.value}' also not found in new map."
                        )
                else:
                    log.debug(
                        "Original selection was at index 0 or invalid, cannot get key above."
                    )

        # If we found a target key (original or fallback), find its new index
        if target_key_to_select:
            final_cursor_index = new_key_to_index_map.get(target_key_to_select, -1)
            if final_cursor_index != -1:
                log.debug(
                    f"Target key '{target_key_to_select.value}' found at new index {final_cursor_index}."
                )
            else:
                # This shouldn't happen if the key is in the map, but handle defensively
                log.warning(
                    f"Target key '{target_key_to_select.value}' was in map but index lookup failed?"
                )

        # If no target key determined (original gone, fallback gone/failed), or index lookup failed,
        # try to select the top row if the table is not empty.
        if final_cursor_index == -1 and self.row_count > 0:
            log.debug("No target key found or index lookup failed, selecting row 0.")
            final_cursor_index = 0

        # Move cursor if a valid index was determined
        if final_cursor_index != -1:
            try:
                if self.is_valid_row_index(final_cursor_index):
                    self.move_cursor(row=final_cursor_index, animate=False)
                    log.debug(f"Moved cursor to index {final_cursor_index}.")
                else:
                    log.warning(
                        f"Calculated final cursor index {final_cursor_index} is invalid for row_count {self.row_count}."
                    )
            except Exception as e:
                log.error(f"Error moving cursor to row {final_cursor_index}: {e}")
        else:
            log.debug("No valid cursor index determined (table might be empty).")
        # --- End Restore Cursor ---

        log.debug("Full refresh update finished.")
