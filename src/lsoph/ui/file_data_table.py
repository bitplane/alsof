# Filename: src/lsoph/ui/file_data_table.py
"""A specialized DataTable widget for displaying lsoph file info with partial updates."""

import logging
import time
from typing import Any, Dict, List, Optional, Set, Tuple  # Added more types

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

# Type alias for the visual data tuple
RowVisualData = Tuple[Text, Text, Text]


# --- Formatting Helper ---
def _format_file_info_for_table(
    info: FileInfo, available_width: int, current_time: float
) -> RowVisualData:  # Returns visual components directly
    """Formats FileInfo into data suitable for DataTable.add_row/update_cell."""
    # (Implementation remains the same as your fixed version)

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
    """A DataTable specialized for displaying and managing FileInfo with partial updates."""

    RECENT_COL_WIDTH = 8
    AGE_COL_WIDTH = 5
    SCROLLBAR_WIDTH = 2
    COLUMN_PADDING = 2

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.cursor_type = "row"
        self.zebra_stripes = True
        # Cache the last known visual data for each row key to enable diffing
        self._row_data_cache: Dict[RowKey, RowVisualData] = {}
        # Store row keys in the order they are *supposed* to be based on last sort
        # This helps manage cursor fallback but doesn't directly control table order
        self._sorted_row_keys: List[RowKey] = []

    def on_mount(self) -> None:
        """Set up columns on mount."""
        super().on_mount()
        self.add_column("Recent", key="history", width=self.RECENT_COL_WIDTH)
        initial_path_width = self._get_path_column_width()
        self.add_column("Path", key="path", width=initial_path_width)
        self.add_column("Age", key="age", width=self.AGE_COL_WIDTH)
        self.columns["path"].auto_width = False
        log.debug(
            f"FileDataTable mounted. Initial path width set to {initial_path_width}"
        )

    def _get_path_column_width(self):
        """Calculates the desired width for the path column based on user's logic."""
        # Use self.size.width which reflects the widget's current allocated space
        w = self.size.width - self.SCROLLBAR_WIDTH  # Typo fixed
        # Subtract estimated padding/separators for all columns
        w -= len(self.columns) * self.COLUMN_PADDING
        # Subtract fixed widths of other columns
        calculated_width = w - self.RECENT_COL_WIDTH - self.AGE_COL_WIDTH
        # Ensure width is at least 1
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
            self.refresh()  # Usually not needed as width change triggers redraw

    def update_data(self, sorted_file_infos: list[FileInfo]) -> None:
        """
        Updates the table content using partial updates (add/remove/update_cell).
        """
        current_time = time.time()
        log.debug(f"Starting partial update with {len(sorted_file_infos)} items.")

        # --- Preserve Cursor ---
        selected_key_before_update = self.selected_path
        selected_index_before_update = self.cursor_row

        # --- Calculate width for text formatting ---
        path_text_width = self._get_path_column_width()
        # Ensure column width is also up-to-date
        path_column = self.columns.get("path")
        if path_column and path_column.width != path_text_width:
            path_column.width = path_text_width

        # --- Prepare New State ---
        new_key_to_info_map: Dict[RowKey, FileInfo] = {
            RowKey(info.path): info for info in sorted_file_infos
        }
        new_keys_set: Set[RowKey] = set(new_key_to_info_map.keys())
        # Keep track of the desired sorted order
        self._sorted_row_keys = list(new_key_to_info_map.keys())

        # --- Diffing Logic ---
        current_keys_set: Set[RowKey] = set(self.rows.keys())
        keys_to_add = new_keys_set - current_keys_set
        keys_to_remove = current_keys_set - new_keys_set
        keys_to_check = current_keys_set.intersection(
            new_keys_set
        )  # Keys present before and after

        # --- Process Removals ---
        if keys_to_remove:
            log.debug(f"Removing {len(keys_to_remove)} rows.")
            for key in keys_to_remove:
                try:
                    self.remove_row(key)
                    self._row_data_cache.pop(key, None)  # Remove from cache
                except KeyError:
                    log.warning(f"Attempted to remove non-existent key: {key.value}")
                except Exception as e:
                    log.exception(f"Error removing row key {key.value}: {e}")

        # --- Process Additions and Updates ---
        added_count = 0
        updated_count = 0
        for key in self._sorted_row_keys:  # Iterate in the NEW desired order
            info = new_key_to_info_map[key]
            new_visuals = _format_file_info_for_table(
                info, path_text_width, current_time
            )

            if key in keys_to_check:
                # Existing key: Check if visual data changed
                old_visuals = self._row_data_cache.get(key)
                # Compare string representations for simplicity, or tuple directly
                if old_visuals is None or new_visuals != old_visuals:
                    try:
                        # Update cells only if data differs
                        self.update_cell(
                            key, "history", new_visuals[0], update_width=False
                        )
                        self.update_cell(
                            key, "path", new_visuals[1], update_width=False
                        )
                        self.update_cell(key, "age", new_visuals[2], update_width=False)
                        self._row_data_cache[key] = new_visuals
                        updated_count += 1
                    except KeyError:
                        log.warning(
                            f"KeyError updating cell for key (might have been removed concurrently?): {key.value}"
                        )
                    except Exception as e:
                        log.exception(f"Error updating cells for key {key.value}: {e}")
                # else: Row exists and visuals are the same, do nothing.

            elif key in keys_to_add:
                # New key: Add the row
                try:
                    # Add row - NOTE: This appends visually, does NOT respect sorted order here
                    self.add_row(*new_visuals, key=key.value)
                    self._row_data_cache[key] = new_visuals
                    added_count += 1
                except KeyError:
                    log.warning(
                        f"Attempted to add duplicate row key during add phase: {key.value}"
                    )
                except Exception as e:
                    log.exception(f"Error adding row for key {key.value}: {e}")

        if added_count > 0:
            log.debug(f"Added {added_count} new rows.")
        if updated_count > 0:
            log.debug(f"Updated {updated_count} existing rows.")
        if added_count > 0:
            log.warning(
                "Added rows appear at the end due to DataTable limitations; visual sort order may be temporarily incorrect."
            )

        # --- Restore Cursor ---
        new_cursor_index = -1
        if selected_key_before_update:
            selected_rowkey_obj = RowKey(selected_key_before_update)
            # Check if the key still exists *in the table's rows* after updates
            if selected_rowkey_obj in self.rows:
                try:
                    # Find the new visual index of the key
                    # This requires iterating through the current visual order
                    current_visual_keys = list(self.rows.keys())
                    new_cursor_index = current_visual_keys.index(selected_rowkey_obj)
                except ValueError:
                    log.warning(
                        f"Selected key '{selected_key_before_update}' not found in final table rows despite being expected."
                    )
                    # Fallback if index lookup fails unexpectedly
                    if self.row_count > 0:
                        potential_index = max(0, selected_index_before_update - 1)
                        new_cursor_index = min(potential_index, self.row_count - 1)
            else:
                # Key is gone, use fallback logic based on previous index
                if self.row_count > 0:
                    potential_index = max(0, selected_index_before_update - 1)
                    new_cursor_index = min(potential_index, self.row_count - 1)

        # Move cursor if a valid index was determined
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

        log.debug("Partial update finished.")
