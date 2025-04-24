# Filename: src/lsoph/ui/file_data_table.py
"""
A specialized DataTable widget using index-as-key for partial updates.
NOTE: This approach uses the visual index as the RowKey, which can lead
      to unexpected behavior if rows are added/removed in ways that disrupt
      the expected visual order compared to the underlying data sort order.
"""

import logging
import time
from typing import Any, Dict, List, Optional, Set, Tuple  # Restored List

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

# Renamed Type alias for the visual data tuple (must match column order)
TableRow = Tuple[Text, Text, Text]
COLUMN_KEYS = ["history", "path", "age"]  # Order must match TableRow


# --- Formatting Helper ---
# Renamed function
def _render_row(
    info: FileInfo, available_width: int, current_time: float
) -> TableRow:  # Returns visual components directly
    """Formats FileInfo into data suitable for DataTable.add_row/update_cell."""
    # (Implementation remains the same)

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
    Uses stringified index as RowKey and attempts partial updates.
    Simplified error handling and logging.
    Attempts to maintain relative cursor screen position during updates.
    """

    RECENT_COL_WIDTH = 8  # Width for emoji history (e.g., 5 emojis + padding)
    AGE_COL_WIDTH = 5  # width of the age column
    SCROLLBAR_WIDTH = 2  # just a guess 🤷
    COLUMN_PADDING = 2  # User's estimate for padding per column

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.cursor_type = "row"
        self.zebra_stripes = True
        # Renamed: Stores the list of paths in the order they were last displayed
        self._paths: List[str] = []
        # Renamed type alias used in Dict value
        self._row_data_cache: Dict[str, TableRow] = {}  # Key is str(index)

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

    def _get_path_column_width(self):
        """Calculates the desired width for the path column based on user's logic."""
        # Assume self.size is valid when this is called
        w = self.size.width - self.SCROLLBAR_WIDTH
        w -= len(self.columns) * self.COLUMN_PADDING
        calculated_width = w - self.RECENT_COL_WIDTH - self.AGE_COL_WIDTH
        return max(1, calculated_width)

    @property
    def selected_path(self) -> Optional[str]:
        """Returns the path string of the data visually at the cursor row."""
        # Simplified: relies on cursor_row being valid or index check failing
        idx = self.cursor_row
        # Use renamed internal list
        # Allow IndexError if idx >= len(...)
        if idx >= 0 and idx < len(self._paths):
            return self._paths[idx]
        return None  # Return None if index invalid (< 0)

    def on_resize(self, event: events.Resize) -> None:
        """Update path column width on resize."""
        new_width = self._get_path_column_width()
        path_column = self.columns.get("path")
        # Check column exists before accessing width
        if path_column and path_column.width != new_width:
            path_column.width = new_width
            # Update text widths immediately after resize
            self._refresh_path_text()  # Renamed method call
            self.refresh()  # Refresh after resize and text update

    # Renamed method
    def _refresh_path_text(self):
        """Force recalculation of path text for all rows after resize."""
        path_text_width = self._get_path_column_width()
        current_keys = list(self.rows.keys())
        for row_key_obj in current_keys:
            # Allow errors below to propagate if key is invalid or state inconsistent
            if row_key_obj.value is None:
                continue
            cache_key = str(row_key_obj.value)
            try:  # Add try block for int conversion
                idx_key = int(cache_key)  # Expect value to be convertible int
            except ValueError:
                # log.warning(f"Invalid index key value '{cache_key}' during text refresh.")
                continue  # Skip if key is not an integer index

            # Use renamed type alias
            cached_data: Optional[TableRow] = self._row_data_cache.get(cache_key)

            # Allow IndexError if idx_key is out of bounds for _paths
            # Check lower bound explicitly
            if cached_data and idx_key >= 0 and idx_key < len(self._paths):
                original_path = self._paths[idx_key]  # Use renamed list
                new_path_text = Text(
                    short_path(original_path, max(1, path_text_width)),
                    style=cached_data[1].style,
                )
                if new_path_text.plain != cached_data[1].plain:
                    # Allow KeyError if row was removed concurrently
                    self.update_cell(
                        cache_key, "path", new_path_text, update_width=False
                    )
                    self._row_data_cache[cache_key] = (
                        cached_data[0],
                        new_path_text,
                        cached_data[2],
                    )

    # Renamed method
    def _find_cursor_pos(
        self,
        old_idx: int,  # Renamed parameter
        old_paths: List[str],  # Renamed parameter
        new_paths: List[str],  # Renamed parameter
    ) -> int:
        """
        Finds the new target index for the cursor. Returns -1 if no
        logical target can be found based on the previous selection.
        """
        selected_path_before: Optional[str] = None
        # Check bounds BEFORE accessing old_paths
        if old_idx >= 0 and old_idx < len(old_paths):
            selected_path_before = old_paths[old_idx]

        if not selected_path_before:
            # No valid selection before, return -1
            return -1

        path_map = {path: i for i, path in enumerate(new_paths)}

        # 1. Check if original selected path still exists
        if selected_path_before in path_map:
            return path_map[selected_path_before]

        # 2. Search backwards up the *previous* list for an item that *still exists*
        for current_check_pos in range(old_idx - 1, -1, -1):
            # Allow potential IndexError if old_idx was invalid relative to old_paths
            path = old_paths[current_check_pos]
            if path in path_map:
                return path_map[path]  # Return the *new* index of the item found above

        # 3. If nothing found above, return -1 (no logical target)
        # Corrected comment: Caller handles the -1 case.
        return -1

    # Renamed parameter sorted_file_infos -> infos
    def update_data(self, infos: list[FileInfo]) -> None:
        """
        Updates the table content using index as key and attempting partial updates.
        Attempts to maintain relative cursor screen position.
        """
        current_time = time.time()

        # --- Preserve Cursor State & Calculate Target Scroll ---
        # Renamed variables
        old_idx = self.cursor_row
        old_paths = self._paths  # Use internal state directly, no need to copy list()
        old_count = len(old_paths)
        old_scroll_y = self.scroll_y
        cursor_screen_offset = -1

        if old_idx >= 0:
            cursor_screen_offset = old_idx - old_scroll_y

        # --- Prepare New State ---
        # Renamed variables
        new_paths = [info.path for info in infos]
        new_info_map = {info.path: info for info in infos}
        new_count = len(new_paths)

        # --- Calculate Target Cursor Index ---
        # Renamed variables and method call
        target_cursor_index = self._find_cursor_pos(old_idx, old_paths, new_paths)

        # --- Attempt to Scroll Viewport *BEFORE* Updates ---
        if target_cursor_index != -1 and cursor_screen_offset != -1:
            target_scroll_y = max(0, target_cursor_index - cursor_screen_offset)
            max_scroll = max(0, new_count - self.size.height)
            target_scroll_y = min(target_scroll_y, max_scroll)
            if self.scroll_y != target_scroll_y:
                # Allow potential errors during scroll setting to propagate
                self.scroll_y = target_scroll_y
        # --- End Pre-Update Scroll ---

        # --- Calculate width for text formatting ---
        path_text_width = self._get_path_column_width()
        # Ensure column width is up-to-date
        path_column = self.columns.get("path")
        if path_column and path_column.width != path_text_width:
            path_column.width = path_text_width

        # --- Diff and Update ---
        # Use renamed type alias
        new_data_cache: Dict[str, TableRow] = {}
        rows_updated = 0
        rows_added = 0
        rows_removed = 0

        # 1. Update/Overwrite existing visual slots
        update_limit = min(old_count, new_count)
        for i in range(update_limit):
            index_key = str(i)
            new_path = new_paths[i]
            # Allow KeyError if path somehow not in map (indicates inconsistency)
            new_info = new_info_map[new_path]

            # Use renamed function _render_row
            new_visuals = _render_row(new_info, path_text_width, current_time)
            new_data_cache[index_key] = new_visuals

            # Use renamed type alias
            old_visuals: Optional[TableRow] = self._row_data_cache.get(index_key)
            if new_visuals != old_visuals:
                # Allow KeyError if row 'i' doesn't exist when expected
                for col_idx, col_key_str in enumerate(COLUMN_KEYS):
                    self.update_cell(
                        index_key,
                        col_key_str,
                        new_visuals[col_idx],
                        update_width=False,
                    )
                rows_updated += 1

        # 2. Add new rows if new list is longer
        if new_count > old_count:
            for i in range(old_count, new_count):
                index_key = str(i)
                new_path = new_paths[i]
                new_info = new_info_map[new_path]  # Allow KeyError
                # Use renamed function _render_row
                new_visuals = _render_row(new_info, path_text_width, current_time)
                new_data_cache[index_key] = new_visuals
                # Allow KeyError if key 'i' somehow already exists
                self.add_row(*new_visuals, key=index_key)
                rows_added += 1

        # 3. Remove extra rows if new list is shorter
        elif old_count > new_count:
            for i in range(old_count - 1, new_count - 1, -1):
                index_key = str(i)
                # Allow KeyError if row 'i' doesn't exist
                self.remove_row(index_key)
                rows_removed += 1
                self._row_data_cache.pop(index_key, None)

        # Update internal state caches
        # Renamed variable
        self._paths = new_paths
        self._row_data_cache = new_data_cache

        # --- Move Cursor ---
        if target_cursor_index != -1:
            final_row_count = self.row_count
            if target_cursor_index < final_row_count:
                if self.cursor_row != target_cursor_index:
                    self.move_cursor(row=target_cursor_index, animate=False)
            # REMOVED automatic move to 0 if target is out of bounds
            # Let the cursor stay where it is if the target is invalid
            elif final_row_count <= 0:
                # If table becomes empty, cursor is implicitly invalid, do nothing
                pass
            # else: # Reduced logging
            # Target index is out of bounds, but table not empty.
            # log.warning(f"Target cursor index {target_cursor_index} out of bounds after update (row_count={final_row_count}). Cursor not moved.")

        # If target_cursor_index was -1, cursor is not moved.

        self.refresh()
