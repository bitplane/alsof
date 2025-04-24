# Filename: src/lsoph/ui/file_data_table.py
"""
A specialized DataTable widget using index-as-key for partial updates.
Handles bytes paths from the Monitor and decodes for display.
"""

import logging
import os  # For os.fsdecode
import time
from typing import Any, Dict, List, Optional, Set, Tuple

from rich.text import Text
from textual import events
from textual.coordinate import Coordinate
from textual.widgets import DataTable
from textual.widgets.data_table import CellKey, RowKey

from lsoph.monitor import FileInfo

# short_path utility now accepts bytes and returns str
from lsoph.util.short_path import short_path

# Import the new emoji helper (doesn't need changes)
from .emoji import get_emoji_history_string

log = logging.getLogger("lsoph.ui.table")

# Type alias for the visual data tuple (strings for display)
TableRow = Tuple[Text, Text, Text]
COLUMN_KEYS = ["history", "path", "age"]  # Order must match TableRow


# --- Formatting Helper ---
def _render_row(
    info: FileInfo, available_width: int, current_time: float
) -> TableRow:  # Returns visual components (Text objects)
    """Formats FileInfo (with bytes path) into Text suitable for DataTable."""

    # --- Get Emoji History ---
    MAX_EMOJI_HISTORY = 5  # Keep consistent with column width
    emoji_history_str = get_emoji_history_string(info, MAX_EMOJI_HISTORY)
    # --- End Emoji History ---

    # --- DECODE AND SHORTEN PATH ---
    # Use short_path utility which accepts bytes and returns decoded, shortened string
    path_display_str = short_path(info.path, max(1, available_width))
    # -----------------------------

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
    path_text = Text(path_display_str, style=style)  # Use decoded string
    age_text = Text(age_str.rjust(4), style=style)

    return recent_text, path_text, age_text


# --- End Formatting Helper ---


class FileDataTable(DataTable):
    """
    A DataTable specialized for displaying and managing FileInfo.
    Uses stringified index as RowKey and attempts partial updates.
    Stores original bytes paths internally but displays decoded strings.
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
        # --- _paths NOW STORES BYTES ---
        self._paths: List[bytes] = []
        # -----------------------------
        # Cache stores visual Text objects (TableRow)
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
    def selected_path(self) -> Optional[bytes]:  # Returns bytes path
        """Returns the original bytes path of the data visually at the cursor row."""
        idx = self.cursor_row
        # Use internal bytes list
        if idx >= 0 and idx < len(self._paths):
            return self._paths[idx]  # Return bytes path
        return None  # Return None if index invalid (< 0)

    def on_resize(self, event: events.Resize) -> None:
        """Update path column width on resize."""
        new_width = self._get_path_column_width()
        path_column = self.columns.get("path")
        if path_column and path_column.width != new_width:
            path_column.width = new_width
            # Update displayed path text widths immediately after resize
            self._refresh_path_text()
            self.refresh()

    def _refresh_path_text(self):
        """Force recalculation of displayed path text for all rows after resize."""
        path_text_width = self._get_path_column_width()
        current_keys = list(self.rows.keys())
        for row_key_obj in current_keys:
            if row_key_obj.value is None:
                continue
            cache_key = str(row_key_obj.value)
            try:
                idx_key = int(cache_key)
            except ValueError:
                continue

            cached_data: Optional[TableRow] = self._row_data_cache.get(cache_key)

            if cached_data and idx_key >= 0 and idx_key < len(self._paths):
                # --- GET ORIGINAL BYTES PATH ---
                original_path_bytes = self._paths[idx_key]
                # -----------------------------
                # --- DECODE AND SHORTEN ---
                new_path_display_str = short_path(
                    original_path_bytes, max(1, path_text_width)
                )
                # ------------------------
                new_path_text = Text(
                    new_path_display_str,
                    style=cached_data[1].style,  # Keep original style
                )

                if new_path_text.plain != cached_data[1].plain:
                    try:
                        self.update_cell(
                            cache_key, "path", new_path_text, update_width=False
                        )
                        self._row_data_cache[cache_key] = (
                            cached_data[0],
                            new_path_text,  # Update cache with new Text
                            cached_data[2],
                        )
                    except KeyError:
                        log.warning(
                            f"Row key '{cache_key}' not found during path text refresh."
                        )

    def _find_cursor_pos(
        self,
        old_idx: int,
        old_paths: List[bytes],  # Expects bytes paths
        new_paths: List[bytes],  # Expects bytes paths
    ) -> int:
        """
        Finds the new target index for the cursor based on bytes paths.
        Returns -1 if no logical target can be found.
        """
        selected_path_before: Optional[bytes] = None
        if old_idx >= 0 and old_idx < len(old_paths):
            selected_path_before = old_paths[old_idx]

        if not selected_path_before:
            return -1

        # Map bytes paths to new indices
        path_map = {path: i for i, path in enumerate(new_paths)}

        # 1. Check if original selected bytes path still exists
        if selected_path_before in path_map:
            return path_map[selected_path_before]

        # 2. Search backwards up the *previous* list for an item that *still exists*
        for current_check_pos in range(old_idx - 1, -1, -1):
            # Allow potential IndexError if old_idx was invalid relative to old_paths
            try:
                path = old_paths[current_check_pos]
                if path in path_map:
                    return path_map[path]  # Return the *new* index
            except IndexError:
                log.warning(
                    f"IndexError accessing old_paths at {current_check_pos} in _find_cursor_pos"
                )
                break  # Stop searching if index is invalid

        # 3. If nothing found above, return -1
        return -1

    def update_data(self, infos: list[FileInfo]) -> None:
        """
        Updates the table content using index as key and attempting partial updates.
        Accepts FileInfo with bytes paths, displays decoded strings.
        Attempts to maintain relative cursor screen position.
        """
        current_time = time.time()

        # --- Preserve Cursor State & Calculate Target Scroll ---
        old_idx = self.cursor_row
        old_paths_bytes = self._paths  # Internal state uses bytes
        old_count = len(old_paths_bytes)
        old_scroll_y = self.scroll_y
        cursor_screen_offset = -1

        if old_idx >= 0:
            cursor_screen_offset = old_idx - old_scroll_y

        # --- Prepare New State ---
        # --- PATHS ARE NOW BYTES ---
        new_paths_bytes = [info.path for info in infos]
        new_info_map = {info.path: info for info in infos}  # Map bytes path -> FileInfo
        # -------------------------
        new_count = len(new_paths_bytes)

        # --- Calculate Target Cursor Index (using bytes paths) ---
        target_cursor_index = self._find_cursor_pos(
            old_idx, old_paths_bytes, new_paths_bytes
        )

        # --- Attempt to Scroll Viewport *BEFORE* Updates ---
        if target_cursor_index != -1 and cursor_screen_offset != -1:
            target_scroll_y = max(0, target_cursor_index - cursor_screen_offset)
            # Use actual table height for max scroll calculation
            table_height = (
                self.content_size.height
            )  # Or self.size.height if more appropriate
            max_scroll = max(0, new_count - table_height)
            target_scroll_y = min(target_scroll_y, max_scroll)
            if self.scroll_y != target_scroll_y:
                try:
                    self.scroll_y = target_scroll_y
                except Exception as scroll_err:
                    log.warning(
                        f"Error setting scroll_y to {target_scroll_y}: {scroll_err}"
                    )

        # --- Calculate width for text formatting ---
        path_text_width = self._get_path_column_width()
        # Ensure column width is up-to-date
        path_column = self.columns.get("path")
        if path_column and path_column.width != path_text_width:
            path_column.width = path_text_width

        # --- Diff and Update ---
        new_data_cache: Dict[str, TableRow] = {}  # Cache holds visual Text objects
        rows_updated = 0
        rows_added = 0
        rows_removed = 0

        # 1. Update/Overwrite existing visual slots
        update_limit = min(old_count, new_count)
        for i in range(update_limit):
            index_key = str(i)
            new_path_bytes = new_paths_bytes[i]  # Get bytes path
            try:
                new_info = new_info_map[
                    new_path_bytes
                ]  # Look up FileInfo using bytes path
            except KeyError:
                log.error(
                    f"Inconsistency: Path {os.fsdecode(new_path_bytes)!r} not found in new_info_map at index {i}"
                )
                continue  # Skip this row if data is inconsistent

            # _render_row accepts FileInfo (with bytes path), returns visual Text objects
            new_visuals: TableRow = _render_row(new_info, path_text_width, current_time)
            new_data_cache[index_key] = new_visuals  # Cache the visual representation

            old_visuals: Optional[TableRow] = self._row_data_cache.get(index_key)
            if new_visuals != old_visuals:
                try:
                    for col_idx, col_key_str in enumerate(COLUMN_KEYS):
                        self.update_cell(
                            index_key,
                            col_key_str,
                            new_visuals[col_idx],  # Update with new Text object
                            update_width=False,
                        )
                    rows_updated += 1
                except KeyError:
                    log.warning(f"Row key '{index_key}' not found during update.")

        # 2. Add new rows if new list is longer
        if new_count > old_count:
            for i in range(old_count, new_count):
                index_key = str(i)
                new_path_bytes = new_paths_bytes[i]  # Get bytes path
                try:
                    new_info = new_info_map[
                        new_path_bytes
                    ]  # Look up FileInfo using bytes path
                except KeyError:
                    log.error(
                        f"Inconsistency: Path {os.fsdecode(new_path_bytes)!r} not found in new_info_map at index {i}"
                    )
                    continue  # Skip adding row if data is inconsistent

                # _render_row accepts FileInfo (with bytes path), returns visual Text objects
                new_visuals = _render_row(new_info, path_text_width, current_time)
                new_data_cache[index_key] = new_visuals  # Cache visual representation
                try:
                    self.add_row(*new_visuals, key=index_key)
                    rows_added += 1
                except KeyError:
                    log.warning(f"Row key '{index_key}' already exists during add.")

        # 3. Remove extra rows if new list is shorter
        elif old_count > new_count:
            for i in range(old_count - 1, new_count - 1, -1):
                index_key = str(i)
                try:
                    self.remove_row(index_key)
                    rows_removed += 1
                except KeyError:
                    log.warning(f"Row key '{index_key}' not found during remove.")
                self._row_data_cache.pop(index_key, None)  # Remove from visual cache

        # Update internal state caches
        self._paths = new_paths_bytes  # Store new list of bytes paths
        self._row_data_cache = new_data_cache  # Store new visual cache

        # --- Move Cursor ---
        if target_cursor_index != -1:
            final_row_count = self.row_count
            if target_cursor_index < final_row_count:
                if self.cursor_row != target_cursor_index:
                    try:
                        self.move_cursor(row=target_cursor_index, animate=False)
                    except Exception as cursor_err:
                        log.warning(
                            f"Error moving cursor to {target_cursor_index}: {cursor_err}"
                        )
            elif final_row_count <= 0:
                pass  # Table empty, do nothing
            # else: # Target index out of bounds
            #     log.warning(f"Target cursor index {target_cursor_index} out of bounds after update (row_count={final_row_count}). Cursor not moved.")

        # If target_cursor_index was -1, cursor is not moved.

        # No explicit self.refresh() needed here, as add/update/remove should trigger it.
