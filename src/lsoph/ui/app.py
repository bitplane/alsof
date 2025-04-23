# Filename: src/lsoph/ui/app.py
"""Main Textual application class for lsoph."""

import asyncio
import logging
import time  # Import time for calculating age
from collections import deque
from typing import Callable, Dict, List, Optional, Tuple, Union  # Added Optional, Tuple

# Third-party imports
from rich.text import Text
from textual.app import App, ComposeResult
from textual.binding import Binding
from textual.containers import Container
from textual.coordinate import Coordinate
from textual.reactive import reactive
from textual.widgets import DataTable, Footer, Static
from textual.widgets.data_table import CellKey, RowKey

# Import Worker related types if needed for specific handling
from textual.worker import Worker, WorkerState

# Local application imports
from lsoph.monitor import FileInfo, Monitor
from lsoph.util.short_path import short_path

# Import the screen classes
from .detail_screen import DetailScreen
from .log_screen import LogScreen

# Define types imported from cli (or define them commonly)
BackendFuncType = Callable[[Union[List[int], List[str]], Monitor], None]
BackendArgsType = Union[List[int], List[str]]
BackendWorkerFuncType = Callable[[BackendFuncType, Monitor, BackendArgsType], None]

log = logging.getLogger("lsoph.ui.app")


# --- Helper Functions for Table Update ---


def _format_file_info_for_table(
    info: FileInfo, available_width: int, current_time: float
) -> Tuple[str, Text, Text, Text]:
    """Formats FileInfo into data suitable for DataTable.add_row."""

    # 1. Determine Emoji
    emoji = " "  # Default
    if info.status == "deleted":
        emoji = "❌"
    elif info.status == "error" or info.last_error_enoent:
        emoji = "❗"
    else:
        recent_types = list(info.recent_event_types)
        has_read = "READ" in recent_types
        has_write = "WRITE" in recent_types
        if has_read and has_write:
            emoji = "↔️"
        elif has_write:
            emoji = "⬆️"
        elif has_read:
            emoji = "⬇️"
        elif info.is_open:
            emoji = "✅"
        elif "OPEN" in recent_types or "CLOSE" in recent_types:
            emoji = "🚪"
        elif "STAT" in recent_types:
            emoji = "👀"
        elif "RENAME" in recent_types:
            emoji = "🔄"
        elif info.event_history:
            emoji = "❔"  # Has history but no recent specific activity

    # 2. Determine Activity/Status String
    activity_str = ""
    if info.bytes_read or info.bytes_written:
        activity_str = f"{info.bytes_read}r/{info.bytes_written}w"
    # Show specific non-transient statuses if no I/O bytes recorded
    elif info.status not in ["unknown", "accessed", "closed", "active"]:
        activity_str = info.status  # e.g., "deleted", "error", "open"

    # 3. Shorten Path
    path_display = short_path(info.path, available_width)

    # 4. Calculate Age
    age_seconds = current_time - info.last_activity_ts
    if age_seconds < 10:
        age_str = f"{age_seconds:.1f}s"
    elif age_seconds < 60:
        age_str = f"{int(age_seconds)}s"
    elif age_seconds < 3600:
        age_str = f"{int(age_seconds / 60)}m"
    else:
        age_str = f"{int(age_seconds / 3600)}h"

    # 5. Determine Style
    style = ""
    if info.status == "deleted":
        style = "strike"
    elif info.last_error_enoent:
        style = "dim strike"
    elif info.status == "error":
        style = "red"
    elif info.is_open:
        style = "bold green" if info.status == "active" else "bold"
    elif info.status == "active":
        style = "green"
    elif info.last_event_type == "STAT" and not info.is_open:
        style = "yellow"
    elif age_seconds > 60:
        style = "dim"  # Dim older entries

    # 6. Create Rich Text objects
    emoji_text = Text(f" {emoji} ", style=style)
    activity_text = Text(activity_str.ljust(10), style=style)  # Pad activity
    path_text = Text(path_display, style=style)
    age_text = Text(age_str.rjust(4), style=style)  # Right-align age

    return info.path, emoji_text, activity_text, path_text, age_text


# --- Main Application ---


class FileApp(App[None]):
    """Textual file monitor application."""

    TITLE = "lsoph - List Open Files Helper"
    SUB_TITLE = "Monitoring file activity..."  # Initial subtitle

    BINDINGS = [
        Binding("q,escape", "quit", "Quit", show=True),
        Binding("x", "ignore_all", "Ignore All", show=True),
        Binding("i,backspace,delete", "ignore_selected", "Ignore Sel.", show=True),
        Binding("l,ctrl+l", "show_log", "Show/Hide Log", show=True),  # Added 'l'
        Binding("d,enter", "show_detail", "Show Detail", show=True),  # Added 'd'
        Binding("ctrl+d", "dump_monitor", "Dump Monitor", show=False),  # Debug
    ]

    CSS_PATH = "app.css"  # Load CSS from file

    # Reactive variable to trigger table updates when monitor version changes
    last_monitor_version = reactive(-1)
    # Reactive variable for the status bar content
    status_text = reactive("Status: Initializing...")

    def __init__(
        self,
        monitor: Monitor,
        log_queue: deque,
        backend_func: BackendFuncType,
        backend_args: BackendArgsType,
        backend_worker_func: BackendWorkerFuncType,
    ):
        """Initialize the FileApp."""
        super().__init__()
        self.monitor = monitor
        self.log_queue = log_queue
        self._backend_func = backend_func
        self._backend_args = backend_args
        self._backend_worker_func = backend_worker_func
        self._update_interval = 0.5  # Update interval for checking monitor version
        self._backend_worker: Optional[Worker] = None  # To hold the worker instance

    def compose(self) -> ComposeResult:
        """Create child widgets for the main application screen."""
        yield DataTable(id="file-table", cursor_type="row", zebra_stripes=True)
        yield Static(self.status_text, id="status-bar")  # Use reactive variable
        yield Footer()

    # --- Worker Management ---

    async def _run_backend_in_thread(
        self,
        worker_func: BackendWorkerFuncType,
        backend_func: BackendFuncType,
        monitor: Monitor,
        backend_args: BackendArgsType,
    ) -> None:
        """Runs the synchronous worker function in a thread using asyncio."""
        log.debug(f"Async wrapper starting task for {worker_func.__name__}")
        try:
            # Run the potentially blocking backend function in a separate thread
            await asyncio.to_thread(worker_func, backend_func, monitor, backend_args)
            log.debug(f"Async wrapper task for {worker_func.__name__} completed.")
            # Update status when backend finishes normally
            self.call_later(self.update_status, "Monitoring backend finished.")
        except Exception:
            # Log exceptions from the worker thread
            log.exception(f"Exception in background worker {worker_func.__name__}")
            self.call_later(self.update_status, "Error: Monitoring backend failed.")
            # self.notify("Background task failed", severity="error", timeout=5)

    def start_backend_worker(self):
        """Starts the background worker that runs the monitoring backend."""
        if self._backend_worker and self._backend_worker.state == WorkerState.RUNNING:
            log.warning("Backend worker already running.")
            return

        worker_name = f"backend_{self._backend_func.__module__}"
        log.info(
            f"Starting worker '{worker_name}' via run_worker with async wrapper..."
        )
        self._backend_worker = self.run_worker(
            self._run_backend_in_thread(
                self._backend_worker_func,
                self._backend_func,
                self.monitor,
                self._backend_args,
            ),
            name=worker_name,
            group="backend_workers",
            description=f"Running {self._backend_func.__module__} backend...",
            exclusive=True,  # Only one backend worker at a time
        )
        log.info(
            f"Worker {self._backend_worker.name} created with state {self._backend_worker.state}"
        )

    async def cancel_backend_worker(self):
        """Requests cancellation of the backend worker."""
        if self._backend_worker and self._backend_worker.state == WorkerState.RUNNING:
            log.info(
                f"Requesting cancellation for worker {self._backend_worker.name}..."
            )
            await self._backend_worker.cancel()  # Use await for cancellation
            log.info(f"Worker {self._backend_worker.name} cancellation requested.")
        elif self._backend_worker:
            log.debug(
                f"Backend worker {self._backend_worker.name} not running (state: {self._backend_worker.state})."
            )
        else:
            log.debug("No backend worker instance to cancel.")

    # --- App Lifecycle ---

    def on_mount(self) -> None:
        """Called when the app screen is mounted."""
        log.info("FileApp mounting...")
        table = self.query_one(DataTable)
        # Add columns with keys for easier updates
        table.add_column("?", key="emoji", width=3)
        table.add_column("Activity", key="activity", width=10)
        table.add_column("Path", key="path", width=80)  # Give path more space initially
        table.add_column("Age", key="age", width=5)

        self.update_table()  # Initial table population
        table.focus()
        log.debug("DataTable focused on mount.")

        # Start the backend monitoring process in the background
        self.start_backend_worker()

        # Start timer to periodically check for monitor updates
        self.set_interval(self._update_interval, self.check_monitor_version)
        self.update_status("Monitoring started...")
        log.info("UI Mounted, update timer started, backend worker started.")

    async def on_unmount(self) -> None:
        """Called when the app is unmounted (e.g., before exit)."""
        log.info("FileApp unmounting. Cancelling backend worker...")
        await self.cancel_backend_worker()  # Ensure worker cancellation is requested

    # --- Reactive Watchers ---

    def watch_last_monitor_version(self, old_version: int, new_version: int) -> None:
        """Called when the monitor version changes. Triggers table update."""
        if new_version > old_version:
            log.debug(
                f"Monitor version changed ({old_version} -> {new_version}), scheduling table update."
            )
            self.call_later(self.update_table)  # Schedule update instead of direct call

    def watch_status_text(self, old_text: str, new_text: str) -> None:
        """Called when status_text changes. Updates the status bar widget."""
        try:
            status_bar = self.query_one("#status-bar", Static)
            status_bar.update(new_text)
        except Exception as e:
            # Log if status bar isn't found, but don't crash
            log.warning(f"Could not update status bar: {e}")

    # --- Update Logic ---

    def check_monitor_version(self):
        """Periodically checks the monitor's version and updates the reactive variable if changed."""
        current_version = self.monitor.version
        if current_version != self.last_monitor_version:
            self.last_monitor_version = current_version  # Update reactive variable

    def update_status(self, text: str):
        """Helper method to update the reactive status_text variable."""
        self.status_text = text

    def update_table(self) -> None:
        """Updates the DataTable with the latest file information from the monitor."""
        if not self.monitor:
            return  # Monitor not initialized

        log.debug("Updating DataTable...")
        try:
            table = self.query_one(DataTable)
        except Exception:
            log.warning("Could not query table during update.")
            return

        current_time = time.time()

        # --- Calculate available width for path ---
        other_cols_width = 0
        col_count = 0
        fixed_width_cols = {"emoji", "activity", "age"}
        for key, col in table.columns.items():
            col_count += 1
            if key in fixed_width_cols:
                other_cols_width += col.width
        table_width = (
            table.content_size.width or self.size.width
        )  # Use screen width as fallback
        # Estimate padding/borders (adjust as needed)
        padding = max(0, col_count + 1) * 1
        available_width = max(
            20, table_width - other_cols_width - padding
        )  # Ensure minimum width
        log.debug(
            f"Table width: {table_width}, Other cols: {other_cols_width}, Padding: {padding}, Available for path: {available_width}"
        )
        # --- End width calculation ---

        # Get sorted list of active files from monitor
        all_files = list(self.monitor)
        active_files = [
            info for info in all_files if info.path not in self.monitor.ignored_paths
        ]
        active_files.sort(key=lambda info: info.last_activity_ts, reverse=True)
        log.debug(f"update_table: Processing {len(active_files)} active files.")

        # --- Preserve Cursor Position ---
        selected_row_key: Optional[RowKey] = None
        current_cursor_row_index = -1
        try:
            coordinate: Optional[Coordinate] = table.cursor_coordinate
            if coordinate and table.is_valid_coordinate(coordinate):
                current_cursor_row_index = coordinate.row
                cell_key: Optional[CellKey] = table.coordinate_to_cell_key(coordinate)
                selected_row_key = cell_key.row_key if cell_key else None
                log.debug(
                    f"Preserving cursor: RowIndex={current_cursor_row_index}, RowKey={selected_row_key}"
                )
        except Exception as e:
            log.debug(f"Error getting cursor state: {e}")
        # --- End Preserve Cursor ---

        # --- Update Table Rows ---
        current_rows = dict(table.rows)  # Get existing rows {RowKey: (RowData, Meta)}
        rows_to_add = []
        rows_to_update = {}  # {RowKey: NewRowData}
        row_keys_in_new_data = set()
        new_row_key_to_index_map: Dict[RowKey, int] = (
            {}
        )  # Map RowKey back to its new index

        for idx, info in enumerate(active_files):
            row_key_value, emoji, activity, path, age = _format_file_info_for_table(
                info, available_width, current_time
            )
            row_key = RowKey(row_key_value)
            row_keys_in_new_data.add(row_key)
            new_row_key_to_index_map[row_key] = idx  # Store new index
            new_row_data = (emoji, activity, path, age)

            if row_key in current_rows:
                # Check if data actually changed before marking for update
                # This avoids unnecessary redraws if only timestamp changed slightly
                # Note: Comparing Rich Text objects directly might be complex.
                # A simpler check might compare key attributes or just update always.
                # For now, we update if the row exists in the new data.
                rows_to_update[row_key] = new_row_data
            else:
                rows_to_add.append((row_key, new_row_data))

        rows_to_remove = [
            key for key in current_rows if key not in row_keys_in_new_data
        ]
        # --- End Update Table Rows ---

        # --- Apply Changes with update_rows ---
        # Perform updates efficiently using update_rows (Textual 0.53+)
        try:
            table.update_rows(
                add=rows_to_add,
                update=rows_to_update,
                remove=rows_to_remove,
            )
            log.debug(
                f"DataTable updated: Added={len(rows_to_add)}, Updated={len(rows_to_update)}, Removed={len(rows_to_remove)}"
            )
        except Exception as e:
            log.exception(f"Error during table.update_rows: {e}")
            # Fallback to clear/add if update_rows fails (e.g., older Textual)
            # table.clear()
            # for key, data in rows_to_add: table.add_row(*data, key=key.value)
            # for key, data in rows_to_update.items(): table.add_row(*data, key=key.value)

        # --- Restore Cursor Position ---
        new_row_index_to_set = -1
        if (
            selected_row_key is not None
            and selected_row_key in new_row_key_to_index_map
        ):
            # If the previously selected row still exists, restore it
            new_row_index_to_set = new_row_key_to_index_map[selected_row_key]
            log.debug(
                f"Restoring cursor to key '{selected_row_key}' at new index {new_row_index_to_set}"
            )
        elif current_cursor_row_index != -1 and table.row_count > 0:
            # If previous row is gone, try to keep cursor near original position
            new_row_index_to_set = min(current_cursor_row_index, table.row_count - 1)
            log.debug(
                f"Restoring cursor near original index {current_cursor_row_index} -> {new_row_index_to_set}"
            )
        elif table.row_count > 0:
            # Otherwise, move to the top row if the table is not empty
            new_row_index_to_set = 0
            log.debug("Moving cursor to top row.")

        if new_row_index_to_set != -1:
            try:
                # Check validity before moving
                if table.is_valid_row_index(new_row_index_to_set):
                    table.move_cursor(row=new_row_index_to_set, animate=False)
                else:
                    log.warning(
                        f"Calculated new cursor row {new_row_index_to_set} is invalid."
                    )
            except Exception as e:
                log.error(f"Error moving cursor to row {new_row_index_to_set}: {e}")
        # --- End Restore Cursor ---

        # Update status bar text (via reactive variable)
        self.update_status(
            f"Tracking {len(active_files)} files. Ignored: {len(self.monitor.ignored_paths)}. Monitor v{self.monitor.version}"
        )

    # --- Event Handlers ---

    def on_data_table_row_selected(self, event: DataTable.RowSelected) -> None:
        """Called when the user presses Enter on a DataTable row."""
        self.action_show_detail()  # Delegate to action

    # --- Actions ---

    async def action_quit(self) -> None:
        """Action to quit the application."""
        log.info("Quit action triggered. Cancelling workers and exiting.")
        await self.cancel_backend_worker()
        self.exit()

    def _get_selected_path(self) -> Optional[str]:
        """Helper to get the path string from the currently selected row."""
        try:
            table = self.query_one(DataTable)
            coordinate = table.cursor_coordinate
            if not table.is_valid_coordinate(coordinate):
                return None
            cell_key: Optional[CellKey] = table.coordinate_to_cell_key(coordinate)
            row_key_obj = cell_key.row_key if cell_key else None
            if row_key_obj is not None and row_key_obj.value is not None:
                return str(row_key_obj.value)
        except Exception as e:
            log.error(f"Error getting selected path: {e}")
        return None

    def action_ignore_selected(self) -> None:
        """Action to ignore the currently selected file path."""
        path_to_ignore = self._get_selected_path()
        if not path_to_ignore:
            self.notify("No row selected.", severity="warning", timeout=2)
            return

        log.info(f"Ignoring selected path: {path_to_ignore}")
        try:
            # Keep track of original cursor index before modification
            table = self.query_one(DataTable)
            original_row_index = table.cursor_row

            self.monitor.ignore(path_to_ignore)
            # Monitor change should trigger reactive update via check_monitor_version

            # Try to move cursor intelligently after ignore (might be delayed)
            # This logic might run before the table fully updates, so it's best effort.
            self.call_later(self._move_cursor_after_ignore, original_row_index)

            self.notify(f"Ignored: {short_path(path_to_ignore, 60)}", timeout=2)
        except Exception as e:
            log.exception("Error ignoring selected.")
            self.notify(f"Error ignoring file: {e}", severity="error")

    def _move_cursor_after_ignore(self, original_row_index: int):
        """Attempts to move cursor after an item is ignored."""
        try:
            table = self.query_one(DataTable)
            if table.row_count > 0:
                # Try to move to the row before the deleted one, or top/bottom
                new_cursor_row = max(0, original_row_index - 1)  # Try row above first
                new_cursor_row = min(
                    new_cursor_row, table.row_count - 1
                )  # Clamp to bounds
                if table.is_valid_row_index(new_cursor_row):
                    table.move_cursor(row=new_cursor_row, animate=False)
                    log.debug(f"Moved cursor to row {new_cursor_row} after ignore.")
                else:  # Fallback to top if calculation failed
                    table.move_cursor(row=0, animate=False)
            else:
                log.debug("Table empty after ignore, cursor not moved.")
        except Exception as e:
            log.error(f"Error moving cursor after ignore: {e}")

    def action_ignore_all(self) -> None:
        """Action to ignore all currently tracked files."""
        log.info("Ignoring all tracked files.")
        try:
            count_before = len(
                [fi for fi in self.monitor if fi.path not in self.monitor.ignored_paths]
            )
            if count_before == 0:
                self.notify("No active files to ignore.", timeout=2)
                return

            self.monitor.ignore_all()
            # Monitor change should trigger reactive update

            # Move cursor to top after clearing all
            self.call_later(self._move_cursor_after_ignore_all)

            self.notify(f"Ignoring {count_before} currently tracked files.", timeout=2)
        except Exception as e:
            log.exception("Error ignoring all.")
            self.notify(f"Error ignoring all files: {e}", severity="error")

    def _move_cursor_after_ignore_all(self):
        """Moves cursor to top after ignore_all action."""
        try:
            table = self.query_one(DataTable)
            if table.row_count > 0:
                table.move_cursor(row=0, animate=False)
        except Exception as e:
            log.error(f"Error moving cursor after ignore all: {e}")

    def action_show_log(self) -> None:
        """Action to show or hide the log screen."""
        # Check if LogScreen is the topmost screen
        is_log_screen_active = isinstance(self.screen, LogScreen)

        if is_log_screen_active:
            self.pop_screen()
            log.debug("Popped LogScreen.")
        else:
            # Check if *any* LogScreen is installed (might be under another modal)
            if self.is_screen_installed(LogScreen):
                # If it's installed but not active, pop until we reveal it
                # This might be unexpected behavior, consider just pushing a new one?
                # For simplicity, let's just push a new one if it's not the active screen.
                log.info("LogScreen installed but not active, pushing a new LogScreen.")
                self.push_screen(LogScreen(self.log_queue))
            else:
                # LogScreen not installed, push it
                log.info("Action: show_log triggered. Pushing LogScreen.")
                self.push_screen(LogScreen(self.log_queue))

    def action_show_detail(self) -> None:
        """Shows the detail screen for the selected row."""
        path = self._get_selected_path()
        if not path:
            self.notify("No row selected.", severity="warning", timeout=2)
            return

        log.debug(f"Showing details for selected path: {path}")
        try:
            file_info = self.monitor.files.get(path)
            if file_info:
                log.debug(f"Found FileInfo, pushing DetailScreen for {path}")
                self.push_screen(DetailScreen(file_info))
            else:
                log.warning(
                    f"File '{path}' (from row_key.value) not found in monitor state."
                )
                self.notify(
                    "File state not found (may have changed).",
                    severity="warning",
                    timeout=3,
                )
        except Exception as e:
            log.exception(f"Error pushing DetailScreen for path: {path}")
            self.notify(f"Error showing details: {e}", severity="error")

    def action_dump_monitor(self) -> None:
        """Debug action to dump monitor state to log."""
        log.debug("--- Monitor State Dump ---")
        try:
            log.debug(f"Identifier: {self.monitor.identifier}")
            log.debug(f"Backend PID: {self.monitor.backend_pid}")
            log.debug(f"Ignored Paths: {self.monitor.ignored_paths!r}")
            log.debug(
                f"PID->FD Map ({len(self.monitor.pid_fd_map)} pids): {self.monitor.pid_fd_map!r}"
            )
            log.debug(f"Files Dict ({len(self.monitor.files)} items):")
            # Use waits decorator implicitly via iteration
            sorted_files = sorted(list(self.monitor), key=lambda f: f.path)
            for info in sorted_files:
                log.debug(f"  {info.path}: {info!r}")
            log.debug("--- End Monitor State Dump ---")
            self.notify("Monitor state dumped to log (debug level).")
        except Exception as e:
            log.exception("Error during monitor state dump.")
            self.notify("Error dumping monitor state.", severity="error")
