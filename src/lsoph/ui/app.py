# Filename: src/lsoph/ui/app.py
"""Main Textual application class for lsoph."""

import asyncio
import logging
import time

# Use Python 3.10+ style hints
from collections import deque
from typing import Any, Callable, Coroutine, Dict, List, Optional, Tuple

from rich.text import Text
from textual.app import App, ComposeResult
from textual.binding import Binding
from textual.containers import Vertical
from textual.coordinate import Coordinate
from textual.dom import NoMatches
from textual.reactive import reactive
from textual.widgets import DataTable, Footer, Header, Static
from textual.widgets.data_table import CellKey, RowKey
from textual.worker import Worker, WorkerState

# Import the corrected base backend class
from lsoph.backend.base import Backend

# Import FileInfo for type hinting
from lsoph.monitor import FileInfo, Monitor
from lsoph.util.short_path import short_path

from .detail_screen import DetailScreen
from .log_screen import LogScreen

# Type alias for the backend coroutine (attach or run_command)
BackendCoroutine = Coroutine[Any, Any, None]

log = logging.getLogger("lsoph.ui.app")


# --- Helper Functions for Table Update ---
# _format_file_info_for_table remains the same
def _format_file_info_for_table(
    info: FileInfo, available_width: int, current_time: float
) -> Tuple[str, Text, Text, Text, Text]:
    """Formats FileInfo into data suitable for DataTable.add_row."""
    emoji = " "
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
            emoji = "❔"

    activity_str = ""
    if info.bytes_read or info.bytes_written:
        activity_str = f"{info.bytes_read}r/{info.bytes_written}w"
    elif info.status not in ["unknown", "accessed", "closed", "active"]:
        activity_str = info.status

    path_display = short_path(info.path, available_width)

    age_seconds = current_time - info.last_activity_ts
    if age_seconds < 10:
        age_str = f"{age_seconds:.1f}s"
    elif age_seconds < 60:
        age_str = f"{int(age_seconds)}s"
    elif age_seconds < 3600:
        age_str = f"{int(age_seconds / 60)}m"
    else:
        age_str = f"{int(age_seconds / 3600)}h"

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
        style = "dim"

    emoji_text = Text(f" {emoji} ", style=style)
    activity_text = Text(activity_str.ljust(10), style=style)
    path_text = Text(path_display, style=style)
    age_text = Text(age_str.rjust(4), style=style)

    return info.path, emoji_text, activity_text, path_text, age_text


# --- Main Application ---


class LsophApp(App[None]):
    """Textual file monitor application for lsoph."""

    TITLE = "lsoph - List Open Files Helper"
    SUB_TITLE = "Monitoring file activity..."

    BINDINGS = [
        Binding("q,escape", "quit", "Quit", show=True),
        Binding("x", "ignore_all", "Ignore All", show=True),
        Binding("i,backspace,delete", "ignore_selected", "Ignore Sel.", show=True),
        Binding("l,ctrl+l", "show_log", "Show/Hide Log", show=True),
        Binding("d,enter", "show_detail", "Show Detail", show=True),
        Binding("ctrl+d", "dump_monitor", "Dump Monitor", show=False),
    ]

    CSS_PATH = "app.css"

    last_monitor_version = reactive(-1)
    status_text = reactive("Status: Initializing...")

    def __init__(
        self,
        monitor: Monitor,
        log_queue: deque,
        backend_instance: Backend,
        backend_coroutine: BackendCoroutine,
    ):
        super().__init__()
        self.monitor = monitor
        self.log_queue = log_queue
        self.backend_instance = backend_instance
        self.backend_coroutine = backend_coroutine
        self._update_interval = 0.5
        self._backend_worker: Optional[Worker] = None
        self._backend_stop_signalled = False
        self._backend_stopped_notified = False

    def compose(self) -> ComposeResult:
        """Create child widgets for the main application screen."""
        yield Header()
        yield DataTable(id="file-table", cursor_type="row", zebra_stripes=True)
        yield Static(self.status_text, id="status-bar")
        yield Footer()

    # --- Worker Management ---

    def start_backend_worker(self):
        """Starts the background worker to run the backend's async method."""
        if self._backend_worker and self._backend_worker.state == WorkerState.RUNNING:
            log.warning("Backend worker already running.")
            return
        worker_name = f"backend_{self.backend_instance.__class__.__name__}"
        log.info(f"Starting worker '{worker_name}' to run backend coroutine...")
        self._backend_worker = self.run_worker(
            self.backend_coroutine,
            name=worker_name,
            group="backend_workers",
            description=f"Running {self.backend_instance.__class__.__name__} backend...",
            exclusive=True,
        )
        log.info(
            f"Worker {self._backend_worker.name} created with state {self._backend_worker.state}"
        )

    async def cancel_backend_worker(self):
        """Signals the backend instance to stop and cancels the Textual worker."""
        # First, signal the backend instance itself to stop its internal loops
        # This should handle terminating the actual strace/lsof process
        log.debug("Calling backend_instance.stop()...")
        await self.backend_instance.stop()
        log.debug("Backend_instance.stop() returned.")

        # Now, handle the Textual worker cancellation if it's still relevant
        worker = self._backend_worker  # Use local variable for safety
        if worker and worker.state == WorkerState.RUNNING:
            log.info(f"Requesting cancellation for Textual worker {worker.name}...")
            # Use try-except around await cancel() as it might raise errors
            # if the worker state changes rapidly between the check and the call
            try:
                await worker.cancel()
                log.info(f"Textual worker {worker.name} cancellation requested.")
            except Exception as e:
                log.error(f"Error cancelling Textual worker {worker.name}: {e}")
        elif worker:
            log.debug(
                f"Textual backend worker {worker.name} not running (state: {worker.state}). No Textual cancellation needed."
            )
        else:
            log.debug("No Textual backend worker instance to cancel.")
        # Ensure the worker reference is cleared after handling
        self._backend_worker = None

    # --- App Lifecycle ---

    def on_mount(self) -> None:
        """Called when the app screen is mounted."""
        log.info("LsophApp mounting...")
        table = self.query_one(DataTable)
        table.add_column("?", key="emoji", width=3)
        table.add_column("Activity", key="activity", width=10)
        table.add_column("Path", key="path", width=80)
        table.add_column("Age", key="age", width=5)
        self.update_table()
        table.focus()
        log.debug("DataTable focused on mount.")
        self.start_backend_worker()
        self.set_interval(self._update_interval, self.check_monitor_version)
        log.info("UI Mounted, update timer started, backend worker started.")

    async def on_unmount(self) -> None:  # Make async
        """Called when the app is unmounted."""
        log.info("LsophApp unmounting. Cancelling backend worker...")
        self._backend_stop_signalled = True
        await self.cancel_backend_worker()

    # --- Reactive Watchers ---

    def watch_last_monitor_version(self, old_version: int, new_version: int) -> None:
        if new_version > old_version:
            self.call_later(self.update_table)

    def watch_status_text(self, old_text: str, new_text: str) -> None:
        if self.is_mounted:
            try:
                status_bars = self.query("#status-bar")
                if status_bars:
                    status_bars.first(Static).update(new_text)
            except Exception as e:
                log.warning(f"Could not update status bar via watcher: {e}")

    # --- Update Logic ---

    def check_monitor_version(self):
        """Periodically checks the monitor's version and worker status."""
        worker = self._backend_worker
        if (
            worker
            and worker.state != WorkerState.RUNNING
            and not self._backend_stop_signalled
            and not self._backend_stopped_notified
        ):
            self._backend_stopped_notified = True
            # Determine if it was an actual error or just unexpected success
            status_msg = f"Error: Monitoring backend stopped unexpectedly!"
            log_msg = f"Backend worker {worker.name} stopped unexpectedly (state: {worker.state})."
            severity = "error"

            # Log the error. Textual/Asyncio should have logged the exception already if one occurred.
            log.error(log_msg + " Check previous logs for potential errors.")

            # Update UI
            self.update_status(status_msg)
            self.notify(
                f"{status_msg} Check logs for details.",
                title="Backend Stopped Unexpectedly",
                severity=severity,
                timeout=10,
            )
            # Clear the worker reference as it's no longer valid/running
            self._backend_worker = None

        # Check monitor version for table updates
        current_version = self.monitor.version
        if current_version != self.last_monitor_version:
            self.last_monitor_version = current_version

    def update_status(self, text: str):
        """Helper method to update the reactive status_text variable."""
        self.status_text = text

    def update_table(self) -> None:
        """Updates the DataTable with the latest file information."""
        if not self.monitor:
            return
        try:
            table = self.query_one(DataTable)
        except NoMatches:
            log.warning("DataTable not found during update_table.")
            return
        except Exception as e:
            log.exception(f"Error querying table: {e}")
            return

        current_time = time.time()
        other_cols_width = sum(
            col.width
            for key, col in table.columns.items()
            if key in {"emoji", "activity", "age"}
        )
        col_count = len(table.columns)
        table_width = table.content_size.width or self.size.width
        padding = max(0, col_count + 1) * 1
        available_width = max(20, table_width - other_cols_width - padding)
        all_files = list(self.monitor)
        active_files = [
            info for info in all_files if info.path not in self.monitor.ignored_paths
        ]
        active_files.sort(key=lambda info: info.last_activity_ts, reverse=True)
        selected_row_key: Optional[RowKey] = None
        current_cursor_row_index = -1
        try:
            coordinate: Optional[Coordinate] = table.cursor_coordinate
            if coordinate and table.is_valid_coordinate(coordinate):
                current_cursor_row_index = coordinate.row
                cell_key: Optional[CellKey] = table.coordinate_to_cell_key(coordinate)
                selected_row_key = cell_key.row_key if cell_key else None
        except Exception as e:
            log.debug(f"Error getting cursor state: {e}")
        table.clear()
        row_keys_added_this_update = set()
        new_row_key_to_index_map: Dict[RowKey, int] = {}
        for idx, info in enumerate(active_files):
            row_key_value, emoji, activity, path, age = _format_file_info_for_table(
                info, available_width, current_time
            )
            row_key = RowKey(row_key_value)
            if row_key in row_keys_added_this_update:
                continue
            row_keys_added_this_update.add(row_key)
            new_row_key_to_index_map[row_key] = idx
            row_data = (emoji, activity, path, age)
            try:
                table.add_row(*row_data, key=row_key_value)
            except Exception as add_exc:
                log.exception(f"Error adding row for key {row_key_value}: {add_exc}")
        new_row_index_to_set = -1
        if (
            selected_row_key is not None
            and selected_row_key in new_row_key_to_index_map
        ):
            new_row_index_to_set = new_row_key_to_index_map[selected_row_key]
        elif current_cursor_row_index != -1 and table.row_count > 0:
            new_row_index_to_set = min(current_cursor_row_index, table.row_count - 1)
        elif table.row_count > 0:
            new_row_index_to_set = 0
        if new_row_index_to_set != -1:
            try:
                if table.is_valid_row_index(new_row_index_to_set):
                    table.move_cursor(row=new_row_index_to_set, animate=False)
            except Exception as e:
                log.error(f"Error moving cursor to row {new_row_index_to_set}: {e}")
        self.update_status(
            f"Tracking {len(active_files)} files. Ignored: {len(self.monitor.ignored_paths)}. Monitor v{self.monitor.version}"
        )

    # --- Event Handlers ---

    def on_data_table_row_selected(self, event: DataTable.RowSelected) -> None:
        self.action_show_detail()

    # --- Actions ---

    async def action_quit(self) -> None:  # Make async
        """Action to quit the application."""
        log.info("Quit action triggered. Signalling backend worker and exiting.")
        self._backend_stop_signalled = True
        await self.cancel_backend_worker()
        self.exit()

    # _get_selected_path, action_ignore_selected, _move_cursor_after_ignore,
    # action_ignore_all, _move_cursor_after_ignore_all, action_show_log,
    # action_show_detail, action_dump_monitor remain synchronous

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
            table = self.query_one(DataTable)
            original_row_index = table.cursor_row
            self.monitor.ignore(path_to_ignore)
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
                new_cursor_row = max(0, original_row_index - 1)
                new_cursor_row = min(new_cursor_row, table.row_count - 1)
                if table.is_valid_row_index(new_cursor_row):
                    table.move_cursor(row=new_cursor_row, animate=False)
                # If the only row was removed, cursor moves implicitly to -1 (no row)
                # If multiple rows, and top row removed, cursor stays at 0 (new top row)
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
            # If table becomes empty, cursor is implicitly -1
        except Exception as e:
            log.error(f"Error moving cursor after ignore all: {e}")

    def action_show_log(self) -> None:
        """Action to show or hide the log screen."""
        is_log_screen_active = isinstance(self.screen, LogScreen)
        if is_log_screen_active:
            self.pop_screen()
            log.debug("Popped LogScreen.")
        else:
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
            sorted_files = sorted(list(self.monitor), key=lambda f: f.path)
            for info in sorted_files:
                log.debug(f"  {info.path}: {info!r}")
            log.debug("--- End Monitor State Dump ---")
            self.notify("Monitor state dumped to log (debug level).")
        except Exception as e:
            log.exception("Error during monitor state dump.")
            self.notify("Error dumping monitor state.", severity="error")
