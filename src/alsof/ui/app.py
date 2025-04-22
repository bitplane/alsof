"""Main Textual application class for alsof."""

import asyncio
import logging
from collections import deque
from typing import Callable, List, Union

from rich.text import Text
from textual.app import App, ComposeResult
from textual.binding import Binding
from textual.coordinate import Coordinate
from textual.reactive import reactive
from textual.widgets import DataTable, Footer, Static
from textual.widgets.data_table import CellKey, RowKey

from alsof.monitor import Monitor, FileInfo
from alsof.util.short_path import short_path

from .detail_screen import DetailScreen
from .log_screen import LogScreen

BackendFuncType = Callable[[Union[List[int], List[str]], Monitor], None]
BackendArgsType = Union[List[int], List[str]]
BackendWorkerFuncType = Callable[[BackendFuncType, Monitor, BackendArgsType], None]


log = logging.getLogger("alsof.app")


class FileApp(App[None]):
    """Textual file monitor application."""

    TITLE = "alsof - Another lsof"
    BINDINGS = [
        Binding("q,escape", "quit", "Quit", show=True),
        Binding("x", "ignore_all", "Ignore All", show=True),
        Binding("i,backspace,delete", "ignore_selected", "Ignore Selected", show=True),
        Binding("ctrl+l", "show_log", "Show Log / Close Log", show=True),
        Binding("ctrl+d", "dump_monitor", "Dump Monitor", show=False),
    ]
    CSS = """
    Screen { border: none; }
    DataTable { height: 1fr; border: none; }
    #status-bar { height: auto; dock: bottom; color: $text-muted; padding: 0 1; }

    LogScreen > Container {
        border: thick $accent; padding: 1; width: 80%; height: 80%; background: $surface;
    }
    DetailScreen > Container {
        border: thick $accent; padding: 1; width: 90%; height: 80%; background: $surface;
    }
    """

    last_monitor_version = reactive(-1)

    def __init__(
        self,
        monitor: Monitor,
        log_queue: deque,
        backend_func: BackendFuncType,
        backend_args: BackendArgsType,
        backend_worker_func: BackendWorkerFuncType,
    ):
        """Initialize the FileApp.

        Args:
            monitor (Monitor): The file monitor instance.
            log_queue (deque): The queue for log messages.
            backend_func (BackendFuncType): The backend function (attach/run) to execute.
            backend_args (BackendArgsType): The arguments for the backend function (pids/command).
            backend_worker_func (BackendWorkerFuncType): The actual function to run in the worker.
        """
        super().__init__()
        self.monitor = monitor
        self.log_queue = log_queue
        # Store backend info to start it later
        self._backend_func = backend_func
        self._backend_args = backend_args
        self._backend_worker_func = backend_worker_func
        self._update_interval = 1.0

    def compose(self) -> ComposeResult:
        """Create child widgets for the main application screen."""
        yield DataTable(id="file-table", cursor_type="row", zebra_stripes=True)
        yield Static("Status: Initializing...", id="status-bar")
        yield Footer()

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
            # Use asyncio.to_thread to run the sync function in the event loop's thread pool
            await asyncio.to_thread(worker_func, backend_func, monitor, backend_args)
            log.debug(f"Async wrapper task for {worker_func.__name__} completed.")
        except Exception:
            log.exception(f"Exception in background worker {worker_func.__name__}")
            # Optionally notify the user about the background error
            # self.notify("Background task failed", severity="error", timeout=5)

    def on_mount(self) -> None:
        """Called when the app screen is mounted."""
        log.info("FileApp mounting...")
        table = self.query_one(DataTable)
        table.add_column("?", key="emoji", width=3)
        table.add_column("Activity", key="activity", width=10)
        table.add_column("Path", key="path")
        self.update_table()
        table.focus()
        log.debug("DataTable focused on mount.")

        # Start Backend Worker using the async wrapper
        worker_name = f"backend_{self._backend_func.__module__}"
        log.info(
            f"Starting worker '{worker_name}' via run_worker with async wrapper..."
        )
        self.run_worker(
            self._run_backend_in_thread(
                self._backend_worker_func,
                self._backend_func,
                self.monitor,
                self._backend_args,
            ),
            name=worker_name,
            group="backend_workers",
            exclusive=True,
        )

        self.set_interval(self._update_interval, self.update_table)
        self.update_status("Monitoring started...")
        log.info("UI Mounted, update timer started, backend worker started.")

    def update_status(self, text: str):
        """Helper to update the status bar widget safely."""
        try:
            status_bar = self.query_one("#status-bar", Static)
            status_bar.update(text)
        except Exception:
            pass  # Ignore errors if status bar not found

    def _get_emoji_for_file(self, info: FileInfo) -> str:
        """Determines the appropriate emoji based on file status and activity."""
        if info.status == "deleted":
            return "❌"
        if info.status == "error" or info.last_error_enoent:
            return "❗"
        recent_types = list(info.recent_event_types)
        has_read = "READ" in recent_types
        has_write = "WRITE" in recent_types
        if has_read and has_write:
            return "↔️"
        if has_write:
            return "⬆️"
        if has_read:
            return "⬇️"
        if info.is_open:
            return "✅"
        if "OPEN" in recent_types:
            return "🚪"
        if "STAT" in recent_types:
            return "👀"
        if "RENAME" in recent_types:
            return "🔄"
        if "CLOSE" in recent_types:
            return "🚪"
        if info.status == "unknown" and info.event_history:
            return "❔"
        return " "

    def update_table(self) -> None:
        """Updates the DataTable with the latest file information."""
        if not self.monitor:
            return
        current_version = self.monitor.version
        if current_version == self.last_monitor_version:
            return

        log.info(
            f"Monitor version changed ({self.last_monitor_version} -> {current_version}), updating table."
        )
        self.last_monitor_version = current_version

        try:
            table = self.query_one(DataTable)
            status_bar = self.query_one("#status-bar", Static)
        except Exception:
            log.warning("Could not query table/status bar during update.")
            return

        other_cols_width = 0
        col_count = 0
        fixed_width_cols = {"emoji", "activity"}
        for key, col in table.columns.items():
            col_count += 1
            if key in fixed_width_cols:
                other_cols_width += col.width

        table_width = table.content_size.width
        padding = max(0, col_count + 1)
        available_width = max(10, table_width - other_cols_width - padding)

        all_files = list(self.monitor)
        active_files = [
            info for info in all_files if info.path not in self.monitor.ignored_paths
        ]
        active_files.sort(key=lambda info: info.last_activity_ts, reverse=True)
        log.debug(f"update_table: Processing {len(active_files)} active files.")

        selected_path_key = None
        coordinate: Coordinate | None = table.cursor_coordinate
        if table.is_valid_coordinate(coordinate):
            try:
                cell_key: CellKey | None = table.coordinate_to_cell_key(coordinate)
                selected_path_key = cell_key.row_key if cell_key else None
            except Exception as e:
                log.debug(f"Error getting cursor row key: {e}")
                selected_path_key = None

        table.clear()
        row_keys_added_this_update = set()

        for info in active_files:
            row_key_value = info.path  # This is the actual path string
            if row_key_value in row_keys_added_this_update:
                log.warning(
                    f"Skipping duplicate path in update_table loop: {row_key_value}"
                )
                continue
            row_keys_added_this_update.add(row_key_value)

            emoji = self._get_emoji_for_file(info)
            path_display = short_path(info.path, available_width)
            activity_str = (
                f"{info.bytes_read}r/{info.bytes_written}w"
                if (info.bytes_read or info.bytes_written)
                else (
                    info.status
                    if info.status not in ["unknown", "accessed", "closed", "active"]
                    else ""
                )
            )
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

            row_data = (
                Text(f" {emoji} ", style=style),
                Text(activity_str, style=style),
                Text(path_display, style=style),
            )
            try:
                # Use the actual path string as the key value for the row
                table.add_row(*row_data, key=row_key_value)
            except Exception as add_exc:
                log.exception(f"Error adding row for key {row_key_value}: {add_exc}")

        new_row_index = -1
        if selected_path_key is not None and selected_path_key in table.rows:
            try:
                new_row_index = table.get_row_index(selected_path_key)
            except Exception as e:
                log.debug(
                    f"Error getting new row index for key '{selected_path_key}': {e}"
                )
                new_row_index = -1

        if new_row_index != -1 and new_row_index < table.row_count:
            table.move_cursor(row=new_row_index, animate=False)
        elif table.row_count > 0 and (selected_path_key is None or new_row_index == -1):
            current_cursor_row, _ = table.cursor_coordinate
            if current_cursor_row != 0:
                table.move_cursor(row=0, animate=False)

        status_bar.update(
            f"Tracking {len(active_files)} files. Ignored: {len(self.monitor.ignored_paths)}. Monitor v{current_version}"
        )

    # --- Message Handler ---
    def on_data_table_row_selected(self, event: DataTable.RowSelected) -> None:
        """Called when the user presses Enter on a DataTable row."""
        log.debug(
            f"on_data_table_row_selected triggered. Event row_key obj: {event.row_key!r}"
        )
        if event.control.id != "file-table":
            log.debug(
                f"Ignoring RowSelected event from control id '{event.control.id}'"
            )
            return

        row_key_obj: RowKey | None = event.row_key
        if row_key_obj is None or row_key_obj.value is None:
            log.error(
                "DataTable.RowSelected message received but row_key or its value is None."
            )
            self.notify("Could not identify selected row key value.", severity="error")
            return

        # Get the actual path string from the RowKey's value attribute
        path = str(row_key_obj.value)
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

    # --- Actions ---
    def action_quit(self) -> None:
        """Action to quit the application."""
        self.exit()

    def action_ignore_selected(self) -> None:
        """Action to ignore the currently selected file path."""
        table = self.query_one(DataTable)
        coordinate = table.cursor_coordinate
        if not table.is_valid_coordinate(coordinate):
            self.notify("No row selected.", severity="warning")
            return
        try:
            cell_key: CellKey | None = table.coordinate_to_cell_key(coordinate)
            row_key_obj = cell_key.row_key if cell_key else None

            if row_key_obj is not None and row_key_obj.value is not None:
                # Use .value here too
                path_to_ignore = str(row_key_obj.value)
                log.info(f"Ignoring selected path: {path_to_ignore}")
                self.monitor.ignore(path_to_ignore)
                self.notify(f"Ignored: {short_path(path_to_ignore, 60)}", timeout=2)
            else:
                self.notify(
                    "Could not get key value for selected row.", severity="error"
                )
        except Exception as e:
            log.exception("Error ignoring selected.")
            self.notify(f"Error ignoring file: {e}", severity="error")

    def action_ignore_all(self) -> None:
        """Action to ignore all currently tracked files."""
        log.info("Ignoring all tracked files.")
        try:
            count_before = len(
                [fi for fi in self.monitor if fi.path not in self.monitor.ignored_paths]
            )
            self.monitor.ignore_all()
            self.notify(f"Ignoring {count_before} currently tracked files.", timeout=2)
        except Exception as e:
            log.exception("Error ignoring all.")
            self.notify(f"Error ignoring all files: {e}", severity="error")

    def action_show_log(self) -> None:
        """Action to show or hide the log screen."""
        if isinstance(self.screen, LogScreen):
            self.pop_screen()
            log.debug("Popped LogScreen via action_show_log.")
        elif self.is_screen_installed(LogScreen):
            self.pop_screen()
            log.debug("Popped current screen to reveal LogScreen.")
        else:
            log.info("Action: show_log triggered. Pushing LogScreen.")
            self.push_screen(LogScreen(self.log_queue))

    def action_dump_monitor(self) -> None:
        """Debug action to dump monitor state to log."""
        log.debug("--- Monitor State Dump ---")
        try:
            log.debug(f"Identifier: {self.monitor.identifier}")
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


# Removed the standalone main function
