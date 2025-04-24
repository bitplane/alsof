# Filename: src/lsoph/ui/app.py
"""Main Textual application class for lsoph. Handles bytes paths from Monitor."""

import asyncio
import logging
import os  # For os.fsdecode
import time
from collections import deque
from collections.abc import Callable, Coroutine
from typing import Any, Optional

from rich.text import Text
from textual.app import App, ComposeResult
from textual.binding import Binding
from textual.containers import Vertical
from textual.dom import NoMatches
from textual.reactive import reactive

# Import DataTable event types
from textual.widgets import DataTable, Footer, Header, Static
from textual.worker import Worker, WorkerState

from lsoph.backend.base import Backend
from lsoph.monitor import FileInfo, Monitor  # FileInfo path is bytes

# short_path accepts bytes, returns str
from lsoph.util.short_path import short_path

from .detail_screen import DetailScreen  # DetailScreen needs to handle bytes path

# Import the FileDataTable widget (now handles bytes paths internally)
from .file_data_table import FileDataTable
from .log_screen import LogScreen

# Type alias for the backend coroutine (attach or run_command)
BackendCoroutine = Coroutine[Any, Any, None]

log = logging.getLogger("lsoph.ui.app")


class LsophApp(App[None]):
    """Textual file monitor application for lsoph."""

    TITLE = "lsoph - List Open Files Helper"
    SUB_TITLE = "Monitoring file activity..."

    BINDINGS = [
        # --- Always Visible Bindings ---
        Binding("q,escape", "quit", "Quit", show=True),
        Binding("l,ctrl+l", "show_log", "Show/Hide Log", show=True),
        # --- Contextual Bindings (Hidden by default, work on main screen) ---
        # Ignore / Delete
        Binding("d,backspace,delete", "ignore_selected", "Ignore Sel.", show=False),
        # Ignore All
        Binding(
            "x,shift+delete,shift+backspace", "ignore_all", "Ignore All", show=False
        ),
        # Info / Details (Enter is handled by on_data_table_row_selected/activated)
        Binding("i", "show_detail", "Show Detail", show=False),
        # Navigation
        Binding("g,home", "scroll_home", "Scroll Top", show=False),
        Binding(
            "G,end", "scroll_end", "Scroll End", show=False
        ),  # Use Shift+G for end like Vim
        # --- Debug Bindings (Always hidden) ---
        Binding("ctrl+d", "dump_monitor", "Dump Monitor", show=False),
    ]

    CSS_PATH = "style.css"

    # Reactive variables to trigger updates
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
        self._update_interval = 0.5  # Interval for checking monitor version
        self._backend_worker: Worker | None = None
        self._backend_stop_signalled = False
        self._backend_stopped_notified = False
        # Reference to the FileDataTable widget instance
        self._file_table: Optional[FileDataTable] = None

    def compose(self) -> ComposeResult:
        """Create child widgets for the main application screen."""
        yield Header()
        # Use the custom FileDataTable widget
        yield FileDataTable(id="file-table")
        yield Static(self.status_text, id="status-bar")
        yield Footer()

    # --- Worker Management ---
    # (start_backend_worker and cancel_backend_worker remain the same)
    def start_backend_worker(self):
        """Starts the background worker to run the backend's async method."""
        if self._backend_worker and self._backend_worker.state == WorkerState.RUNNING:
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
        if not self._backend_worker:
            log.error(f"Failed to create worker {worker_name}")
            self.notify("Error starting backend worker!", severity="error", timeout=5)
            return
        log.info(
            f"Worker {self._backend_worker.name} created with state {self._backend_worker.state}"
        )

    async def cancel_backend_worker(self):
        """Signals the backend instance to stop and cancels the Textual worker."""
        if not self._backend_stop_signalled:
            log.debug("Calling backend_instance.stop()...")
            await self.backend_instance.stop()
            self._backend_stop_signalled = True
            log.debug("Backend_instance.stop() returned.")
        worker = self._backend_worker
        if worker and worker.state == WorkerState.RUNNING:
            log.info(f"Requesting cancellation for Textual worker {worker.name}...")
            try:
                await worker.cancel()
                log.info(f"Textual worker {worker.name} cancellation requested.")
            except Exception as e:
                log.error(f"Error cancelling Textual worker {worker.name}: {e}")
        self._backend_worker = None

    # --- App Lifecycle ---

    def on_mount(self) -> None:
        """Called when the app screen is mounted."""
        log.info("LsophApp mounting...")
        try:
            self._file_table = self.query_one(FileDataTable)
            self._file_table.focus()
            log.debug("FileDataTable focused on mount.")
        except Exception as e:
            log.exception(f"Error getting FileDataTable on mount: {e}")
        self.start_backend_worker()
        self.set_interval(self._update_interval, self.check_monitor_version)
        log.info("UI Mounted, update timer started, backend worker started.")

    async def on_unmount(self) -> None:
        """Called when the app is unmounted (e.g., on quit)."""
        log.info("LsophApp unmounting. Cancelling backend worker...")
        await self.cancel_backend_worker()

    # --- Reactive Watchers ---

    def watch_last_monitor_version(self, old_version: int, new_version: int) -> None:
        """Triggers table update when monitor version changes."""
        if not self._file_table:
            return
        if new_version > old_version:
            # Monitor.__iter__ yields FileInfo with bytes paths
            all_files: list[FileInfo] = list(self.monitor)
            active_files = [
                info
                for info in all_files
                # Compare bytes path with ignored bytes paths
                if info.path not in self.monitor.ignored_paths
            ]
            active_files.sort(key=lambda info: info.last_activity_ts, reverse=True)
            # FileDataTable.update_data accepts FileInfo list (with bytes paths)
            self._file_table.update_data(active_files)
            self.update_status(
                f"Tracking {len(active_files)} files. Ignored: {len(self.monitor.ignored_paths)}. Monitor v{new_version}"
            )

    def watch_status_text(self, old_text: str, new_text: str) -> None:
        """Updates the status bar widget when status_text changes."""
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
            status_msg = f"Error: Monitoring backend stopped unexpectedly!"
            log_msg = f"Backend worker {worker.name} stopped unexpectedly (state: {worker.state})."
            log.error(log_msg + " Check previous logs for potential errors.")
            self.update_status(status_msg)
            self.notify(
                f"{status_msg} Check logs for details.",
                title="Backend Stopped Unexpectedly",
                severity="error",
                timeout=10,
            )
            self._backend_worker = None
        current_version = self.monitor.version
        if current_version != self.last_monitor_version:
            self.last_monitor_version = current_version

    def update_status(self, text: str):
        """Helper method to update the reactive status_text variable."""
        self.status_text = text

    # --- Event Handlers ---

    def on_data_table_row_selected(self, event: DataTable.RowSelected) -> None:
        """Handle row selection (Enter key) - show details."""
        if event.control is self._file_table:
            self._show_detail_for_selected_row()

    def on_data_table_row_activated(self, event: "DataTable.RowActivated") -> None:
        """Handle row activation (Double Click) - show details."""
        if event.control is self._file_table:
            self._show_detail_for_selected_row()

    # --- Actions ---

    async def action_quit(self) -> None:
        """Action to quit the application."""
        log.info("Quit action triggered. Signalling backend worker and exiting.")
        await self.cancel_backend_worker()
        self.exit()

    def _ensure_table_focused(self) -> bool:
        """Checks if the file table exists and is focused."""
        if not self._file_table:
            return False
        if self.screen is not self:
            return False
        if not self._file_table.has_focus and not self.focused_descendant_is_widget(
            self._file_table
        ):
            return False
        return True

    def action_ignore_selected(self) -> None:
        """Action to ignore the currently selected file path (bytes)."""
        if not self._file_table:
            return

        # FileDataTable.selected_path returns bytes
        path_to_ignore_bytes = self._file_table.selected_path
        if not path_to_ignore_bytes:
            self.notify("No row selected.", severity="warning", timeout=2)
            return

        # Decode for logging and notification
        # --- FIX: Use os.fsdecode with one argument ---
        path_to_ignore_str = os.fsdecode(path_to_ignore_bytes)
        # ---------------------------------------------
        log.info(f"Ignoring selected path: {path_to_ignore_str!r}")
        # Call monitor.ignore with bytes path
        self.monitor.ignore(path_to_ignore_bytes)
        # --- Force Update ---
        self.last_monitor_version = self.monitor.version
        # --- End Force Update ---
        self.notify(
            f"Ignored: {short_path(path_to_ignore_bytes, 60)}", timeout=2
        )  # short_path accepts bytes

    def action_ignore_all(self) -> None:
        """Action to ignore all currently tracked files."""
        if not self._file_table:
            return

        log.info("Ignoring all tracked files.")
        # Get current active files (bytes paths) before ignoring
        count_before = len(
            [fi for fi in self.monitor if fi.path not in self.monitor.ignored_paths]
        )
        if count_before == 0:
            self.notify("No active files to ignore.", timeout=2)
            return
        # monitor.ignore_all works internally with bytes paths
        self.monitor.ignore_all()
        # --- Force Update ---
        self.last_monitor_version = self.monitor.version
        # --- End Force Update ---
        self.notify(f"Ignoring {count_before} currently tracked files.", timeout=2)

    def action_show_log(self) -> None:
        """Action to show or hide the log screen."""
        is_log_screen_active = isinstance(self.screen, LogScreen)
        if is_log_screen_active:
            self.pop_screen()
        else:
            self.push_screen(LogScreen(self.log_queue))

    def action_show_detail(self) -> None:
        """Shows the detail screen for the selected row (requires focus check)."""
        if not self._ensure_table_focused():
            return
        self._show_detail_for_selected_row()

    def _show_detail_for_selected_row(self) -> None:
        """Core logic to show detail screen for the current selection (bytes path)."""
        if not self._file_table:
            return

        # FileDataTable.selected_path returns bytes
        path_bytes = self._file_table.selected_path
        if not path_bytes:
            return

        # Decode for logging
        # --- FIX: Use os.fsdecode with one argument ---
        path_str = os.fsdecode(path_bytes)
        # ---------------------------------------------
        log.debug(f"Showing details for selected path: {path_str!r}")
        try:
            # Look up using bytes path key
            file_info = self.monitor.files.get(path_bytes)
            if file_info:
                # Pass FileInfo (with bytes path) to DetailScreen
                self.push_screen(DetailScreen(file_info))
            else:
                log.warning(f"File '{path_str!r}' not found in monitor state.")
                self.notify("File state not found.", severity="warning", timeout=3)
        except Exception as e:
            log.exception(f"Error pushing DetailScreen for path: {path_str!r}")
            self.notify(f"Error showing details: {e}", severity="error")

    def action_scroll_home(self) -> None:
        """Scrolls the file table to the top."""
        if self._file_table:
            self._file_table.scroll_home(animate=False)
            if self._file_table.row_count > 0:
                try:
                    self._file_table.move_cursor(row=0, animate=False)
                except Exception as e:
                    log.warning(f"Error moving cursor to top: {e}")

    def action_scroll_end(self) -> None:
        """Scrolls the file table to the bottom."""
        if self._file_table:
            self._file_table.scroll_end(animate=False)
            if self._file_table.row_count > 0:
                try:
                    self._file_table.move_cursor(
                        row=self._file_table.row_count - 1, animate=False
                    )
                except Exception as e:
                    log.warning(f"Error moving cursor to bottom: {e}")

    def action_dump_monitor(self) -> None:
        """Debug action to dump monitor state to log (decodes paths)."""
        log.debug("--- Monitor State Dump ---")
        try:
            log.debug(f"Identifier: {self.monitor.identifier}")
            log.debug(f"Backend PID: {self.monitor.backend_pid}")
            # Decode ignored paths for logging
            # --- FIX: Use os.fsdecode with one argument ---
            ignored_paths_str = {os.fsdecode(p) for p in self.monitor.ignored_paths}
            # ---------------------------------------------
            log.debug(
                f"Ignored Paths ({len(self.monitor.ignored_paths)}): {ignored_paths_str!r}"
            )
            # Decode paths in pid_fd_map for logging
            # --- FIX: Use os.fsdecode with one argument ---
            pid_fd_map_str = {
                pid: {fd: os.fsdecode(p) for fd, p in fds.items()}
                for pid, fds in self.monitor.pid_fd_map.items()
            }
            # ---------------------------------------------
            log.debug(
                f"PID->FD Map ({len(self.monitor.pid_fd_map)} pids): {pid_fd_map_str!r}"
            )
            log.debug(f"Files Dict ({len(self.monitor.files)} items):")
            # Use monitor's __iter__ for thread safety
            # Decode path for logging
            sorted_files = sorted(
                list(self.monitor), key=lambda f: f.path
            )  # Sort by bytes path
            for info in sorted_files:
                # --- FIX: Use os.fsdecode with one argument ---
                path_str = os.fsdecode(info.path)
                # ---------------------------------------------
                log.debug(
                    f"  {path_str!r}: Status={info.status}, Open={info.is_open}, R/W={info.bytes_read}/{info.bytes_written}, Last={info.last_event_type}, PIDs={list(info.open_by_pids.keys())}"
                )
            log.debug("--- End Monitor State Dump ---")
            self.notify("Monitor state dumped to log (debug level).")
        except Exception as e:
            log.exception("Error during monitor state dump.")
            self.notify("Error dumping monitor state.", severity="error")
