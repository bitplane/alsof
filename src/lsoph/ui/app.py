# Filename: src/lsoph/ui/app.py
"""Main Textual application class for lsoph."""

import asyncio
import logging
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
from lsoph.monitor import FileInfo, Monitor
from lsoph.util.short_path import short_path

from .detail_screen import DetailScreen

# Import the FileDataTable widget
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

    # REMEMBER: User renamed CSS file
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
            # log.warning("Backend worker already running.") # Reduce noise
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
            # log.debug(f"Monitor version changed ({old_version} -> {new_version}), calling table update.") # Reduced noise
            all_files = list(self.monitor)
            active_files = [
                info
                for info in all_files
                if info.path not in self.monitor.ignored_paths
            ]
            active_files.sort(key=lambda info: info.last_activity_ts, reverse=True)
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
        # Check if the event came from the main file table
        if event.control is self._file_table:
            # log.debug(f"DataTable Row Selected (Enter) from main table: {event.row_key}") # Reduced noise
            # Call the internal method directly, bypassing focus check
            self._show_detail_for_selected_row()
        # else: log.debug("Ignoring row selection event from other source.")

    def on_data_table_row_activated(self, event: "DataTable.RowActivated") -> None:
        """Handle row activation (Double Click) - show details."""
        # Check if the event came from the main file table
        if event.control is self._file_table:
            # log.debug(f"DataTable Row Activated (Double Click) from main table: {event.row_key}") # Reduced noise
            # Call the internal method directly, bypassing focus check
            self._show_detail_for_selected_row()
        # else: log.debug("Ignoring row activation event from other source.")

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
        # Check if the table itself or one of its descendants has focus
        # Also check if the main app screen is the current one
        if self.screen is not self:
            return False  # Keep screen check here
        if not self._file_table.has_focus and not self.focused_descendant_is_widget(
            self._file_table
        ):
            return False
        return True

    def action_ignore_selected(self) -> None:
        """Action to ignore the currently selected file path."""
        if not self._file_table:
            return  # Ensure table exists

        path_to_ignore = self._file_table.selected_path
        if not path_to_ignore:
            self.notify("No row selected.", severity="warning", timeout=2)
            return

        log.info(f"Ignoring selected path: {path_to_ignore}")
        self.monitor.ignore(path_to_ignore)
        # --- Force Update ---
        self.last_monitor_version = self.monitor.version
        # --- End Force Update ---
        self.notify(f"Ignored: {short_path(path_to_ignore, 60)}", timeout=2)

    def action_ignore_all(self) -> None:
        """Action to ignore all currently tracked files."""
        if not self._file_table:
            return  # Ensure table exists

        log.info("Ignoring all tracked files.")
        count_before = len(
            [fi for fi in self.monitor if fi.path not in self.monitor.ignored_paths]
        )
        if count_before == 0:
            self.notify("No active files to ignore.", timeout=2)
            return
        self.monitor.ignore_all()
        # --- Force Update ---
        self.last_monitor_version = self.monitor.version
        # --- End Force Update ---
        self.notify(f"Ignoring {count_before} currently tracked files.", timeout=2)

    def action_show_log(self) -> None:
        """Action to show or hide the log screen."""
        # This action is global, no screen check needed here
        is_log_screen_active = isinstance(self.screen, LogScreen)
        if is_log_screen_active:
            self.pop_screen()
        else:
            self.push_screen(LogScreen(self.log_queue))

    # This action is bound to 'i' and requires focus check
    def action_show_detail(self) -> None:
        """Shows the detail screen for the selected row (requires focus check)."""
        # Keep focus check for the 'i' key binding
        if not self._ensure_table_focused():
            return
        self._show_detail_for_selected_row()

    # Internal method without focus check, called by event handlers and action_show_detail
    def _show_detail_for_selected_row(self) -> None:
        """Core logic to show detail screen for the current selection."""
        if not self._file_table:
            return  # Should not happen if called correctly

        path = self._file_table.selected_path
        if not path:
            # log.debug("_show_detail_for_selected_row called but no path selected.") # Reduced noise
            return

        log.debug(f"Showing details for selected path: {path}")
        try:
            file_info = self.monitor.files.get(path)
            if file_info:
                self.push_screen(DetailScreen(file_info))
            else:
                log.warning(f"File '{path}' not found in monitor state.")
                self.notify("File state not found.", severity="warning", timeout=3)
        except Exception as e:
            log.exception(f"Error pushing DetailScreen for path: {path}")
            self.notify(f"Error showing details: {e}", severity="error")

    def action_scroll_home(self) -> None:
        """Scrolls the file table to the top."""
        if self._file_table:
            # log.debug("Action: scroll_home") # Reduced noise
            self._file_table.scroll_home(animate=False)
            if self._file_table.row_count > 0:
                self._file_table.move_cursor(row=0, animate=False)

    def action_scroll_end(self) -> None:
        """Scrolls the file table to the bottom."""
        if self._file_table:
            # log.debug("Action: scroll_end") # Reduced noise
            self._file_table.scroll_end(animate=False)
            if self._file_table.row_count > 0:
                self._file_table.move_cursor(
                    row=self._file_table.row_count - 1, animate=False
                )

    def action_dump_monitor(self) -> None:
        """Debug action to dump monitor state to log."""
        log.debug("--- Monitor State Dump ---")
        try:
            log.debug(f"Identifier: {self.monitor.identifier}")
            log.debug(f"Backend PID: {self.monitor.backend_pid}")
            log.debug(
                f"Ignored Paths ({len(self.monitor.ignored_paths)}): {self.monitor.ignored_paths!r}"
            )
            log.debug(
                f"PID->FD Map ({len(self.monitor.pid_fd_map)} pids): {self.monitor.pid_fd_map!r}"
            )
            log.debug(f"Files Dict ({len(self.monitor.files)} items):")
            # Use monitor's __iter__ for thread safety
            sorted_files = sorted(list(self.monitor), key=lambda f: f.path)
            for info in sorted_files:
                log.debug(
                    f"  {info.path}: Status={info.status}, Open={info.is_open}, R/W={info.bytes_read}/{info.bytes_written}, Last={info.last_event_type}, PIDs={list(info.open_by_pids.keys())}"
                )
            log.debug("--- End Monitor State Dump ---")
            self.notify("Monitor state dumped to log (debug level).")
        except Exception as e:
            log.exception("Error during monitor state dump.")
            self.notify("Error dumping monitor state.", severity="error")
