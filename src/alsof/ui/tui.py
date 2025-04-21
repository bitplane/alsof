# Filename: tui.py
"""Main Textual application class and logic."""

import logging
from collections import deque

from rich.text import Text
from textual.app import App, ComposeResult
from textual.binding import Binding
from textual.containers import Container  # Import Container if needed, maybe not here
from textual.coordinate import Coordinate
from textual.reactive import reactive
from textual.widgets import DataTable, Footer, Static

# Import monitor types and utility functions
from alsof.monitor import FileInfo, Monitor
from alsof.screens.detail_screen import DetailScreen

# Import screen classes
from alsof.screens.log_screen import LogScreen
from alsof.utils import short_path  # Use the new short_path function

log = logging.getLogger(__name__)  # Use module-specific logger


class FileApp(App[None]):
    """Textual file monitor application."""

    TITLE = "alsof - Another lsof"
    BINDINGS = [
        Binding("q,escape", "quit", "Quit", show=True, priority=True),
        Binding("x", "ignore_all", "Ignore All", show=True),
        Binding("i,backspace,delete", "ignore_selected", "Ignore Selected", show=True),
        Binding("enter", "show_details", "Show Details", show=True),
        Binding("ctrl+l", "show_log", "Show Log / Close Log", show=True),
        Binding("ctrl+d", "dump_monitor", "Dump Monitor", show=False),  # Debug binding
    ]
    CSS = """
    Screen { border: none; }
    DataTable { height: 1fr; border: none; }
    #status-bar { height: auto; dock: bottom; color: $text-muted; padding: 0 1; }
    /* LogScreen styling */
    LogScreen > Container {
        border: thick $accent; padding: 1; width: 80%; height: 80%; background: $surface;
    }
    LogScreen #log-container { height: 1fr; }
    LogScreen #app-log { height: 1fr; }
    /* DetailScreen styling */
    DetailScreen > Container {
        border: thick $accent; padding: 1; width: 90%; height: 80%; background: $surface;
    }
    DetailScreen #detail-container { height: 1fr; }
    DetailScreen #event-log { height: 1fr; border: none; }
    """

    last_monitor_version = reactive(-1)

    def __init__(self, monitor: Monitor, log_queue: deque):
        super().__init__()
        self.monitor = monitor
        self.log_queue = log_queue
        self._update_interval = 1.0  # Update interval in seconds

    def compose(self) -> ComposeResult:
        """Create child widgets for the main application screen."""
        yield DataTable(id="file-table", cursor_type="row", zebra_stripes=True)
        yield Static("Status: Initializing...", id="status-bar")
        yield Footer()

    def on_mount(self) -> None:
        """Called when the app screen is mounted."""
        table = self.query_one(DataTable)
        table.add_column("?", key="emoji", width=3)
        table.add_column("Activity", key="activity", width=10)
        table.add_column("Path", key="path")  # Let path take remaining width
        self.update_table()
        self.set_interval(self._update_interval, self.update_table)
        self.update_status("Monitoring started...")
        log.info("UI Mounted, starting update timer.")

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
        return " "  # Default blank

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

        # --- Calculate Path Width ---
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
        # log.debug(f"Path width calculation: table={table_width}, other={other_cols_width}, padding={padding}, available={available_width}")

        # --- Get and Sort Data ---
        all_files = list(self.monitor)
        active_files = [
            info for info in all_files if info.path not in self.monitor.ignored_paths
        ]
        active_files.sort(key=lambda info: info.last_activity_ts, reverse=True)
        log.debug(f"update_table: Processing {len(active_files)} active files.")

        # --- Preserve Cursor ---
        selected_path_key = None
        coordinate: Coordinate | None = table.cursor_coordinate
        if table.is_valid_coordinate(coordinate):
            try:
                selected_path_key = table.get_row_key(coordinate.row)
                # if selected_path_key is not None: log.debug(f"Cursor key preserved: '{selected_path_key}'")
            except Exception as e:
                log.debug(f"Error getting cursor row key: {e}")
                selected_path_key = None
        # else: log.debug("Cursor coordinate invalid before clear.")

        # --- Repopulate Table ---
        table.clear()
        row_keys_added_this_update = set()

        for info in active_files:
            row_key = info.path
            if row_key in row_keys_added_this_update:
                log.warning(f"Skipping duplicate path in update_table loop: {row_key}")
                continue
            row_keys_added_this_update.add(row_key)

            emoji = self._get_emoji_for_file(info)
            # Use the new short_path function from utils
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
                table.add_row(*row_data, key=row_key)
            except Exception as add_exc:
                log.exception(f"Error adding row for key {row_key}: {add_exc}")

        # --- Restore Cursor ---
        new_row_index = -1
        if selected_path_key is not None and selected_path_key in table.rows:
            try:
                new_row_index = table.get_row_index(selected_path_key)
                # log.debug(f"Found key '{selected_path_key}' at new index {new_row_index}")
            except Exception as e:
                log.debug(
                    f"Error getting new row index for key '{selected_path_key}': {e}"
                )
                new_row_index = -1
        # elif selected_path_key is not None: log.debug(f"Saved key '{selected_path_key}' no longer in table.")

        if new_row_index != -1 and new_row_index < table.row_count:
            # log.debug(f"Moving cursor to row index {new_row_index}")
            table.move_cursor(row=new_row_index, animate=False)
        elif table.row_count > 0 and (selected_path_key is None or new_row_index == -1):
            # log.debug("Moving cursor to row 0 (fallback)")
            current_cursor_row, _ = table.cursor_coordinate
            if current_cursor_row != 0:
                table.move_cursor(row=0, animate=False)
        # elif table.row_count == 0: log.debug("Table empty, not moving cursor.")

        # --- Update Status Bar ---
        status_bar.update(
            f"Tracking {len(active_files)} files. "
            f"Ignored: {len(self.monitor.ignored_paths)}. "
            f"Monitor v{current_version}"
        )

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
            row_key = table.get_row_key(coordinate.row)
            if row_key is not None:
                path_to_ignore = str(row_key)
                log.info(f"Ignoring selected path: {path_to_ignore}")
                self.monitor.ignore(path_to_ignore)
                self.notify(
                    f"Ignored: {short_path(path_to_ignore, 60)}", timeout=2
                )  # Show shortened path
            else:
                self.notify("Could not get key for selected row.", severity="error")
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

    def action_show_details(self) -> None:
        """Action to show the detail screen for the selected file."""
        table = self.query_one(DataTable)
        coordinate = table.cursor_coordinate
        if not table.is_valid_coordinate(coordinate):
            self.notify("No row selected.", severity="warning")
            return
        path = None
        try:
            row_key = table.get_row_key(coordinate.row)
            if row_key is not None:
                path = str(row_key)
                log.debug(f"Showing details for: {path}")
                file_info = self.monitor.files.get(path)
                if file_info:
                    self.push_screen(DetailScreen(file_info))
                else:
                    log.warning(f"File '{path}' disappeared before showing details.")
                    self.notify(
                        "File state not found (may have been removed).",
                        severity="warning",
                        timeout=3,
                    )
            else:
                self.notify("Could not get key for selected row.", severity="error")
        except Exception as e:
            log.exception("Error showing details.")
            self.notify(f"Error showing details: {e}", severity="error")

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
