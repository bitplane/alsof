# Filename: app.py

import datetime
import logging
from collections import deque

from rich.text import Text
from textual.app import App, ComposeResult
from textual.binding import Binding
from textual.containers import Container, VerticalScroll
from textual.reactive import reactive
from textual.screen import ModalScreen
from textual.widgets import DataTable, Footer, Label, Log, Static

from alsof.monitor import FileInfo, Monitor

log = logging.getLogger("alsof.app")  # Use package-aware logger name


def truncate_middle(text: str, max_length: int) -> str:
    """Truncates text in the middle, preserving start and end."""
    if len(text) <= max_length:
        return text
    if max_length < 5:
        return text[:max_length]
    ellipsis = "..."
    keep_len = max_length - len(ellipsis)
    end_len = min(len(text) // 2 + 1, keep_len * 2 // 3, len(text) - 1)
    start_len = keep_len - end_len
    if start_len < 0:
        start_len = 0
        end_len = keep_len
    start_len = min(start_len, len(text))
    end_len = min(end_len, len(text))
    if start_len + end_len > len(text):
        start_len = max(0, keep_len // 2)
        end_len = keep_len - start_len
    start_len = max(0, start_len)
    end_len = max(0, end_len)
    return f"{text[:start_len]}{ellipsis}{text[len(text)-end_len:]}"


class LogScreen(ModalScreen[None]):
    """A modal screen to display application logs."""

    BINDINGS = [
        Binding("escape,q", "app.pop_screen", "Close Logs", show=True),
        Binding("c", "clear_log", "Clear", show=True),
    ]

    def __init__(self, log_queue: deque):
        self.log_queue = log_queue
        self._timer = None
        super().__init__()

    def compose(self) -> ComposeResult:
        with VerticalScroll(id="log-container"):
            yield Log(id="app-log", max_lines=2000, auto_scroll=True)

    def on_mount(self) -> None:
        log_widget = self.query_one(Log)
        log_widget.markup = False  # Display logs as plain text
        log.debug(
            f"LogScreen mounted. Processing {len(self.log_queue)} existing log messages."
        )
        existing_logs = list(self.log_queue)
        if existing_logs:
            log_widget.write_lines(existing_logs)
        self._timer = self.set_interval(1 / 10, self._check_log_queue)

    def on_unmount(self) -> None:
        if self._timer:
            self._timer.stop()
            log.debug("LogScreen unmounted. Stopped log queue timer.")

    def _check_log_queue(self) -> None:
        log_widget = self.query_one(Log)
        count = 0
        while self.log_queue:
            try:
                record = self.log_queue.popleft()
                log_widget.write_line(record)
                count += 1
            except IndexError:
                break
        # if count > 0: log.debug(f"Processed {count} new log messages from queue.")

    def action_clear_log(self) -> None:
        log_widget = self.query_one(Log)
        log_widget.clear()
        self.notify("Logs cleared.", timeout=1)


# --- Detail Screen ---


class DetailScreen(ModalScreen[None]):
    """Screen to display event history for a specific file."""

    BINDINGS = [Binding("escape,q", "app.pop_screen", "Close", show=True)]

    def __init__(self, file_info: FileInfo):
        self.file_info = file_info
        super().__init__()

    def compose(self) -> ComposeResult:
        yield Container(
            Label(f"Event History for: {self.file_info.path}"),
            Log(
                id="event-log", max_lines=1000, markup=True
            ),  # Keep markup for this one
            id="detail-container",
        )

    def on_mount(self) -> None:
        log_widget = self.query_one(Log)
        history = self.file_info.event_history
        log.debug(f"DetailScreen on_mount: History length = {len(history)}")
        log.debug(f"DetailScreen on_mount: History content = {history}")
        if not history:
            log_widget.write_line("No event history recorded.")
            return
        log_widget.write_line("Timestamp        | Type     | Success | Details")
        log_widget.write_line(
            "-----------------|----------|---------|--------------------"
        )
        for event in history:
            ts_raw = event.get("ts", 0)
            try:
                ts = datetime.datetime.fromtimestamp(ts_raw).strftime("%H:%M:%S.%f")[
                    :-3
                ]
            except (TypeError, ValueError):
                ts = str(ts_raw)
            etype = str(event.get("type", "?")).ljust(8)
            success = "[green]OK[/]" if event.get("success", False) else "[red]FAIL[/]"
            visible_len = 2 if event.get("success", False) else 4
            padding = " " * (7 - visible_len)
            success_padded = f"{success}{padding}"
            details = str(event.get("details", {}))
            details_display = details[:100] + "..." if len(details) > 100 else details
            log_widget.write_line(
                f"{ts} | {etype} | {success_padded} | {details_display}"
            )


# --- Main Application ---


class FileApp(App[None]):
    """Textual file monitor application."""

    TITLE = None
    BINDINGS = [
        Binding("q,escape", "quit", "Quit", show=True, priority=True),
        Binding("x", "ignore_all", "Ignore All", show=True),
        Binding("i,backspace,delete", "ignore_selected", "Ignore Selected", show=True),
        Binding("enter", "show_details", "Show Details", show=True),
        Binding("ctrl+l", "show_log", "Show Log", show=True),
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
    LogScreen #log-container { } LogScreen #app-log { }
    """

    last_monitor_version = reactive(-1)

    def __init__(self, monitor: Monitor, log_queue: deque):
        super().__init__()
        self.monitor = monitor
        self.log_queue = log_queue
        self._update_interval = 1.0

    def compose(self) -> ComposeResult:
        # yield Header() # Header removed
        yield DataTable(id="file-table", cursor_type="row", zebra_stripes=True)
        yield Static("Status: Initializing...", id="status-bar")
        yield Footer()

    def on_mount(self) -> None:
        table = self.query_one(DataTable)
        table.add_column("?", key="emoji", width=3)
        table.add_column("Activity", key="activity", width=10)
        table.add_column("Path", key="path")
        self.update_table()
        self.set_interval(self._update_interval, self.update_table)
        self.update_status("Monitoring started...")
        log.info("UI Mounted, starting update timer.")

    def update_status(self, text: str):
        try:
            status_bar = self.query_one("#status-bar", Static)
            status_bar.update(text)
        except Exception:
            log.exception("Error updating status bar")

    def _get_emoji_for_file(self, info: FileInfo) -> str:
        if info.status == "deleted":
            return "❌"
        if info.status == "error" or info.last_error_enoent:
            return "❗"
        recent_types = [t for t in info.recent_event_types]
        if not recent_types:
            return "❔" if info.status == "unknown" else " "
        has_read = "READ" in recent_types
        has_write = "WRITE" in recent_types
        if has_read and has_write:
            return "↔️"
        if has_write:
            return "⬆️"
        if has_read:
            return "⬇️"
        if "OPEN" in recent_types:
            return "✅"
        if "STAT" in recent_types:
            return "👀"
        if "RENAME" in recent_types:
            return "🔄"
        if "CLOSE" in recent_types:
            return "🚪"
        return "❔"

    def update_table(self) -> None:
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
            log.warning("Could not query table/status bar.")
            return

        other_cols_width = 0
        col_count = 0
        for key, col in table.columns.items():
            col_count += 1
            if key != "path":
                other_cols_width += col.content_width
        table_width = table.size.width
        padding = max(0, col_count - 1) + 2
        available_width = max(10, table_width - other_cols_width - padding)

        all_files = list(self.monitor)
        # --- DEBUG LOG ---
        log.debug(f"update_table: len(all_files) = {len(all_files)}")
        # --- END DEBUG ---
        active_files = [
            info for info in all_files if info.path not in self.monitor.ignored_paths
        ]
        # --- DEBUG LOG ---
        log.debug(f"update_table: len(active_files) = {len(active_files)}")
        # --- END DEBUG ---
        active_files.sort(key=lambda info: info.last_activity_ts, reverse=True)

        selected_path_key = None
        coordinate = table.cursor_coordinate
        if table.is_valid_coordinate(coordinate):
            try:
                cell_key = table.coordinate_to_cell_key(coordinate)
                selected_path_key = cell_key.row_key
                log.debug(
                    f"Cursor was on row {coordinate.row}, key '{selected_path_key}'"
                )
            except Exception as e:
                log.exception(f"Error getting cursor row key: {e}")
                selected_path_key = None
        else:
            log.debug("Cursor coordinate invalid or table empty.")

        table.clear()
        row_keys_added = set()
        for info in active_files:
            if info.path in row_keys_added:
                continue
            row_key = info.path
            row_keys_added.add(row_key)
            # --- DEBUG LOG ---
            log.debug(f"update_table: Adding row for key='{row_key}'")
            # --- END DEBUG ---
            emoji = self._get_emoji_for_file(info)
            path_display = truncate_middle(info.path, available_width)
            activity_str = (
                f"{info.bytes_read}r/{info.bytes_written}w"
                if (info.bytes_read or info.bytes_written)
                else info.status
            )
            style = ""
            if info.status == "deleted":
                style = "strike"
            elif info.last_error_enoent:
                style = "red"
            elif info.status == "error":
                style = "red"
            elif info.is_open:
                style = "bold"
            elif info.last_event_type == "STAT":
                style = "yellow"
            table.add_row(
                Text(f" {emoji} ", style=style),
                Text(activity_str, style=style),
                Text(path_display, style=style),
                key=row_key,
            )

        new_row_index = -1
        if selected_path_key is not None and selected_path_key.value in table.rows:
            try:
                new_row_index = table.get_row_index(selected_path_key.value)
                log.debug(
                    f"Found key '{selected_path_key.value}' at new index {new_row_index}"
                )
            except Exception as e:
                log.exception(
                    f"Error getting new row index for key '{selected_path_key.value}': {e}"
                )
                new_row_index = -1
        elif selected_path_key is not None:
            log.debug(
                f"Saved key '{selected_path_key.value}' no longer exists in table."
            )

        if new_row_index != -1:
            log.debug(f"Moving cursor to row index {new_row_index}")
            table.move_cursor(row=new_row_index, animate=False)
        elif table.row_count > 0:
            log.debug("Moving cursor to row 0 (fallback)")
            table.move_cursor(row=0, animate=False)
        else:
            log.debug("Table empty, not moving cursor.")

        status_bar.update(
            f"Tracking {len(active_files)} files. "
            f"Ignored: {len(self.monitor.ignored_paths)}. "
            f"Version: {current_version}"
        )

    def action_quit(self) -> None:
        self.exit()

    def action_ignore_selected(self) -> None:
        table = self.query_one(DataTable)
        coordinate = table.cursor_coordinate
        if not table.is_valid_coordinate(coordinate):
            self.notify("No row selected.", severity="warning")
            return
        try:
            cell_key = table.coordinate_to_cell_key(coordinate)
            if cell_key and cell_key.row_key is not None:
                path_to_ignore = str(cell_key.row_key.value)
                log.info(f"Ignoring selected path: {path_to_ignore}")
                self.monitor.ignore(path_to_ignore)
                self.update_table()
                self.notify(f"Ignored: {path_to_ignore}", timeout=2)
            else:
                self.notify("Could not get key for row.", severity="error")
        except Exception as e:
            log.exception("Error ignoring selected.")
            self.notify(f"Error: {e}", severity="error")

    def action_ignore_all(self) -> None:
        log.info("Ignoring all tracked files.")
        try:
            count_before = len(
                [fi for fi in self.monitor if fi.path not in self.monitor.ignored_paths]
            )
            self.monitor.ignore_all()
            count_after = len(
                [fi for fi in self.monitor if fi.path not in self.monitor.ignored_paths]
            )
            self.update_table()
            self.notify(f"Ignored {count_before - count_after} files.", timeout=2)
        except Exception as e:
            log.exception("Error ignoring all.")
            self.notify(f"Error: {e}", severity="error")

    def action_show_details(self) -> None:
        table = self.query_one(DataTable)
        coordinate = table.cursor_coordinate
        if not table.is_valid_coordinate(coordinate):
            self.notify("No row selected.", severity="warning")
            return
        path = None
        try:
            cell_key = table.coordinate_to_cell_key(coordinate)
            if cell_key and cell_key.row_key is not None:
                path = str(cell_key.row_key.value)
                log.debug(f"Showing details for: {path}")
                file_info = self.monitor[path]
                self.push_screen(DetailScreen(file_info))
            else:
                self.notify("Could not get key for row.", severity="error")
        except KeyError:
            path_str = f"'{path}'" if path else "(unknown key)"
            log.warning(f"File {path_str} not found in monitor state.")
            self.notify("File state not found.", severity="warning")
        except Exception as e:
            log.exception("Error showing details.")
            self.notify(f"Error: {e}", severity="error")

    def action_show_log(self) -> None:
        """Pushes the LogScreen onto the view."""
        log.info("Action: show_log triggered.")
        self.push_screen(LogScreen(self.log_queue))

    # --- DEBUG ACTION ---
    def action_dump_monitor(self) -> None:
        """Debug action to dump monitor state to log."""
        log.debug("--- Monitor State Dump ---")
        log.debug(f"Identifier: {self.monitor.identifier}")
        log.debug(f"Ignored Paths: {self.monitor.ignored_paths!r}")
        log.debug(f"PID->FD Map: {self.monitor.pid_fd_map!r}")
        log.debug(f"Files Dict ({len(self.monitor.files)} items):")
        for path, info in self.monitor.files.items():
            log.debug(f"  {path}: {info!r}")
        log.debug("--- End Monitor State Dump ---")
        self.notify("Monitor state dumped to log (debug level).")


# --- Main function to launch app (accepts queue) ---


def main(monitor: Monitor, log_queue: deque):
    """Runs the Textual application."""
    log.info("Initializing Textual App...")
    app = FileApp(monitor=monitor, log_queue=log_queue)
    app.run()
