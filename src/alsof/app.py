# Filename: app.py

import datetime
import logging

from rich.text import Text
from textual.app import App, ComposeResult
from textual.binding import Binding
from textual.containers import Container
from textual.reactive import reactive
from textual.screen import ModalScreen
from textual.widgets import DataTable, Footer, Header, Label, Log, Static

# Assume monitor.py and versioned.py are importable via the package
from alsof.monitor import Monitor, FileInfo

log = logging.getLogger("alsof.app")


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


class DetailScreen(ModalScreen[None]):
    """Screen to display event history for a specific file."""

    BINDINGS = [
        Binding("escape,q", "app.pop_screen", "Close", show=True),
    ]

    def __init__(self, file_info: FileInfo):
        self.file_info = file_info
        super().__init__()

    def compose(self) -> ComposeResult:
        yield Container(
            Label(f"Event History for: {self.file_info.path}"),
            Log(id="event-log", max_lines=1000, markup=True),
            id="detail-container",
        )

    def on_mount(self) -> None:
        """Populate the log on mount."""
        log_widget = self.query_one(Log)
        history = self.file_info.event_history
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


class FileApp(App[None]):
    """Textual file monitor application."""

    TITLE = None  # No title bar

    BINDINGS = [
        Binding("q,escape", "quit", "Quit", show=True, priority=True),
        Binding("x", "ignore_all", "Ignore All", show=True),
        Binding("i,backspace,delete", "ignore_selected", "Ignore Selected", show=True),
        Binding("enter", "show_details", "Show Details", show=True),
    ]

    # CSS can still define base styles if needed, but row-specific
    # styles will be applied directly via Text objects.
    CSS = """
    Screen { }
    DataTable {
        height: 1fr;
        border: thick $accent;
    }
    #status-bar {
        height: auto;
        dock: bottom;
        color: $text-muted;
        padding: 0 1;
    }
    /* Keep class definitions if useful for other styling or targeting */
    .deleted-row { }
    .error-row { }
    .open-row { }
    .stat-row { }
    """

    last_monitor_version = reactive(-1)

    def __init__(self, monitor: Monitor):
        super().__init__()
        self.monitor = monitor
        self._update_interval = 1.0  # Seconds

    def compose(self) -> ComposeResult:
        yield Header()
        yield DataTable(id="file-table", cursor_type="row", zebra_stripes=True)
        yield Static("Status: Initializing...", id="status-bar")
        yield Footer()

    def on_mount(self) -> None:
        """Called when the app widget is mounted."""
        table = self.query_one(DataTable)
        table.add_column("?", key="emoji", width=3)
        table.add_column("Activity", key="activity", width=10)
        table.add_column("Path", key="path")

        self.update_table()
        self.set_interval(self._update_interval, self.update_table)
        self.update_status("Monitoring started...")
        log.info("UI Mounted, starting update timer.")

    def update_status(self, text: str):
        """Helper to update the status bar."""
        try:
            status_bar = self.query_one("#status-bar", Static)
            status_bar.update(text)
        except Exception:
            log.exception("Error updating status bar")

    def _get_emoji_for_file(self, info: FileInfo) -> str:
        """Determines an emoji based on recent activity."""
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
        """Called by the timer to refresh the DataTable."""
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
            log.warning("Could not query table/status bar, possibly shutting down.")
            return

        # --- Calculate available width for path ---
        other_cols_width = 0
        col_count = 0
        for key, col in table.columns.items():
            col_count += 1
            if key != "path":
                other_cols_width += col.content_width
        table_width = table.size.width
        padding = max(0, col_count - 1) + 2
        available_width = max(10, table_width - other_cols_width - padding)

        # --- Get and Sort Data ---
        all_files = list(self.monitor)
        active_files = [
            info for info in all_files if info.path not in self.monitor.ignored_paths
        ]
        active_files.sort(key=lambda info: info.last_activity_ts, reverse=True)

        # --- Preserve Cursor ---
        selected_path_key = None
        cursor_row = table.cursor_row
        if cursor_row >= 0 and cursor_row < table.row_count:
            try:
                selected_path_key = table.get_row_key(cursor_row)
            except Exception:
                pass

        # --- Update Table ---
        table.clear()
        row_keys_added = set()

        for info in active_files:
            if info.path in row_keys_added:
                continue

            row_key = info.path
            row_keys_added.add(row_key)

            emoji = self._get_emoji_for_file(info)
            path_display = truncate_middle(info.path, available_width)
            activity_str = (
                f"{info.bytes_read}r/{info.bytes_written}w"
                if (info.bytes_read or info.bytes_written)
                else info.status
            )

            # Determine style string based on state
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

            # Add row, applying style to each cell's Text object
            table.add_row(
                Text(f" {emoji} ", style=style),  # Apply style here
                Text(activity_str, style=style),  # Apply style here
                Text(path_display, style=style),  # Apply style here
                key=row_key,
                # Removed classes= argument
            )

        # --- Restore Cursor ---
        new_row_index = -1
        if selected_path_key and table.is_valid_row_key(selected_path_key):
            try:
                new_row_index = table.get_row_index(selected_path_key)
            except Exception:
                pass

        if new_row_index != -1:
            table.move_cursor(row=new_row_index, animate=False)
        elif table.row_count > 0:
            table.move_cursor(row=0, animate=False)

        # Update status bar
        status_bar.update(
            f"Tracking {len(active_files)} files. Ignored: {len(self.monitor.ignored_paths)}. Version: {current_version}"
        )

    # --- Action Handlers ---

    def action_quit(self) -> None:
        """Quit the application."""
        log.info("Quit action triggered.")
        self.exit()

    def action_ignore_selected(self) -> None:
        """Ignore the currently selected file."""
        table = self.query_one(DataTable)
        if not table.is_valid_coordinate(table.cursor_coordinate):
            self.notify("No row selected to ignore.", severity="warning", timeout=2)
            return
        try:
            row_key = table.get_row_key(table.cursor_coordinate.row)
            if row_key:
                path_to_ignore = str(row_key)
                log.info(f"Ignoring selected path: {path_to_ignore}")
                self.monitor.ignore(path_to_ignore)
                self.notify(f"Ignored: {path_to_ignore}", timeout=2)
            else:
                self.notify(
                    "Could not get path for selected row.", severity="error", timeout=2
                )
        except Exception as e:
            log.exception(f"Error ignoring selected file: {e}")
            self.notify(f"Error: {e}", severity="error", timeout=3)

    def action_ignore_all(self) -> None:
        """Ignore all currently tracked files."""
        log.info("Ignoring all tracked files.")
        try:
            count_before = len(
                [fi for fi in self.monitor if fi.path not in self.monitor.ignored_paths]
            )
            self.monitor.ignore_all()
            count_after = len(
                [fi for fi in self.monitor if fi.path not in self.monitor.ignored_paths]
            )
            self.notify(f"Ignored {count_before - count_after} files.", timeout=2)
        except Exception as e:
            log.exception(f"Error ignoring all files: {e}")
            self.notify(f"Error ignoring all: {e}", severity="error", timeout=3)

    def action_show_details(self) -> None:
        """Show the event history for the selected file."""
        table = self.query_one(DataTable)
        if not table.is_valid_coordinate(table.cursor_coordinate):
            self.notify(
                "No row selected to show details.", severity="warning", timeout=2
            )
            return
        try:
            row_key = table.get_row_key(table.cursor_coordinate.row)
            if row_key:
                path = str(row_key)
                file_info = self.monitor[path]  # Use __getitem__
                log.info(f"Showing details for: {path}")
                self.push_screen(DetailScreen(file_info))
            else:
                self.notify(
                    "Could not get path for selected row.", severity="error", timeout=2
                )
        except KeyError:
            log.warning(f"File '{path}' not found in monitor state for details view.")
            self.notify(
                "File state not found (might have been removed).",
                severity="warning",
                timeout=2,
            )
        except Exception as e:
            log.exception(f"Error showing details: {e}")
            self.notify(f"Error showing details: {e}", severity="error", timeout=3)


# --- Main function to launch app ---


def main(monitor: Monitor):
    """Runs the Textual application."""
    log.info("Initializing Textual App...")
    app = FileApp(monitor=monitor)
    app.run()
