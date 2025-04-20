import datetime
import logging
import sys

from textual.app import App, ComposeResult
from textual.binding import Binding
from textual.containers import Container
from textual.reactive import reactive
from textual.screen import ModalScreen
from textual.widgets import DataTable, Footer, Header, Label, Log, Static

# Assume monitor.py and versioned.py are importable
try:
    from monitor import FileInfo, Monitor
except ImportError as e:
    print(
        f"ERROR: Failed to import 'Monitor' or 'FileInfo' from 'monitor.py'. "
        f"Ensure 'monitor.py' exists and is importable. Details: {e}",
        file=sys.stderr,
    )
    sys.exit(f"Missing dependency: {e}")

# --- Setup Logging ---
# Configure basic logging; callers can override this configuration.
log = logging.getLogger(__name__)  # Use module name


# --- Utility ---
def truncate_middle(text: str, max_length: int) -> str:
    """Truncates text in the middle, preserving start and end."""
    if len(text) <= max_length:
        return text
    if max_length < 5:
        return text[:max_length]

    ellipsis = "..."
    keep_len = max_length - len(ellipsis)
    # Prioritize keeping more of the end (filename)
    end_len = min(len(text) // 2 + 1, keep_len * 2 // 3, len(text) - 1)
    start_len = keep_len - end_len
    if start_len < 0:
        start_len = 0
        end_len = keep_len

    start_len = min(start_len, len(text))
    end_len = min(end_len, len(text))

    if start_len + end_len > len(text):
        start_len = keep_len // 2
        end_len = keep_len - start_len

    return f"{text[:start_len]}{ellipsis}{text[len(text)-end_len:]}"


# --- Detail Screen ---


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
            Log(id="event-log", max_lines=1000, markup=True),  # Use Log widget
            id="detail-container",
        )

    def on_mount(self) -> None:
        """Populate the log on mount."""
        log_widget = self.query_one(Log)
        history = self.file_info.event_history  # deque of dicts
        if not history:
            log_widget.write_line("No event history recorded.")
            return

        log_widget.write_line("Timestamp        | Type     | Success | Details")
        log_widget.write_line(
            "-----------------|----------|---------|--------------------"
        )
        for event in history:
            ts = datetime.datetime.fromtimestamp(event.get("ts", 0)).strftime(
                "%H:%M:%S.%f"
            )[:-3]
            etype = str(event.get("type", "?")).ljust(8)
            success = "[green]OK[/]" if event.get("success", False) else "[red]FAIL[/]"
            success = success.ljust(16)  # Pad markup string correctly
            details = str(event.get("details", {}))
            log_widget.write_line(f"{ts} | {etype} | {success} | {details}")


# --- Main Application ---


class FileApp(App[None]):
    """Textual file monitor application."""

    TITLE = None  # No title bar

    BINDINGS = [
        Binding("q,escape", "quit", "Quit", show=True, priority=True),
        Binding("x", "ignore_all", "Ignore All", show=True),
        Binding("i,backspace,delete", "ignore_selected", "Ignore Selected", show=True),
        Binding("enter", "show_details", "Show Details", show=True),
    ]

    CSS = """
    Screen {
        /* layout: vertical; */
    }
    #file-table {
        height: 1fr; /* Fill available space */
        border: thick $accent;
    }
    #status-bar {
        height: auto;
        dock: bottom;
        padding: 0 1;
    }
    /* Basic styling for DataTable rows */
    .deleted-row {
        text-style: strike;
        color: $text-muted;
    }
    .error-row {
        color: $error;
    }
    .open-row {
        text-style: bold;
    }
    .stat-row {
        color: $warning; /* Yellowish */
    }
    """

    # Reactive variable to store last seen monitor version
    last_monitor_version = reactive(-1)

    def __init__(self, monitor: Monitor):
        super().__init__()
        self.monitor = monitor
        self._update_interval = 1.0  # Seconds

    def compose(self) -> ComposeResult:
        yield Header()  # Standard header widget
        yield DataTable(id="file-table", cursor_type="row", zebra_stripes=True)
        yield Static(
            id="status-bar", renderable="Status: Initializing..."
        )  # Simple status bar
        yield Footer()  # Standard footer for keybindings

    def on_mount(self) -> None:
        """Called when the app widget is mounted."""
        table = self.query_one(DataTable)
        table.add_column("?", key="emoji", width=3)
        table.add_column("Activity", key="activity", width=10)  # Bytes/Status
        table.add_column("Path", key="path", width=None)  # Flexible width

        # Start the periodic update timer
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
        # Simple logic for now, can be expanded
        if not info.recent_event_types:
            return " "  # Blank if no recent events

        last_type = info.recent_event_types[-1]  # Most recent type

        if info.status == "deleted":
            return "❌"
        if info.status == "error":
            return "❗"
        if last_type == "OPEN":
            return "✅"  # Opened
        if last_type == "CLOSE":
            return "🚪"  # Closed
        if last_type == "READ" and last_type == "WRITE":
            return "↔️"  # Read/Write
        if last_type == "READ":
            return "⬇️"  # Read
        if last_type == "WRITE":
            return "⬆️"  # Write
        if last_type == "STAT":
            return "👀"  # Stat/Access
        if last_type == "RENAME":
            return "🔄"  # Rename (if added back)

        return "❔"  # Unknown/Other

    def update_table(self) -> None:
        """Called by the timer to refresh the DataTable."""
        if not self.monitor:
            return  # Should not happen

        current_version = self.monitor.version
        if current_version == self.last_monitor_version:
            # log.debug("Monitor version unchanged, skipping table update.")
            return  # No changes in the monitor state

        log.info(
            f"Monitor version changed ({self.last_monitor_version} -> {current_version}), updating table."
        )
        self.last_monitor_version = current_version

        try:
            table = self.query_one(DataTable)
            status_bar = self.query_one("#status-bar", Static)
        except Exception:
            log.warning("Could not query table/status bar, possibly shutting down.")
            return  # Widgets might not exist during shutdown

        # --- Calculate available width for path ---
        # This needs to account for borders, padding etc. more accurately
        other_cols_width = 0
        for key, col in table.columns.items():
            if key != "path":
                other_cols_width += col.content_width  # Use content_width
        # Estimate borders/padding (adjust as needed)
        table_width = table.size.width
        padding = 4
        available_width = max(10, table_width - other_cols_width - padding)

        # --- Get and Sort Data ---
        # Use the iterator, filter/sort here
        all_files = list(self.monitor)  # Get FileInfo objects via __iter__
        # Separate ignored files? For now, filter them out before display
        active_files = [
            info for info in all_files if info.path not in self.monitor.ignored_paths
        ]
        # Sort active files by last activity time
        active_files.sort(key=lambda info: info.last_activity_ts, reverse=True)

        # --- Preserve Cursor ---
        selected_path_key = None
        try:
            if table.is_valid_coordinate(table.cursor_coordinate):
                selected_path_key = table.get_row_key(table.cursor_coordinate.row)
        except Exception:
            pass  # Ignore errors getting cursor

        # --- Update Table ---
        table.clear()
        row_keys_added = set()

        for info in active_files:
            if info.path in row_keys_added:
                continue  # Should not happen if self.files keys are unique

            row_key = info.path
            row_keys_added.add(row_key)

            # Determine Style & Content
            emoji = self._get_emoji_for_file(info)
            path_display = truncate_middle(info.path, available_width)
            # Activity column: show bytes or status?
            activity_str = (
                f"{info.bytes_read}r/{info.bytes_written}w"
                if (info.bytes_read or info.bytes_written)
                else info.status
            )

            style = ""
            if info.status == "deleted":
                style = "strike"
            elif info.last_error_enoent:  # Check for file not found specifically
                style = "red"  # Use direct styling for red
            elif info.status == "error":
                style = "red"  # General error red
            elif info.is_open:
                style = "bold"
            elif info.last_event_type == "STAT":
                style = "yellow"  # Direct styling for yellow

            # Add row with styling
            table.add_row(
                f" {emoji} ",  # Add space around emoji
                activity_str,
                path_display,
                key=row_key,
                style=style,
                # classes=css_class # Using classes is another option
            )

        # --- Restore Cursor ---
        if selected_path_key and table.is_valid_row_key(selected_path_key):
            table.move_cursor(row_key=selected_path_key, animate=False)
        elif table.row_count > 0:
            table.move_cursor(row=0, animate=False)

        # Update status bar
        status_bar.update(
            f"Tracking {len(active_files)} files. Version: {current_version}"
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
                self.monitor.ignore(path_to_ignore)  # Call monitor method
                self.update_table()  # Trigger immediate update
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
            count_before = len(self.monitor)
            self.monitor.ignore_all()  # Call monitor method
            count_after = len(self.monitor)
            self.update_table()  # Trigger immediate update
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
                # Use __getitem__ on monitor
                file_info = self.monitor[path]
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
    # Setup logging potentially based on monitor or global config?
    # For now, assume logging is configured by cli.py
    log.info("Initializing Textual App...")
    app = FileApp(monitor=monitor)
    app.run()
