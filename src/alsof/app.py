# Filename: app.py

import datetime
import logging
from collections import deque

from rich.text import Text  # Ensure Rich Text is imported
from textual.app import App, ComposeResult
from textual.binding import Binding
from textual.containers import Container, VerticalScroll

# Import Coordinate for type hinting
from textual.coordinate import Coordinate
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
        # If max_length is very small, just truncate at the end
        return text[: max_length - 3] + "..." if max_length >= 3 else text[:max_length]

    ellipsis = "..."
    keep_len = max_length - len(ellipsis)
    # Calculate start and end lengths, ensuring they are non-negative
    start_len = max(1, keep_len // 2)
    end_len = max(
        1, keep_len - start_len
    )  # Ensure end_len is at least 1 if keep_len > 1

    # Make sure indices don't exceed text length
    start_len = min(start_len, len(text))
    end_len = min(end_len, len(text) - start_len)

    # Prevent overlap in extreme short max_length cases or if calculation is off
    if start_len + len(ellipsis) + end_len > len(text):
        # Recalculate simply: prioritize start, then add ellipsis, then fill end
        start_len = min(start_len, len(text))
        if start_len + len(ellipsis) < len(text):
            end_len = min(end_len, len(text) - start_len - len(ellipsis))
            # Adjust end_len further if total length exceeds max_length
            total_len_calc = start_len + len(ellipsis) + end_len
            if total_len_calc > max_length:
                end_len -= total_len_calc - max_length
                end_len = max(0, end_len)  # Ensure end_len is not negative
        else:
            # Not enough space for start + ellipsis, just truncate end
            return (
                text[: max_length - 3] + "..." if max_length >= 3 else text[:max_length]
            )

    return f"{text[:start_len]}{ellipsis}{text[len(text)-end_len:]}"


class LogScreen(ModalScreen[None]):
    """A modal screen to display application logs."""

    BINDINGS = [
        Binding("escape,q,ctrl+l", "app.pop_screen", "Close Logs", show=True),
        Binding("c", "clear_log", "Clear", show=True),
    ]

    def __init__(self, log_queue: deque):
        self.log_queue = log_queue
        self._timer = None
        super().__init__()

    def compose(self) -> ComposeResult:
        with VerticalScroll(id="log-container"):
            # Log widget automatically handles markup in strings passed to write_line(s)
            yield Log(id="app-log", max_lines=2000, auto_scroll=True)

    def on_mount(self) -> None:
        log_widget = self.query_one(Log)
        log.debug(
            f"LogScreen mounted. Processing {len(self.log_queue)} existing log messages."
        )
        existing_logs = list(self.log_queue)
        if existing_logs:
            # Use write_lines for strings (which may contain markup)
            log_widget.write_lines(existing_logs)  # Use write_lines here
        self._timer = self.set_interval(1 / 10, self._check_log_queue)

    def on_unmount(self) -> None:
        if self._timer:
            self._timer.stop()
            log.debug("LogScreen unmounted. Stopped log queue timer.")

    def _check_log_queue(self) -> None:
        log_widget = self.query_one(Log)
        count = 0
        lines_to_write = []
        while self.log_queue:
            try:
                # Get markup string from queue
                record = self.log_queue.popleft()
                lines_to_write.append(record)
                count += 1
            except IndexError:
                break
        # Write collected lines in bulk if any
        if lines_to_write:
            log_widget.write_lines(lines_to_write)  # Use write_lines here too
            # log.debug(f"Processed {count} new log messages from queue.")

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
                id="event-log",
                max_lines=1000,
                markup=True,  # Keep markup for this one (it uses manual markup)
            ),
            id="detail-container",  # id should be on the container
        )

    def on_mount(self) -> None:
        log_widget = self.query_one(Log)
        history = self.file_info.event_history
        log.debug(f"DetailScreen on_mount: History length = {len(history)}")
        log.debug(f"DetailScreen on_mount: History content = {history}")
        if not history:
            log_widget.write_line("No event history recorded.")
            return
        log_widget.write_line("Timestamp         | Type     | Success | Details")
        log_widget.write_line(
            "-----------------|----------|---------|--------------------"
        )
        for event in history:
            ts_raw = event.get("ts", 0)
            try:
                # Ensure timestamp conversion handles potential errors robustly
                if isinstance(ts_raw, (int, float)) and ts_raw > 0:
                    ts = datetime.datetime.fromtimestamp(ts_raw).strftime(
                        "%H:%M:%S.%f"
                    )[:-3]
                else:
                    ts = str(ts_raw)[:17].ljust(
                        17
                    )  # Fallback formatting, adjust length
            except (TypeError, ValueError, OSError):  # Catch potential timestamp errors
                ts = str(ts_raw)[:17].ljust(17)  # Fallback formatting, adjust length

            etype = str(event.get("type", "?")).ljust(8)
            success = "[green]OK[/]" if event.get("success", False) else "[red]FAIL[/]"
            # Calculate visible length correctly based on markup
            visible_len = len(Text.from_markup(success).plain)
            padding = " " * (7 - visible_len)
            success_padded = f"{success}{padding}"
            details = str(event.get("details", {}))
            # Truncate details more aggressively for display
            details_display = truncate_middle(
                details.replace("\n", "\\n"), 60
            )  # Truncate details
            log_widget.write_line(
                f"{ts} | {etype} | {success_padded} | {details_display}"
            )


# --- Main Application ---


class FileApp(App[None]):
    """Textual file monitor application."""

    TITLE = "alsof - Another lsof"  # Give it a title
    BINDINGS = [
        Binding("q,escape", "quit", "Quit", show=True, priority=True),
        Binding("x", "ignore_all", "Ignore All", show=True),
        Binding("i,backspace,delete", "ignore_selected", "Ignore Selected", show=True),
        Binding("enter", "show_details", "Show Details", show=True),
        Binding(
            "ctrl+l", "show_log", "Show Log / Close Log", show=True
        ),  # Updated description
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
    LogScreen #log-container { height: 1fr; } /* Ensure log container fills space */
    LogScreen #app-log { height: 1fr; }
    /* DetailScreen styling */
    DetailScreen > Container {
        border: thick $accent; padding: 1; width: 90%; height: 80%; background: $surface;
    }
    DetailScreen #detail-container { height: 1fr; }
    DetailScreen #event-log { height: 1fr; border: none; } /* Remove border from event log */
    """

    last_monitor_version = reactive(-1)

    def __init__(self, monitor: Monitor, log_queue: deque):
        super().__init__()
        self.monitor = monitor
        self.log_queue = log_queue
        self._update_interval = 1.0  # Update interval in seconds

    def compose(self) -> ComposeResult:
        # yield Header() # Header removed
        yield DataTable(id="file-table", cursor_type="row", zebra_stripes=True)
        yield Static("Status: Initializing...", id="status-bar")
        yield Footer()

    def on_mount(self) -> None:
        table = self.query_one(DataTable)
        table.add_column("?", key="emoji", width=3)
        table.add_column("Activity", key="activity", width=10)
        table.add_column("Path", key="path")  # Let path take remaining width
        self.update_table()
        self.set_interval(self._update_interval, self.update_table)
        self.update_status("Monitoring started...")
        log.info("UI Mounted, starting update timer.")

    def update_status(self, text: str):
        try:
            status_bar = self.query_one("#status-bar", Static)
            status_bar.update(text)
        except Exception:
            # Don't log excessively if status bar query fails repeatedly
            pass  # log.exception("Error updating status bar")

    def _get_emoji_for_file(self, info: FileInfo) -> str:
        # Prioritize error/deleted status
        if info.status == "deleted":
            return "❌"
        if info.status == "error" or info.last_error_enoent:
            return "❗"

        # Check recent events for activity type
        recent_types = list(info.recent_event_types)  # Get a copy
        has_read = "READ" in recent_types
        has_write = "WRITE" in recent_types

        if has_read and has_write:
            return "↔️"
        if has_write:
            return "⬆️"
        if has_read:
            return "⬇️"

        # If no R/W, check other significant events
        if info.is_open:  # Check if currently open
            return "✅"  # Open but no recent R/W
        if "OPEN" in recent_types:  # Recently opened but now closed?
            return "🚪"  # Treat as recently closed if OPEN is last but not is_open
        if "STAT" in recent_types:
            return "👀"
        if "RENAME" in recent_types:
            return "🔄"
        if "CLOSE" in recent_types:
            return "🚪"

        # Default if no specific activity detected
        # Show question mark only if status is truly unknown and has history
        if info.status == "unknown" and info.event_history:
            return "❔"
        # Otherwise, show blank for idle/accessed states
        return " "

    def update_table(self) -> None:
        if not self.monitor:
            return

        current_version = self.monitor.version
        # Check if update is needed
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
            return  # Avoid errors if widgets are gone

        # --- Calculate Path Width ---
        other_cols_width = 0
        col_count = 0
        fixed_width_cols = {"emoji", "activity"}  # Columns with fixed width
        for key, col in table.columns.items():
            col_count += 1
            if key in fixed_width_cols:
                other_cols_width += col.width  # Use defined width for calculation

        # Use content_size which accounts for borders/padding
        table_width = table.content_size.width
        # Padding is roughly number of columns - 1 internal borders + 2 outer padding
        padding = max(0, col_count + 1)
        available_width = max(10, table_width - other_cols_width - padding)
        log.debug(
            f"Table width: {table_width}, "
            f"Other cols: {other_cols_width}, "
            f"Padding: {padding}, "
            f"Available for path: {available_width}"
        )

        # --- Get and Sort Data ---
        all_files = list(self.monitor)  # Get snapshot
        active_files = [
            info for info in all_files if info.path not in self.monitor.ignored_paths
        ]
        active_files.sort(key=lambda info: info.last_activity_ts, reverse=True)
        log.debug(f"update_table: Processing {len(active_files)} active files.")

        # --- Preserve Cursor ---
        selected_path_key = None
        coordinate: Coordinate | None = (
            table.cursor_coordinate
        )  # Use Coordinate type hint
        if table.is_valid_coordinate(coordinate):  # coordinate can now be None safely
            try:
                selected_path_key = table.get_row_key(coordinate.row)
                if selected_path_key is not None:
                    log.debug(
                        f"Cursor was on row {coordinate.row}, key '{selected_path_key}'"
                    )
            except Exception as e:
                log.debug(f"Error getting cursor row key: {e}")
                selected_path_key = None
        else:
            log.debug("Cursor coordinate invalid or table empty before clear.")

        # --- Repopulate Table ---
        # Clear the table before adding rows
        table.clear()
        row_keys_added_this_update = set()  # Track keys added in this specific update

        # Add rows
        for info in active_files:
            row_key = info.path
            # Avoid adding duplicates if monitor state somehow has them
            if row_key in row_keys_added_this_update:
                log.warning(f"Skipping duplicate path in update_table loop: {row_key}")
                continue
            row_keys_added_this_update.add(row_key)

            emoji = self._get_emoji_for_file(info)
            path_display = truncate_middle(info.path, available_width)
            activity_str = (
                f"{info.bytes_read}r/{info.bytes_written}w"
                if (info.bytes_read or info.bytes_written)
                else (
                    info.status
                    if info.status not in ["unknown", "accessed", "closed", "active"]
                    else ""
                )  # Show significant status, hide common ones
            )
            style = ""
            if info.status == "deleted":
                style = "strike"
            elif info.last_error_enoent:  # Specific ENOENT style
                style = "dim strike"  # Dim and strike through for file not found errors
            elif info.status == "error":
                style = "red"
            elif info.is_open:
                # Style open files, perhaps differently if also active?
                style = "bold green" if info.status == "active" else "bold"
            elif info.status == "active":  # Active but closed
                style = "green"
            elif (
                info.last_event_type == "STAT" and not info.is_open
            ):  # Style STAT only if closed
                style = "yellow"

            row_data = (
                Text(f" {emoji} ", style=style),
                Text(activity_str, style=style),
                Text(path_display, style=style),
            )

            # Add the row since table was cleared
            try:
                table.add_row(*row_data, key=row_key)
            except Exception as add_exc:  # Catch potential errors during add_row
                log.exception(f"Error adding row for key {row_key}: {add_exc}")

        # --- Remove redundant row removal logic ---
        # keys_to_remove = current_keys - new_keys # Not needed after table.clear()
        # if keys_to_remove: ...

        # --- Restore Cursor ---
        new_row_index = -1
        # FIX: Check existence using 'in table.rows'
        if selected_path_key is not None and selected_path_key in table.rows:
            try:
                new_row_index = table.get_row_index(selected_path_key)
                log.debug(
                    f"Found previously selected key '{selected_path_key}' at new index {new_row_index}"
                )
            except Exception as e:
                log.debug(
                    f"Error getting new row index for key '{selected_path_key}': {e}"
                )
                new_row_index = -1  # Reset if error occurs
        elif selected_path_key is not None:
            log.debug(
                f"Saved key '{selected_path_key}' no longer exists in table rows."
            )

        # Move cursor only if the target index is valid
        if new_row_index != -1 and new_row_index < table.row_count:
            log.debug(f"Moving cursor to row index {new_row_index}")
            table.move_cursor(row=new_row_index, animate=False)
        elif table.row_count > 0 and (selected_path_key is None or new_row_index == -1):
            # If no previous selection or previous selection gone, move to top
            log.debug("Moving cursor to row 0 (fallback or no prior selection)")
            # Check if cursor is already at 0 to avoid unnecessary move
            current_cursor_row, _ = table.cursor_coordinate
            if current_cursor_row != 0:
                table.move_cursor(row=0, animate=False)
        elif table.row_count == 0:
            log.debug("Table empty, not moving cursor.")

        # --- Update Status Bar ---
        status_bar.update(
            f"Tracking {len(active_files)} files. "
            f"Ignored: {len(self.monitor.ignored_paths)}. "
            f"Monitor v{current_version}"  # Simplified version display
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
            row_key = table.get_row_key(coordinate.row)  # Safer way to get key
            if row_key is not None:
                path_to_ignore = str(row_key)
                log.info(f"Ignoring selected path: {path_to_ignore}")
                self.monitor.ignore(path_to_ignore)
                # No need to call update_table here, reactive property will handle it
                self.notify(f"Ignored: {path_to_ignore}", timeout=2)
            else:
                self.notify("Could not get key for selected row.", severity="error")
        except Exception as e:
            log.exception("Error ignoring selected.")
            self.notify(f"Error: {e}", severity="error")

    def action_ignore_all(self) -> None:
        log.info("Ignoring all tracked files.")
        try:
            # Get count *before* modifying
            count_before = len(
                [fi for fi in self.monitor if fi.path not in self.monitor.ignored_paths]
            )
            self.monitor.ignore_all()  # This triggers version change
            # Let the reactive update handle the table refresh.
            # Calculate ignored count based on what was present before the call.
            # Note: This might not be perfectly accurate if new files arrived *during* ignore_all.
            self.notify(f"Ignoring {count_before} currently tracked files.", timeout=2)
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
            row_key = table.get_row_key(coordinate.row)  # Safer way
            if row_key is not None:
                path = str(row_key)
                log.debug(f"Showing details for: {path}")
                # Use get() with default to handle potential race condition
                file_info = self.monitor.files.get(path)
                if file_info:
                    self.push_screen(DetailScreen(file_info))
                else:
                    # File might have been removed between update_table and action
                    log.warning(f"File '{path}' disappeared before showing details.")
                    self.notify(
                        "File state not found (may have been removed).",
                        severity="warning",
                        timeout=3,
                    )
            else:
                self.notify("Could not get key for selected row.", severity="error")
        except Exception as e:  # Catch broader exceptions
            log.exception("Error showing details.")
            self.notify(f"Error showing details: {e}", severity="error")

    def action_show_log(self) -> None:
        """Pushes the LogScreen onto the view or pops it if already open."""
        # Check if LogScreen is already the top screen
        if isinstance(self.screen, LogScreen):
            self.pop_screen()
            log.debug("Popped LogScreen via action_show_log.")
        elif self.is_screen_installed(LogScreen):
            # If installed but not top, bring it forward (or just pop current)
            # Popping might be simpler if only one modal level expected
            self.pop_screen()  # Assuming current screen is the one to close
            log.debug("Popped current screen to reveal LogScreen.")
        else:
            log.info("Action: show_log triggered. Pushing LogScreen.")
            self.push_screen(LogScreen(self.log_queue))

    # --- DEBUG ACTION ---
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
            # Sort items for consistent debug output
            # Use list(monitor) to get a snapshot safely
            sorted_files = sorted(list(self.monitor), key=lambda f: f.path)
            for info in sorted_files:
                log.debug(f"  {info.path}: {info!r}")
            log.debug("--- End Monitor State Dump ---")
            self.notify("Monitor state dumped to log (debug level).")
        except Exception:
            log.exception("Error during monitor state dump.")
            self.notify("Error dumping monitor state.", severity="error")


# --- Main function to launch app (accepts queue) ---


def main(monitor: Monitor, log_queue: deque):
    """Runs the Textual application."""
    log.info("Initializing Textual App...")
    app = FileApp(monitor=monitor, log_queue=log_queue)
    app.run()
