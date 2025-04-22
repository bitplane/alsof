#!/usr/bin/env python3
import logging
import os
import threading
import time
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

import psutil

from lsoph.monitor import Monitor

# Setup logging
log = logging.getLogger("lsoph.backend.psutil")


class PsutilBackend:
    """Backend implementation that uses psutil to monitor file activities."""

    def __init__(self, monitor: Monitor):
        self.monitor = monitor
        self.cwd_map: Dict[int, str] = {}
        self.pid_map: Dict[int, bool] = {}  # Tracks if we've seen this PID before
        self.fd_map: Dict[int, Dict[int, Tuple[str, bool, bool]]] = (
            {}
        )  # pid -> {fd -> (path, read, write)}
        self.poll_interval = 0.5  # seconds
        self.running = False
        self.poll_thread = None
        self.lock = threading.RLock()

    def _get_process_cwd(self, pid: int) -> Optional[str]:
        """Get current working directory for a process."""
        try:
            proc = psutil.Process(pid)
            return proc.cwd()
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            return None
        except Exception as e:
            log.debug(f"Error getting CWD for PID {pid}: {e}")
            return None

    def _resolve_path(self, pid: int, path: str) -> str:
        """Resolve a potentially relative path to absolute using process CWD."""
        if path.startswith("/") or (len(path) > 1 and path[1] == ":"):  # Absolute path
            return path

        # Try to resolve using process CWD
        if pid in self.cwd_map:
            return os.path.normpath(os.path.join(self.cwd_map[pid], path))

        # Try to get CWD if not cached
        cwd = self._get_process_cwd(pid)
        if cwd:
            self.cwd_map[pid] = cwd
            return os.path.normpath(os.path.join(cwd, path))

        # Fallback to current directory
        return os.path.abspath(path)

    def _get_open_files(self, pid: int) -> List[Dict[str, Any]]:
        """Get open files for a process with error handling."""
        try:
            proc = psutil.Process(pid)
            # Cache the CWD
            if pid not in self.cwd_map:
                try:
                    self.cwd_map[pid] = proc.cwd()
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    pass

            open_files = []
            # Get open files directly from psutil
            try:
                for f in proc.open_files():
                    open_files.append(
                        {
                            "path": f.path,
                            "fd": f.fd,
                            "mode": getattr(f, "mode", ""),
                        }
                    )
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                pass

            # Add connections as files too
            try:
                for conn in proc.connections(kind="all"):
                    if conn.status == "ESTABLISHED":
                        path = f"<SOCKET:{conn.laddr.ip}:{conn.laddr.port}->{conn.raddr.ip}:{conn.raddr.port}>"
                    else:
                        path = f"<SOCKET:{conn.laddr.ip}:{conn.laddr.port}>"

                    open_files.append(
                        {
                            "path": path,
                            "fd": conn.fd if hasattr(conn, "fd") else -1,
                            "mode": "rw",  # Assuming socket connections are read-write
                        }
                    )
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                pass

            return open_files
        except psutil.NoSuchProcess:
            log.debug(f"Process {pid} no longer exists.")
            return []
        except psutil.AccessDenied:
            log.debug(f"Access denied for process {pid}.")
            return []
        except Exception as e:
            log.debug(f"Error getting open files for PID {pid}: {e}")
            return []

    def _get_descendants(self, pid: int) -> List[int]:
        """Get all descendant PIDs recursively."""
        try:
            proc = psutil.Process(pid)
            return [p.pid for p in proc.children(recursive=True)]
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            return []
        except Exception as e:
            log.debug(f"Error getting descendants for PID {pid}: {e}")
            return []

    def _poll_processes(self, pids: List[int]) -> None:
        """Poll processes for open files and update monitor."""
        with self.lock:
            # Check for new processes and store their CWD
            all_pids = set(pids)
            for pid in pids:
                descendants = self._get_descendants(pid)
                for child_pid in descendants:
                    if child_pid not in self.pid_map:
                        # New process - inherit parent's CWD if available
                        if pid in self.cwd_map and child_pid not in self.cwd_map:
                            self.cwd_map[child_pid] = self.cwd_map[pid]
                        self.pid_map[child_pid] = True
                        log.debug(f"Found new child process: {child_pid}")
                    all_pids.add(child_pid)

            # Keep track of current FDs to detect closures
            current_fds: Dict[int, Set[int]] = {}
            timestamp = time.time()

            # Process each PID
            for pid in all_pids:
                # Skip processes we already know don't exist
                if pid in self.pid_map and self.pid_map[pid] is False:
                    continue

                # Get open files
                open_files = self._get_open_files(pid)

                # If process doesn't exist, mark it
                if not open_files and not psutil.pid_exists(pid):
                    self.pid_map[pid] = False
                    if pid in self.fd_map:
                        # Process exit - close all its files
                        for fd in list(self.fd_map[pid].keys()):
                            path, _, _ = self.fd_map[pid][fd]
                            self.monitor.close(pid, fd, True, timestamp)
                        del self.fd_map[pid]
                    continue

                current_fds[pid] = set()

                # Process open files
                for file_info in open_files:
                    path = file_info["path"]
                    fd = file_info["fd"]
                    mode = file_info.get("mode", "")

                    # Skip if invalid fd
                    if fd < 0:
                        continue

                    current_fds[pid].add(fd)

                    # Check if this is a new file or changed mode
                    is_new = True
                    has_changed = False
                    if pid in self.fd_map and fd in self.fd_map[pid]:
                        is_new = False
                        old_path, old_read, old_write = self.fd_map[pid][fd]
                        has_changed = old_path != path

                    # Handle new file or changed file
                    if is_new or has_changed:
                        if not is_new and has_changed:
                            # File path changed (might be a rename)
                            old_path, _, _ = self.fd_map[pid][fd]
                            # First close the old file
                            self.monitor.close(pid, fd, True, timestamp)
                            # Then open the new one
                            log.debug(
                                f"File path changed for PID {pid}, FD {fd}: {old_path} -> {path}"
                            )

                        # Register file open
                        can_read = "r" in mode
                        can_write = "w" in mode or "a" in mode or "+" in mode

                        self.monitor.open(pid, path, fd, True, timestamp)
                        self.fd_map.setdefault(pid, {})[fd] = (
                            path,
                            can_read,
                            can_write,
                        )

                        # Register read/write access based on mode
                        if can_read:
                            self.monitor.read(pid, fd, path, True, timestamp, bytes=0)
                        if can_write:
                            self.monitor.write(pid, fd, path, True, timestamp, bytes=0)

            # Detect closed files
            for pid in list(self.fd_map.keys()):
                if pid not in current_fds:
                    if psutil.pid_exists(pid):
                        # Process exists but has no open files
                        continue

                    # Process has terminated - close all its files
                    for fd, (path, _, _) in self.fd_map[pid].items():
                        self.monitor.close(pid, fd, True, timestamp)
                    del self.fd_map[pid]
                else:
                    # Check for closed files in existing processes
                    for fd in list(self.fd_map[pid].keys()):
                        if fd not in current_fds[pid]:
                            path, _, _ = self.fd_map[pid][fd]
                            self.monitor.close(pid, fd, True, timestamp)
                            del self.fd_map[pid][fd]

    def _polling_thread(self, pids: List[int]) -> None:
        """Background thread that periodically polls processes."""
        try:
            log.info(f"Starting polling thread for PIDs: {pids}")

            while self.running:
                try:
                    self._poll_processes(pids)
                    time.sleep(self.poll_interval)
                except Exception as e:
                    log.error(f"Error in polling thread: {e}")
                    time.sleep(self.poll_interval)

        except Exception as e:
            log.exception(f"Polling thread failed: {e}")
        finally:
            log.info("Polling thread stopped.")

    def attach(self, pids: List[int], monitor: Monitor) -> None:
        """Attach to existing processes."""
        self.monitor = monitor
        self.running = True

        # Initialize pid_map with starting PIDs
        for pid in pids:
            self.pid_map[pid] = True

            # Try to get CWD for each process
            cwd = self._get_process_cwd(pid)
            if cwd:
                self.cwd_map[pid] = cwd

        # Start polling thread
        self.poll_thread = threading.Thread(
            target=self._polling_thread, args=(pids,), daemon=True
        )
        self.poll_thread.start()

        try:
            while self.running:
                time.sleep(0.1)  # Keep main thread alive
        except KeyboardInterrupt:
            log.info("Attach interrupted by user.")
            self.running = False
        except Exception as e:
            log.exception(f"Error in attach: {e}")
            self.running = False

    def run(self, command: List[str], monitor: Monitor) -> None:
        """Run a command and monitor its file activity."""
        import subprocess

        self.monitor = monitor
        self.running = True

        proc = None
        try:
            # Start the process
            log.info(f"Running command: {' '.join(command)}")
            proc = subprocess.Popen(command)
            pid = proc.pid
            log.info(f"Command started with PID: {pid}")

            # Get initial CWD
            cwd = self._get_process_cwd(pid)
            if cwd:
                self.cwd_map[pid] = cwd

            # Mark this process as active
            self.pid_map[pid] = True

            # Start polling thread for this process and its descendants
            self.poll_thread = threading.Thread(
                target=self._polling_thread, args=([pid],), daemon=True
            )
            self.poll_thread.start()

            # Wait for process to complete or user interrupt
            while self.running and proc.poll() is None:
                time.sleep(0.1)

            if proc.poll() is not None:
                log.info(f"Command exited with code: {proc.returncode}")

        except KeyboardInterrupt:
            log.info("Run interrupted by user.")
            self.running = False
        except Exception as e:
            log.exception(f"Error in run: {e}")
            self.running = False
        finally:
            # Cleanup
            if proc and proc.poll() is None:
                log.info("Terminating command process.")
                proc.terminate()
                try:
                    proc.wait(timeout=1)
                except subprocess.TimeoutExpired:
                    log.info("Forcibly killing command process.")
                    proc.kill()
                    proc.wait()

            self.running = False

            # Wait for polling thread to stop
            if self.poll_thread and self.poll_thread.is_alive():
                self.poll_thread.join(timeout=1)


# Functions exposed by the backend


def attach(pids: List[int], monitor: Monitor) -> None:
    """Attach to existing processes."""
    backend = PsutilBackend(monitor)
    backend.attach(pids, monitor)


def run(command: List[str], monitor: Monitor) -> None:
    """Run a command and monitor its file activity."""
    backend = PsutilBackend(monitor)
    backend.run(command, monitor)
