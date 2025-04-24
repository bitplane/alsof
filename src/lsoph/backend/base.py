# Filename: src/lsoph/backend/base.py
"""Base definitions for asynchronous monitoring backends."""

import asyncio
import logging
import subprocess  # Keep for type hint if needed, use asyncio below
from abc import ABC, abstractmethod
from typing import Any, Coroutine  # Added Coroutine, Any

from lsoph.monitor import Monitor

log = logging.getLogger("lsoph.backend.base")


class Backend(ABC):
    """Abstract Base Class for all monitoring backends."""

    # Class attribute intended to be overridden by subclasses
    # This name is used as the key in the BACKENDS dictionary
    backend_name: str = "base"  # Default, should be overridden

    def __init__(self, monitor: Monitor):
        """Initialize the backend."""
        self.monitor = monitor
        self._should_stop = asyncio.Event()
        self._process: asyncio.subprocess.Process | None = (
            None  # Store the process handle
        )
        log.info(f"Initializing backend: {self.__class__.__name__}")

    # __str__ method removed as it's not suitable for class-level key generation

    @staticmethod
    @abstractmethod
    def is_available() -> bool:
        """
        Check if the backend's dependencies (e.g., executable) are met.
        This MUST be implemented by subclasses.
        """
        raise NotImplementedError  # pragma: no cover

    @abstractmethod
    async def attach(self, pids: list[int]):
        """
        Asynchronously attach to and monitor existing process IDs.
        Should periodically check `self.should_stop`.
        """
        pass  # pragma: no cover

    async def run_command(self, command: list[str]):
        """
        Default implementation to run a command and monitor it using the backend's attach method.
        Backends like strace should override this if they have a different run mechanism.
        """
        if not command:
            log.error(
                f"{self.__class__.__name__}.run_command called with empty command."
            )
            return

        log.info(f"{self.__class__.__name__}: Running command: {' '.join(command)}")
        process: asyncio.subprocess.Process | None = None
        attach_task: asyncio.Task | None = None

        try:
            # Start the process asynchronously
            process = await asyncio.create_subprocess_exec(
                *command,
                stdout=asyncio.subprocess.DEVNULL,  # Redirect stdio if needed, or capture
                stderr=asyncio.subprocess.PIPE,  # Capture stderr for errors
            )
            self._process = process  # Store process handle for stop()
            pid = process.pid
            log.info(f"Command '{' '.join(command)}' started with PID: {pid}")

            # Create a task to run the attach method for the new PID.
            # Backends implementing attach should handle descendant tracking if appropriate.
            attach_task = asyncio.create_task(
                self.attach([pid]), name=f"attach_task_{pid}"
            )

            # Wait for either the attach task to complete (e.g., cancellation)
            # or the monitored process to exit, or the stop event.
            process_wait_task = asyncio.create_task(
                process.wait(), name=f"process_wait_{pid}"
            )
            stop_wait_task = asyncio.create_task(
                self._should_stop.wait(), name=f"stop_wait_{pid}"
            )

            done, pending = await asyncio.wait(
                [attach_task, process_wait_task, stop_wait_task],
                return_when=asyncio.FIRST_COMPLETED,
            )

            # Handle results/cancellation
            if process_wait_task in done:
                return_code = process.returncode
                log.info(
                    f"Command process {pid} exited with code {return_code}. Stopping attach task."
                )
                # Process finished, signal attach task to stop (if not already done)
                await self.stop()  # Signal stop event
                if attach_task not in done:  # If attach task is still pending
                    attach_task.cancel()  # Cancel it explicitly
            elif stop_wait_task in done:
                log.info(
                    f"Stop signal received for command '{' '.join(command)}'. Terminating process and attach task."
                )
                # Stop was called externally, cancel attach and terminate process
                if attach_task not in done:
                    attach_task.cancel()
                if process_wait_task not in done:
                    await self._terminate_process()  # Terminate the subprocess
            elif attach_task in done:
                log.info(
                    f"Attach task for command '{' '.join(command)}' finished unexpectedly or was cancelled."
                )
                # Attach finished (maybe cancelled), ensure process is stopped
                if process_wait_task not in done:
                    await self._terminate_process()

            # Cancel any remaining pending tasks
            for task in pending:
                if not task.done():
                    task.cancel()
                    try:
                        await task  # Allow cancellation to propagate
                    except asyncio.CancelledError:
                        pass  # Expected

        except FileNotFoundError:
            log.exception(f"Command not found: {command[0]}")
            await self.stop()  # Ensure stop is signalled
        except (OSError, Exception) as e:
            log.exception(
                f"Failed to start or manage command '{' '.join(command)}': {e}"
            )
            await self.stop()  # Ensure stop is signalled
            # Ensure process is terminated if it started
            if process and process.returncode is None:
                await self._terminate_process()
            # Ensure attach task is cancelled if it started
            if attach_task and not attach_task.done():
                attach_task.cancel()
                try:
                    await attach_task
                except asyncio.CancelledError:
                    pass  # Expected
        finally:
            log.info(f"Finished run_command for: {' '.join(command)}")
            self._process = None  # Clear process handle

    async def _terminate_process(self):
        """Helper to terminate the managed subprocess."""
        if self._process and self._process.returncode is None:
            pid = self._process.pid
            log.info(f"Terminating command process (PID: {pid})...")
            try:
                self._process.terminate()
                # Wait briefly for termination
                await asyncio.wait_for(self._process.wait(), timeout=1.0)
                log.debug(f"Command process {pid} terminated gracefully.")
            except asyncio.TimeoutError:
                log.warning(
                    f"Command process {pid} did not terminate gracefully, killing."
                )
                try:
                    self._process.kill()
                    await self._process.wait()  # Wait for kill
                    log.debug(f"Command process {pid} killed.")
                except ProcessLookupError:
                    log.warning(f"Command process {pid} already exited before kill.")
                except Exception as kill_err:
                    log.exception(f"Error killing process {pid}: {kill_err}")
            except ProcessLookupError:  # Process already exited
                log.warning(f"Command process {pid} already exited before terminate.")
            except Exception as term_err:
                log.exception(
                    f"Error during command process termination for PID {pid}: {term_err}"
                )
        self._process = None  # Clear handle

    async def stop(self):
        """Signals the backend's running task to stop and terminates the managed process if any."""
        if not self._should_stop.is_set():
            log.info(f"Signalling backend {self.__class__.__name__} to stop.")
            self._should_stop.set()
            # Also terminate the process if run_command started one
            await self._terminate_process()
        else:
            log.debug(f"Backend {self.__class__.__name__} stop already signalled.")

    @property
    def should_stop(self) -> bool:
        """Check if the stop event has been set."""
        return self._should_stop.is_set()
