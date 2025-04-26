# Filename: src/lsoph/backend/strace/terminate.py
"""Contains logic for terminating the strace process."""

import asyncio
import logging

log = logging.getLogger(__name__)


async def terminate_strace_process(
    process: asyncio.subprocess.Process | None, pid: int
):
    """Helper to terminate the strace process robustly."""
    # Check if process exists and is running
    if not process or process.returncode is not None:
        return

    log.warning(f"Attempting to terminate strace process (PID: {pid})...")
    stderr_bytes = b""

    try:
        # Send SIGTERM first for graceful shutdown
        log.debug(f"Sending SIGTERM to strace process {pid}")
        process.terminate()

        # Wait for termination and capture stderr
        try:
            _, stderr_bytes = await asyncio.wait_for(process.communicate(), timeout=1.5)
        except asyncio.TimeoutError:
            # Process didn't terminate gracefully
            log.warning(
                f"Strace process {pid} did not exit after SIGTERM, sending SIGKILL."
            )
            raise  # Re-raise timeout to trigger SIGKILL
        except Exception as comm_err:
            log.error(f"Error during strace terminate: {comm_err}")
            # Treat as timeout to trigger SIGKILL
            raise asyncio.TimeoutError

        log.info(
            f"Strace process {pid} terminated gracefully (code {process.returncode})."
        )
        if stderr_bytes:
            log.info(
                f"Strace {pid} stderr (exit {process.returncode}):\n"
                f"{stderr_bytes.decode('utf-8', 'replace').strip()}"
            )
        return

    except ProcessLookupError:
        log.warning(f"Strace process {pid} already exited before SIGTERM.")
        return
    except asyncio.TimeoutError:
        # SIGTERM timed out, proceed to SIGKILL
        pass
    except Exception as term_err:
        log.exception(f"Error during SIGTERM for strace {pid}: {term_err}")

    # SIGKILL block - executes if SIGTERM timed out or failed
    if process.returncode is None:
        try:
            log.debug(f"Sending SIGKILL to strace process {pid}")
            process.kill()

            # Wait briefly for kill and capture remaining stderr
            try:
                _, stderr_bytes = await asyncio.wait_for(
                    process.communicate(), timeout=1.0
                )
            except asyncio.TimeoutError:
                log.error(f"Strace process {pid} did not exit even after SIGKILL!")
            except Exception as comm_err:
                log.error(f"Error communicating with strace after kill: {comm_err}")

            log.info(f"Strace process {pid} killed (code {process.returncode}).")
            if stderr_bytes:
                log.warning(
                    f"Strace {pid} stderr (after kill):\n"
                    f"{stderr_bytes.decode('utf-8', 'replace').strip()}"
                )

        except ProcessLookupError:
            log.warning(f"Strace process {pid} already exited before SIGKILL.")
        except Exception as kill_err:
            log.exception(f"Error during SIGKILL for strace {pid}: {kill_err}")
