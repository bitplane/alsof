# Filename: src/lsoph/backend/strace/terminate.py
"""Contains logic for terminating the strace process."""

import asyncio
import logging

log = logging.getLogger(__name__)  # Use module-specific logger


async def terminate_strace_process(
    process: asyncio.subprocess.Process | None, pid: int
):
    """Helper to terminate the strace process robustly."""
    # Check if process exists and is running
    if not process or process.returncode is not None:
        return
    log.warning(f"Attempting to terminate strace process (PID: {pid})...")
    stderr_bytes = b""  # To store stderr

    try:
        # Send SIGTERM first for graceful shutdown
        log.debug(f"Sending SIGTERM to strace process {pid}")
        process.terminate()
        # Wait for termination and capture stderr
        try:
            # Use communicate() to read stderr and wait for process exit
            # Note: If strace generates a LOT of output on termination, this might block
            #       but it's generally safer than just waiting for exit code.
            _, stderr_bytes = await asyncio.wait_for(process.communicate(), timeout=1.5)
        except asyncio.TimeoutError:
            # If timeout occurs, process didn't terminate gracefully
            log.warning(
                f"Strace process {pid} did not exit after SIGTERM, sending SIGKILL."
            )
            raise  # Re-raise timeout to trigger the kill block below
        except Exception as comm_err:
            # Handle errors during communication (e.g., broken pipe)
            log.error(
                f"Error communicating with strace process {pid} during terminate: {comm_err}"
            )
            # Assume process is stuck, proceed to kill
            raise asyncio.TimeoutError  # Treat as timeout to trigger kill

        # Log successful termination
        log.info(
            f"Strace process {pid} terminated gracefully (SIGTERM, code {process.returncode})."
        )
        # Log stderr if the exit code was non-zero OR if there was output
        # (useful even on graceful exit if strace prints attach/detach messages)
        if stderr_bytes:
            log.info(  # Changed to info level as attach/detach is normal
                f"Strace {pid} stderr (exit {process.returncode}):\n{stderr_bytes.decode('utf-8', 'replace').strip()}"
            )
        return  # Successful termination

    except ProcessLookupError:
        # Process already exited before we could terminate
        log.warning(f"Strace process {pid} already exited before SIGTERM.")
        return
    except asyncio.TimeoutError:
        # SIGTERM timed out, proceed to SIGKILL in the next block
        pass
    except Exception as term_err:
        # Catch other errors during SIGTERM attempt
        log.exception(f"Error during SIGTERM for strace {pid}: {term_err}")

    # --- SIGKILL Block ---
    # This block executes if SIGTERM timed out or failed
    if process.returncode is None:
        try:
            log.debug(f"Sending SIGKILL to strace process {pid}")
            process.kill()
            # Wait briefly for kill and try to capture remaining stderr
            try:
                _, stderr_bytes = await asyncio.wait_for(
                    process.communicate(), timeout=1.0
                )
            except asyncio.TimeoutError:
                log.error(f"Strace process {pid} did not exit even after SIGKILL!")
            except Exception as comm_err:
                log.error(
                    f"Error communicating with strace process {pid} after kill: {comm_err}"
                )

            log.info(
                f"Strace process {pid} killed (SIGKILL, code {process.returncode})."
            )
            # Log any captured stderr after kill
            if stderr_bytes:
                log.warning(
                    f"Strace {pid} stderr (after kill, exit {process.returncode}):\n{stderr_bytes.decode('utf-8', 'replace').strip()}"
                )

        except ProcessLookupError:
            log.warning(f"Strace process {pid} already exited before SIGKILL.")
        except Exception as kill_err:
            log.exception(f"Error during SIGKILL for strace {pid}: {kill_err}")
