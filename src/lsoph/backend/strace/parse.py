# Filename: src/lsoph/backend/strace/parse.py
"""Contains logic for parsing strace output lines."""

import asyncio
import logging
import re
import time
from dataclasses import dataclass
from typing import TYPE_CHECKING, AsyncIterator, Dict, List, Optional

import psutil

from lsoph.monitor import Monitor

# Import the stream function from the new stream module
from .stream import stream_strace_output

# Use TYPE_CHECKING to avoid circular import for type hint
if TYPE_CHECKING:
    # Import StraceBackend only for type hinting
    from .backend import StraceBackend


log = logging.getLogger(__name__)

# Define constants needed by this module
PROCESS_SYSCALLS = ["clone", "fork", "vfork"]
EXIT_SYSCALLS = ["exit_group"]

STRACE_LINE_RE = re.compile(
    r"^(?P<tid>\d+)\s+"
    r"(?P<syscall>\w+)\("
    r"(?P<args>.*?)"
    r"\)\s+=\s+"
    r"(?P<result>-?\d+|\?|0x[\da-fA-F]+)"
    r"(?:\s+(?P<error>[A-Z_]+)\s+\((?P<errmsg>.*?)\))?"
    r"(?:\s+<(?P<tag>unfinished|resumed)\s+...>)?$"
)


@dataclass
class Syscall:
    """Represents a parsed strace syscall event."""

    timestamp: float
    tid: int
    pid: int
    syscall: str
    args: list[str]
    result_str: str
    error_name: Optional[str] = None
    error_msg: Optional[str] = None


def _parse_args_state_machine(args_str: str) -> list[str]:
    """Parses the complex argument string from strace output."""
    # (Implementation remains the same as in strace_cmd.py)
    args = []
    current_arg = ""
    nesting_level = 0
    in_quotes = False
    escape_next = False
    i = 0
    n = len(args_str)
    while i < n:
        char = args_str[i]
        append_char = True
        if escape_next:
            escape_next = False
        elif char == "\\":
            escape_next = True
        elif char == '"':
            in_quotes = not in_quotes
        elif not in_quotes:
            if char in ("(", "{", "["):
                nesting_level += 1
            elif char in (")", "}", "]"):
                nesting_level = max(0, nesting_level - 1)
            elif char == "," and nesting_level == 0:
                args.append(current_arg.strip())
                current_arg = ""
                append_char = False
        if append_char:
            current_arg += char
        i += 1
    args.append(current_arg.strip())
    return [arg for arg in args if arg]


async def parse_strace_stream(
    # Add backend instance parameter to accept the argument
    backend: "StraceBackend",
    monitor: Monitor,
    should_stop: asyncio.Event,
    target_command: Optional[list[str]] = None,
    attach_ids: Optional[list[int]] = None,
    syscalls: Optional[list[str]] = None,  # Made optional, default handled elsewhere
) -> AsyncIterator[Syscall]:
    """
    Asynchronously runs strace via stream_strace_output and parses lines into Syscall objects.
    """
    log.info("Starting async parse_strace_stream...")
    tid_to_pid_map: dict[int, int] = {}

    if attach_ids:
        log.info(f"Pre-populating TID->PID map for attach IDs: {attach_ids}")
        for initial_tid in attach_ids:
            try:
                if not psutil.pid_exists(initial_tid):
                    log.warning(
                        f"Initial attach TID {initial_tid} does not exist, skipping."
                    )
                    continue
                proc_info = psutil.Process(initial_tid)
                pid = proc_info.pid
                tid_to_pid_map[initial_tid] = pid
            except (psutil.NoSuchProcess, psutil.AccessDenied, Exception) as e:
                tid_to_pid_map[initial_tid] = initial_tid
                log.warning(
                    f"Error getting PID for initial TID {initial_tid}: {e}. Mapping TID to itself."
                )

    # Ensure essential syscalls are included (if syscalls list is provided)
    if syscalls:
        combined_syscalls = sorted(
            list(set(syscalls) | set(PROCESS_SYSCALLS) | set(EXIT_SYSCALLS))
        )
    else:
        # Handle case where syscalls might not be passed (though backend should ensure it)
        log.warning("parse_strace_stream called without explicit syscall list.")
        combined_syscalls = sorted(list(set(PROCESS_SYSCALLS) | set(EXIT_SYSCALLS)))

    try:
        # Pass backend instance down to stream_strace_output
        async for line in stream_strace_output(
            backend, monitor, should_stop, target_command, attach_ids, combined_syscalls
        ):
            if should_stop.is_set():
                break

            timestamp = time.time()
            match = STRACE_LINE_RE.match(line)
            if not match:
                if "attached" in line or "detached" in line:
                    log.debug(f"Ignoring strace message line: {line}")
                else:
                    log.warning(f"Ignoring non-matching strace line: {line}")
                continue

            data = match.groupdict()
            if data.get("tag") in ("unfinished", "resumed"):
                continue

            try:
                tid = int(data["tid"])
                syscall = data["syscall"]
                args_str = data["args"]
                result_str = data["result"]
                error_name = data.get("error")
                error_msg = data.get("errmsg")

                pid = tid_to_pid_map.get(tid)
                if pid is None:
                    try:
                        if psutil.pid_exists(tid):
                            proc_info = psutil.Process(tid)
                            pid = proc_info.pid
                            tid_to_pid_map[tid] = pid
                        else:
                            pid = tid
                            tid_to_pid_map[tid] = pid
                            log.warning(f"TID {tid} not found, using TID as PID.")
                    except (
                        psutil.NoSuchProcess,
                        psutil.AccessDenied,
                        Exception,
                    ) as map_e:
                        pid = tid
                        tid_to_pid_map[tid] = pid
                        log.warning(
                            f"Error looking up PID for TID {tid} ({map_e}), assuming PID=TID."
                        )

                parsed_args_list = _parse_args_state_machine(args_str)

                if syscall in PROCESS_SYSCALLS and error_name is None:
                    try:
                        new_id_str = result_str
                        new_id = (
                            int(new_id_str) if new_id_str and new_id_str != "?" else -1
                        )
                        if new_id > 0 and new_id not in tid_to_pid_map:
                            tid_to_pid_map[new_id] = pid
                            log.debug(
                                f"Mapped new process/thread TID {new_id} to parent PID {pid} based on {syscall}"
                            )
                    except (ValueError, TypeError) as proc_e:
                        log.error(
                            f"Error parsing result '{result_str}' for {syscall}: {proc_e}"
                        )
                elif syscall in EXIT_SYSCALLS:
                    if tid in tid_to_pid_map:
                        del tid_to_pid_map[tid]
                        log.debug(f"Removed TID {tid} from map due to {syscall}")

                yield Syscall(
                    timestamp=timestamp,
                    tid=tid,
                    pid=pid,
                    syscall=syscall,
                    args=parsed_args_list,
                    result_str=result_str,
                    error_name=error_name,
                    error_msg=error_msg,
                )
            except Exception as parse_exc:
                log.error(f"Error parsing matched line content: {line} -> {parse_exc}")

    except asyncio.CancelledError:
        log.info("Async strace parsing stream cancelled.")
    except Exception as stream_exc:
        log.exception(
            f"Error occurred in the async strace stream processing: {stream_exc}"
        )
        raise
    finally:
        log.info("Async parse_strace_stream finished.")
