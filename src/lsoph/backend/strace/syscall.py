# Filename: src/lsoph/backend/strace/syscall.py
"""
Common definitions for strace parsing, like the Syscall dataclass.
Allows different parser implementations to use the same structure.
"""
import os
import time
from dataclasses import dataclass, field
from typing import Any, List, Optional

# Syscalls sets for faster lookup
PROCESS_SYSCALLS = {"clone", "fork", "vfork"}
EXIT_SYSCALLS = {"exit", "exit_group"}
RESUME_SYSCALLS = {"rt_sigreturn", "sigreturn"}


@dataclass
class Syscall:
    """Represents a parsed strace syscall event."""

    pid: int
    syscall: str
    args: List[Any] = field(default_factory=list)
    result_str: str | None = None
    result_int: int | None = None
    child_pid: int | None = None
    error_name: str | None = None
    error_msg: str | None = None
    timing: float | None = None
    timestamp: float = field(default_factory=time.time)
    raw_line: bytes = b""

    @property
    def success(self) -> bool:
        """Determine if the syscall was successful (no error reported)."""
        if self.error_name:
            return False
        if self.result_int == -1 and not self.error_name:
            return False
        return True

    def __repr__(self) -> str:
        """Provide a concise string representation for logging."""
        err_part = f" ERR={self.error_name}" if self.error_name else ""
        child_part = f" CHILD={self.child_pid}" if self.child_pid else ""

        # Convert args to strings before joining
        args_str_list = []
        for arg in self.args[:2]:  # Only include up to first 2 args
            args_str_list.append(str(arg))

        args_repr = ", ".join(args_str_list) + ("..." if len(self.args) > 2 else "")

        # Use result_str which handles int or '?' representation
        ret_val = self.result_str if self.result_str is not None else ""

        return (
            f"Syscall(pid={self.pid}, ts={self.timestamp:.3f}, "
            f"call={self.syscall}({args_repr}), ret={ret_val}{err_part}{child_part})"
        )
