# Filename: src/lsoph/backend/strace/syscall.py
"""
Common definitions for strace parsing, like the Syscall dataclass.
Allows different parser implementations (manual, pyparsing) to use the same structure.
"""
import os
import time
from dataclasses import dataclass, field
from typing import Any, List, Optional  # Use List from typing for 3.10+

# Syscalls indicating process creation/management
PROCESS_SYSCALLS = {"clone", "fork", "vfork"}  # Use set for faster lookup
# Syscalls indicating process termination
EXIT_SYSCALLS = {"exit", "exit_group"}  # Use set
# Syscalls indicating potential resumption after signal
RESUME_SYSCALLS = {"rt_sigreturn", "sigreturn"}  # Use set


@dataclass
class Syscall:
    """Represents a parsed strace syscall event."""

    pid: int
    syscall: str  # Syscall name is str
    # --- Args stored as parsed types (int/str) by pyparsing version ---
    args: List[Any] = field(default_factory=list)
    # -----------------------------------------------------------------
    result_str: str | None = None
    result_int: int | None = None
    child_pid: int | None = None
    error_name: str | None = None
    error_msg: str | None = None
    timing: float | None = None
    timestamp: float = field(default_factory=time.time)
    # Store raw bytes line for reference
    raw_line: bytes = b""

    @property
    def success(self) -> bool:
        """Determine if the syscall was successful (no error reported)."""
        if self.error_name:
            return False
        # Check result_int for standard C error convention (-1)
        # but only if error_name wasn't explicitly set (e.g., by ERESTARTSYS)
        if self.result_int == -1 and not self.error_name:
            return False
        # Consider other negative results potential errors if needed,
        # but -1 is the most common indicator alongside errno.
        return True

    def __repr__(self) -> str:
        """Provide a concise string representation for logging."""
        err_part = f" ERR={self.error_name}" if self.error_name else ""
        child_part = f" CHILD={self.child_pid}" if self.child_pid else ""

        # --- FIX: Convert args to string before joining ---
        args_str_list = [str(arg) for arg in self.args]
        args_repr = ", ".join(args_str_list[:2]) + (
            "..." if len(args_str_list) > 2 else ""
        )
        # --------------------------------------------------

        # Use result_str which handles int or '?' representation
        ret_val = self.result_str if self.result_str is not None else ""

        return f"Syscall(pid={self.pid}, ts={self.timestamp:.3f}, call={self.syscall}({args_repr}), ret={ret_val}{err_part}{child_part})"
