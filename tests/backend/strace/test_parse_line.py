# Filename: tests/backend/strace/test_parse_line.py
"""Pytest tests for the strace pyparsing parser defined in parser_defs.py"""

import pyparsing as pp  # For ParseException
import pytest

# Adjust import path based on your project structure
# Import the stricter parse_line function
from lsoph.backend.strace.parser_defs import parse_line


# --- Helper Function to Check Args ---
# Extracts parsed values (int, str, or bytes)
def assert_parsed_args(parsed_results, expected_args_list):
    """Asserts that the parsed arguments match the expected list."""
    parsed_args_list_extracted = []
    # Access args directly from the 'syscall_complete' group
    syscall_data = parsed_results.get("syscall_complete")

    if syscall_data and "args" in syscall_data and syscall_data.args:
        for arg_group in syscall_data.args:  # Iterate through the list of groups
            # Each arg_group is the result of matching 'param'
            # It will be a Group containing either [key, parsed_value] or [parsed_value]
            if isinstance(arg_group, pp.ParseResults):
                if len(arg_group) == 2:  # key=value pair
                    # Append the parsed value (arg_group[1])
                    parsed_args_list_extracted.append(arg_group[1])
                elif len(arg_group) == 1:  # Standalone value
                    # Append the parsed value (arg_group[0])
                    parsed_args_list_extracted.append(arg_group[0])
                else:  # Unexpected structure
                    pytest.fail(
                        f"Unexpected argument group structure: {arg_group.dump()}"
                    )
            else:  # Should not happen if param definition uses Group always
                pytest.fail(f"Unexpected argument type in results: {type(arg_group)}")

    # Compare the extracted values (which can be int, str, or bytes) with the expected list
    assert (
        parsed_args_list_extracted == expected_args_list
    ), f"Expected {expected_args_list!r} but got {parsed_args_list_extracted!r}"


# --- Test Functions for Successful Parsing ---


def test_parse_simple_read():
    """Tests parsing a basic 'read' syscall line."""
    line = '1855516 read(0, "\\r", 1) = 1'
    parsed = parse_line(line)
    assert parsed.pid == 1855516
    assert parsed.syscall_complete.syscall == "read"
    # Expect integers for FD/count, bytes for buffer
    assert_parsed_args(parsed, [0, b"\r", 1])  # Expect bytes b'\r'
    assert parsed.syscall_complete.result_val == 1
    assert parsed.syscall_complete.get("error_part") is None
    assert parsed.syscall_complete.get("timing_part") is None


def test_parse_write_newline():
    """Tests parsing a basic 'write' syscall with newline escape."""
    line = '1855516 write(2, "\\n", 1) = 1'
    parsed = parse_line(line)
    assert parsed.pid == 1855516
    assert parsed.syscall_complete.syscall == "write"
    # Expect integers for FD/count, bytes for buffer
    assert_parsed_args(parsed, [2, b"\n", 1])  # Expect bytes b'\n'
    assert parsed.syscall_complete.result_val == 1


def test_parse_write_with_hex_escapes():
    """Tests parsing a 'write' syscall with \\xHH escapes."""
    line = '1855516 write(2, "\\x1b\\x5b\\x3f\\x32\\x30\\x30\\x34\\x6c\\x0d", 9) = 9'
    parsed = parse_line(line)
    assert parsed.pid == 1855516
    assert parsed.syscall_complete.syscall == "write"
    # Expect integers for FD/count, bytes for buffer (escapes interpreted)
    # Correctly interpreted bytes for \x1b[?2004l\r
    expected_bytes = b"\x1b[?2004l\r"
    assert_parsed_args(parsed, [2, expected_bytes, 9])  # Expect interpreted bytes
    assert parsed.syscall_complete.result_val == 9


def test_parse_clone_key_value_args():
    """Tests parsing 'clone' with key=value arguments and flags."""
    line = "1855516 clone(child_stack=NULL, flags=CLONE_CHILD_CLEARTID|CLONE_CHILD_SETTID|SIGCHLD, child_tidptr=0x7ac60eccda10) = 2150465"
    parsed = parse_line(line)
    assert parsed.pid == 1855516
    assert parsed.syscall_complete.syscall == "clone"
    # Expect strings for NULL/flags (with pipes preserved), integer for pointer
    assert_parsed_args(
        parsed,
        [
            "NULL",  # child_stack value (str)
            "CLONE_CHILD_CLEARTID|CLONE_CHILD_SETTID|SIGCHLD",  # flags value (str with pipes)
            0x7AC60ECCDA10,  # child_tidptr value (parsed as int)
        ],
    )
    assert parsed.syscall_complete.result_val == 2150465


def test_parse_simple_close():
    """Tests parsing a basic 'close' syscall."""
    line = "1855516 close(3) = 0"
    parsed = parse_line(line)
    assert parsed.pid == 1855516
    assert parsed.syscall_complete.syscall == "close"
    assert_parsed_args(parsed, [3])  # Expect integer FD
    assert parsed.syscall_complete.result_val == 0


def test_parse_access_with_error():
    """Tests parsing 'access' with an ENOENT error."""
    line = '2150465 access("\\x2f\\x65\\x74\\x63\\x2f\\x6c\\x64\\x2e\\x73\\x6f\\x2e\\x70\\x72\\x65\\x6c\\x6f\\x61\\x64", R_OK) = -1 ENOENT (No such file or directory)'
    parsed = parse_line(line)
    assert parsed.pid == 2150465
    assert parsed.syscall_complete.syscall == "access"
    # Expect bytes path (escapes interpreted), string mode
    expected_path_bytes = b"/etc/ld.so.preload"
    assert_parsed_args(parsed, [expected_path_bytes, "R_OK"])  # Expect bytes path
    assert parsed.syscall_complete.result_val == -1
    assert "error_part" in parsed.syscall_complete
    assert parsed.syscall_complete.error_part[0] == "ENOENT"
    assert parsed.syscall_complete.error_part[1] == "No such file or directory"


def test_parse_openat_with_flags():
    """Tests parsing 'openat' with flags."""
    line = '2150465 openat(AT_FDCWD, "\\x2f\\x65\\x74\\x63\\x2f\\x6c\\x64\\x2e\\x73\\x6f\\x2e\\x63\\x61\\x63\\x68\\x65", O_RDONLY|O_CLOEXEC) = 3'
    parsed = parse_line(line)
    assert parsed.pid == 2150465
    assert parsed.syscall_complete.syscall == "openat"
    # Expect string AT_FDCWD, bytes path (escapes interpreted), string flags (with pipes)
    expected_path_bytes = b"/etc/ld.so.cache"
    assert_parsed_args(
        parsed, ["AT_FDCWD", expected_path_bytes, "O_RDONLY|O_CLOEXEC"]
    )  # Expect bytes path
    assert parsed.syscall_complete.result_val == 3


def test_parse_fork_no_args():
    """Tests parsing 'fork' with no arguments."""
    line = "1234 fork() = 1235"
    parsed = parse_line(line)
    assert parsed.pid == 1234
    assert parsed.syscall_complete.syscall == "fork"
    assert_parsed_args(parsed, [])  # Expect empty args list
    assert parsed.syscall_complete.result_val == 1235


def test_parse_stat_with_struct_and_timing():
    """Tests parsing 'stat' with a struct and timing info."""
    line = '5678 stat("/etc/hosts", {st_mode=S_IFREG|0644, st_size=212, ...}) = 0 <0.000015>'
    parsed = parse_line(line)
    assert parsed.pid == 5678
    assert parsed.syscall_complete.syscall == "stat"
    # Expect bytes path, bytes for struct
    assert_parsed_args(
        parsed,
        [
            b"/etc/hosts",  # Expect bytes path
            b"{st_mode=S_IFREG|0644, st_size=212, ...}",  # Expect bytes struct
        ],
    )
    assert parsed.syscall_complete.result_val == 0
    assert "error_part" not in parsed.syscall_complete
    assert "timing_part" in parsed.syscall_complete
    assert parsed.syscall_complete.timing_part[0] == 0.000015  # Timing is float


def test_parse_getpid_no_args():
    """Tests parsing 'getpid' with no arguments."""
    line = "222 getpid() = 222"
    parsed = parse_line(line)
    assert parsed.pid == 222
    assert parsed.syscall_complete.syscall == "getpid"
    assert_parsed_args(parsed, [])
    assert parsed.syscall_complete.result_val == 222


def test_parse_openat_with_mode():
    """Tests parsing 'openat' with flags and a numeric mode."""
    line = '444 openat(AT_FDCWD, "/dev/null", O_WRONLY|O_CREAT|O_TRUNC, 0666) = 3'
    parsed = parse_line(line)
    assert parsed.pid == 444
    assert parsed.syscall_complete.syscall == "openat"
    # Expect strings for AT_FDCWD, flags; bytes for path; integer for mode
    assert_parsed_args(
        parsed,
        [
            "AT_FDCWD",
            b"/dev/null",  # Expect bytes path
            "O_WRONLY|O_CREAT|O_TRUNC",
            438,  # Expect decimal int (0666 octal)
        ],
    )
    assert parsed.syscall_complete.result_val == 3


def test_parse_exit_group_question_mark():
    """Tests parsing 'exit_group' with '?' result."""
    line = "111 exit_group(0) = ?"
    parsed = parse_line(line)
    assert parsed.pid == 111
    assert parsed.syscall_complete.syscall == "exit_group"
    assert_parsed_args(parsed, [0])  # Expect integer arg
    assert parsed.syscall_complete.result_val == "?"  # Compare string result '?'


def test_parse_line_no_pid():
    """Tests parsing a line where the PID might be missing (handled by context)."""
    line = 'read(0, "\\r", 1) = 1'
    parsed = parse_line(line)
    assert "pid" not in parsed  # PID should not be present in the parsed result
    assert parsed.syscall_complete.syscall == "read"
    # Expect integers for FD/count, bytes for buffer
    assert_parsed_args(parsed, [0, b"\r", 1])  # Expect bytes b'\r'
    assert parsed.syscall_complete.result_val == 1


# --- NEW TESTS ---


def test_parse_fstat_with_struct():
    """Tests parsing fstat with a struct result."""
    line = "12345 fstat(3, {st_mode=S_IFREG|0644, st_size=1024, ...}) = 0"
    parsed = parse_line(line)
    assert parsed.pid == 12345
    assert parsed.syscall_complete.syscall == "fstat"
    # Expect int FD, bytes struct
    assert_parsed_args(parsed, [3, b"{st_mode=S_IFREG|0644, st_size=1024, ...}"])
    assert parsed.syscall_complete.result_val == 0  # Result is int


def test_parse_unlink_success():
    """Tests parsing a successful unlink."""
    line = '12345 unlink("/tmp/myfile.txt") = 0'
    parsed = parse_line(line)
    assert parsed.pid == 12345
    assert parsed.syscall_complete.syscall == "unlink"
    assert_parsed_args(parsed, [b"/tmp/myfile.txt"])  # Path is bytes
    assert parsed.syscall_complete.result_val == 0  # Result is int


def test_parse_renameat_success():
    """Tests parsing a successful renameat."""
    line = '12345 renameat(AT_FDCWD, "old.txt", AT_FDCWD, "new.txt") = 0'
    parsed = parse_line(line)
    assert parsed.pid == 12345
    assert parsed.syscall_complete.syscall == "renameat"
    # Expect strings for AT_FDCWD, bytes for paths
    assert_parsed_args(parsed, ["AT_FDCWD", b"old.txt", "AT_FDCWD", b"new.txt"])
    assert parsed.syscall_complete.result_val == 0  # Result is int


def test_parse_mmap_hex_result():
    """Tests parsing mmap with a hex pointer result."""
    # Note: mmap args can be complex, this is a simplified example
    line = "12345 mmap(NULL, 4096, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0) = 0x7f1234567000"
    parsed = parse_line(line)
    assert parsed.pid == 12345
    assert parsed.syscall_complete.syscall == "mmap"
    # Expect NULL string, integers for size, fd, offset; string for flags (with pipes)
    assert_parsed_args(
        parsed,
        ["NULL", 4096, "PROT_READ|PROT_WRITE", "MAP_PRIVATE|MAP_ANONYMOUS", -1, 0],
    )
    assert parsed.syscall_complete.result_val == 0x7F1234567000  # Result is int


def test_parse_syscall_with_only_pid():
    """Tests that a line with only a PID fails parsing (needs syscall body)."""
    line = "12345 "
    with pytest.raises(pp.ParseException):
        parse_line(line)


# --- Tests for lines that should fail with the stricter parser ---


def test_fail_signal_line():
    """Signal lines should NOT be parsed by the stricter parse_line."""
    line = "111 --- SIGINT {si_signo=SIGINT, si_code=SI_KERNEL} ---"
    with pytest.raises(pp.ParseException):
        parse_line(line)


def test_fail_exit_summary_line():
    """Exit summary lines should NOT be parsed by the stricter parse_line."""
    line = "111 +++ exited with 0 +++"
    with pytest.raises(pp.ParseException):
        parse_line(line)


def test_fail_invalid_format():
    """Completely invalid lines should fail."""
    line = "invalid line format"
    with pytest.raises(pp.ParseException):
        parse_line(line)


def test_fail_no_paren():
    """Lines missing parentheses should fail."""
    line = "123 syscall_no_paren = 1"
    with pytest.raises(pp.ParseException):
        parse_line(line)


def test_fail_mismatched_paren():
    """Lines with mismatched parentheses should fail."""
    line = "456 syscall_mismatched(paren = 0"
    with pytest.raises(pp.ParseException):
        parse_line(line)


def test_fail_unfinished_line():
    """Unfinished lines should NOT be parsed by the stricter parse_line."""
    line = "111 read(3, <unfinished ...>"
    with pytest.raises(pp.ParseException):
        parse_line(line)


def test_fail_resumed_line():
    """Resumed lines should NOT be parsed by the stricter parse_line."""
    line = '111 <... read resumed>"data...", 1024) = 512'
    with pytest.raises(pp.ParseException):
        parse_line(line)


def test_parse_newfstatat_with_struct():
    """Tests parsing newfstatat with a struct and a filename with spaces."""
    line = '75036 newfstatat(8, "Met O 12c Technical Note", {st_mode=S_IFDIR|0775, st_size=4096, ...}, AT_SYMLINK_NOFOLLOW) = 0'
    parsed = parse_line(line)
    assert parsed.pid == 75036
    assert parsed.syscall_complete.syscall == "newfstatat"
    # Expect int fd, bytes path, bytes struct, string flag
    assert_parsed_args(
        parsed,
        [
            8,  # fd (int)
            b"Met O 12c Technical Note",  # path (bytes)
            b"{st_mode=S_IFDIR|0775, st_size=4096, ...}",  # struct (bytes)
            "AT_SYMLINK_NOFOLLOW",  # flag (str)
        ],
    )
    assert parsed.syscall_complete.result_val == 0


def test_parse_statfs_with_struct():
    """Tests parsing statfs with a struct containing various fields."""
    line = '12345 statfs("/mnt/data", {f_type=0x65735546, f_bsize=4096, f_blocks=2621440, f_bfree=1234567, ...}) = 0'
    parsed = parse_line(line)
    assert parsed.pid == 12345
    assert parsed.syscall_complete.syscall == "statfs"
    # Expect bytes path, bytes struct
    assert_parsed_args(
        parsed,
        [
            b"/mnt/data",  # path (bytes)
            b"{f_type=0x65735546, f_bsize=4096, f_blocks=2621440, f_bfree=1234567, ...}",  # struct (bytes)
        ],
    )
    assert parsed.syscall_complete.result_val == 0


def test_parse_empty_struct():
    """Tests parsing a call with an empty struct."""
    line = "12345 some_syscall({}) = 0"
    parsed = parse_line(line)
    assert parsed.pid == 12345
    assert parsed.syscall_complete.syscall == "some_syscall"
    # Expect bytes empty struct
    assert_parsed_args(parsed, [b"{}"])  # empty struct (bytes)
    assert parsed.syscall_complete.result_val == 0


def test_parse_minimal_struct():
    """Tests parsing a call with a minimal struct containing just one field."""
    line = "12345 some_syscall({value=123}) = 0"
    parsed = parse_line(line)
    assert parsed.pid == 12345
    assert parsed.syscall_complete.syscall == "some_syscall"
    # Expect bytes struct
    assert_parsed_args(parsed, [b"{value=123}"])  # simple struct (bytes)
    assert parsed.syscall_complete.result_val == 0


def test_parse_newfstatat_with_struct():
    """Tests parsing newfstatat with a struct and a filename with spaces."""
    line = '75036 newfstatat(8, "Met O 12c Technical Note", {st_mode=S_IFDIR|0775, st_size=4096, ...}, AT_SYMLINK_NOFOLLOW) = 0'
    parsed = parse_line(line)
    assert parsed.pid == 75036
    assert parsed.syscall_complete.syscall == "newfstatat"
    # Expect int fd, bytes path, bytes struct, string flag

    # Extract all args manually to debug the issue
    syscall_data = parsed.get("syscall_complete")
    all_args = []

    if syscall_data and "args" in syscall_data and syscall_data.args:
        for arg_group in syscall_data.args:
            if isinstance(arg_group, pp.ParseResults):
                if len(arg_group) == 2:  # key=value pair
                    all_args.append(arg_group[1])
                elif len(arg_group) == 1:  # Standalone value
                    all_args.append(arg_group[0])

    # Print each arg for debugging
    print("\nDEBUG - Args in newfstatat:")
    for i, arg in enumerate(all_args):
        print(f"  Arg {i}: {arg!r} (type: {type(arg)})")

    # Now do the normal assertions
    assert_parsed_args(
        parsed,
        [
            8,  # fd (int)
            b"Met O 12c Technical Note",  # path (bytes)
            b"{st_mode=S_IFDIR|0775, st_size=4096, ...}",  # struct (bytes)
            "AT_SYMLINK_NOFOLLOW",  # flag (str)
        ],
    )
    assert parsed.syscall_complete.result_val == 0


def test_parse_empty_struct():
    """Tests parsing a call with an empty struct."""
    line = "12345 some_syscall({}) = 0"
    parsed = parse_line(line)

    # Extract and print for debugging
    syscall_data = parsed.get("syscall_complete")
    all_args = []

    if syscall_data and "args" in syscall_data and syscall_data.args:
        for arg_group in syscall_data.args:
            if isinstance(arg_group, pp.ParseResults):
                if len(arg_group) == 2:  # key=value pair
                    all_args.append(arg_group[1])
                elif len(arg_group) == 1:  # Standalone value
                    all_args.append(arg_group[0])

    # Print each arg for debugging
    print("\nDEBUG - Args in empty struct:")
    for i, arg in enumerate(all_args):
        print(f"  Arg {i}: {arg!r} (type: {type(arg)})")

    assert parsed.pid == 12345
    assert parsed.syscall_complete.syscall == "some_syscall"
    # Expect bytes empty struct
    assert_parsed_args(parsed, [b"{}"])  # empty struct (bytes)
    assert parsed.syscall_complete.result_val == 0


def test_parse_minimal_struct():
    """Tests parsing a call with a minimal struct containing just one field."""
    line = "12345 some_syscall({value=123}) = 0"
    parsed = parse_line(line)

    # Extract and print for debugging
    syscall_data = parsed.get("syscall_complete")
    all_args = []

    if syscall_data and "args" in syscall_data and syscall_data.args:
        for arg_group in syscall_data.args:
            if isinstance(arg_group, pp.ParseResults):
                if len(arg_group) == 2:  # key=value pair
                    all_args.append(arg_group[1])
                elif len(arg_group) == 1:  # Standalone value
                    all_args.append(arg_group[0])

    # Print each arg for debugging
    print("\nDEBUG - Args in minimal struct:")
    for i, arg in enumerate(all_args):
        print(f"  Arg {i}: {arg!r} (type: {type(arg)})")

    assert parsed.pid == 12345
    assert parsed.syscall_complete.syscall == "some_syscall"
    # Expect bytes struct
    assert_parsed_args(parsed, [b"{value=123}"])  # simple struct (bytes)
    assert parsed.syscall_complete.result_val == 0
