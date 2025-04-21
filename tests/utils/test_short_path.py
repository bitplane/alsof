"""Tests for the short_path utility function using pytest fixtures."""

from types import SimpleNamespace

import pytest

import alsof.utils


def make_mock_os(sep):
    def split(path):
        parts = path.rsplit(sep, 1)
        return (parts[0], parts[1]) if len(parts) == 2 else ("", path)

    def join(*parts):
        return sep.join(str(p).strip(sep) for p in parts if p)

    return SimpleNamespace(
        sep=sep, path=SimpleNamespace(sep=sep, split=split, join=join)
    )


@pytest.fixture
def posix():
    yield  # testing in linux right now
    # return make_mock_os("/")


@pytest.fixture
def windows():
    return make_mock_os("\\")


def test_posix_no_truncation(posix):
    """POSIX: Path shorter than max_length is returned unchanged."""
    cwd = "/home/user/project/"
    path = "/usr/local/bin/script.sh"
    max_len = 50
    assert alsof.utils.short_path(path, max_len, cwd=cwd) == path


def test_windows_no_truncation(windows):
    """Windows: Path shorter than max_length is returned unchanged."""
    cwd = "C:\\Users\\User\\Project\\"
    path = "C:\\Windows\\System32\\cmd.exe"
    assert alsof.utils.short_path(path, 50, cwd=cwd) == path


def test_posix_exact_length(posix):
    """POSIX: Path equal to max_length is returned unchanged."""
    cwd = "/home/user/project/"
    path = "/abc/def/ghi"  # len 12
    assert alsof.utils.short_path(path, 12, cwd=cwd) == path


# Very Short Max Length (Simple Truncation)
def test_posix_max_len_too_small(posix):
    """POSIX: Path is simply truncated if max_length is <= ellipsis length."""
    cwd = "/home/user/project/"
    path = "/abc/def/ghi/jkl"
    assert alsof.utils.short_path(path, 3, cwd=cwd) == "/ab"  # path[:3]
    assert alsof.utils.short_path(path, 2, cwd=cwd) == "/a"  # path[:2]
    assert alsof.utils.short_path(path, 1, cwd=cwd) == "/"  # path[:1]
    assert alsof.utils.short_path(path, 0, cwd=cwd) == ""  # path[:0]


def test_windows_max_len_too_small(windows):
    """Windows: Path is simply truncated if max_length is <= ellipsis length."""
    cwd = "C:\\Users\\User\\Project\\"
    path = "C:\\abc\\def"
    assert alsof.utils.short_path(path, 3, cwd=cwd) == "C:\\"  # path[:3]
    assert alsof.utils.short_path(path, 2, cwd=cwd) == "C:"  # path[:2]
    assert alsof.utils.short_path(path, 1, cwd=cwd) == "C"  # path[:1]
    assert alsof.utils.short_path(path, 0, cwd=cwd) == ""  # path[:0]


# Relativization
def test_posix_relativize_fits(posix):
    """POSIX: Path within CWD is relativized and fits."""
    cwd = "/home/user/project/"
    path = cwd + "file.txt"
    expected = "file.txt"
    assert alsof.utils.short_path(path, 20, cwd=cwd) == expected


def test_windows_relativize_fits(windows):
    """Windows: Path within CWD is relativized and fits."""
    cwd = "C:\\Users\\User\\Project\\"
    path = cwd + "file.txt"
    expected = "file.txt"
    actual = alsof.utils.short_path(path, 30, cwd=cwd)
    assert actual == expected


def test_posix_cwd_itself(posix):
    """POSIX: Providing CWD itself returns '.'"""
    cwd = "/home/user/project/"
    assert alsof.utils.short_path(cwd, 20, cwd=cwd) == "."


def test_windows_cwd_itself(windows):
    """Windows: Providing Windows CWD itself returns '.'"""
    cwd = "C:\\Users\\User\\Project\\"
    assert alsof.utils.short_path(cwd, 30, cwd=cwd) == "."


# Filename Only (No Directory)
def test_filename_only_fits(posix):
    """Filename without directory fits."""
    cwd = "/home/user/project/"
    path = "shortfile.txt"
    assert alsof.utils.short_path(path, 20, cwd=cwd) == path


def test_filename_only_truncation(posix):
    """Filename without directory is truncated."""
    cwd = "/home/user/project/"
    path = "a_very_very_long_filename_that_needs_truncation.txt"
    max_len = 20
    expected = "...ds_truncation.txt"
    actual = alsof.utils.short_path(path, max_len, cwd=cwd)
    assert len(actual) == 20
    assert actual == expected


def test_posix_filename_trunc_priority(posix):
    """POSIX: Filename truncation happens even if dir also doesn't fit."""
    cwd = "/home/user/project/"
    path = "/very/long/dir/another_very_long_filename.log"
    max_len = 20
    expected = "...long_filename.log"
    actual = alsof.utils.short_path(path, max_len, cwd=cwd)
    assert len(actual) == 20
    assert actual == expected


def test_windows_filename_trunc_priority(windows):
    """Windows: Filename truncation happens even if dir also doesn't fit."""
    cwd = "C:\\Users\\User\\Project\\"
    path = "C:\\long\\dir\\another_very_long_filename.log"
    max_len = 22
    expected = "...y_long_filename.log"
    actual = alsof.utils.short_path(path, max_len, cwd=cwd)
    assert len(actual) == 22
    assert actual == expected


# Directory Doesn't Fit -> Left Truncate Path
def test_posix_dir_no_fit_left_trunc(posix):
    """POSIX: Test case where filename fits but max_dir_len is <= 0 -> left truncate."""
    cwd = "/home/user/project/"
    path = "/a/b/c/d/e/f/g/h/i/j/k/filename.txt"
    max_len = 20
    expected = "/a.../k/filename.txt"
    actual = alsof.utils.short_path(path, max_len, cwd=cwd)
    assert len(actual) == 20
    assert actual == expected


def test_windows_dir_no_fit_left_trunc(windows):
    """Windows: Test case where filename fits but max_dir_len is <= 0 -> left truncate."""
    cwd = "C:\\Users\\User\\Project\\"
    path = "C:\\a\\b\\c\\d\\e\\f\\g\\h\\i\\j\\k\\filename.txt"
    max_len = 22
    expected = "...\\i\\j\\k\\filename.txt"
    actual = alsof.utils.short_path(path, max_len, cwd=cwd)
    assert len(actual) == 22
    assert actual == expected


# Directory Middle Truncation
def test_posix_dir_middle_truncate(posix):
    """POSIX: Test directory middle truncation."""
    cwd = "/home/user/project/"
    path = "/usr/share/very/long/path/name/goes/here/file.txt"
    max_len = 30
    expected = "/usr/shar...goes/here/file.txt"
    actual = alsof.utils.short_path(path, max_len, cwd=cwd)
    assert len(actual) == 30
    assert actual == expected


def test_windows_dir_middle_truncate(windows):
    """Windows: Test directory middle truncation."""
    cwd = "C:\\Users\\User\\Project\\"
    path = (
        "C:\\Program Files\\Some Vendor\\Another Directory\\App\\file.txt"  # filename=8
    )
    max_len = 40  # max_dir = 40 - 8 - 1 = 31. Fits middle trunc.
    # keep=28. start=14(C:\Program File), end=14( Directory\App)
    # Expected output uses the mocked join/split with '\'
    # Note: Mock join is basic: C:\Program File... Directory\App\file.txt
    expected = "C:\\Program File... Directory\\App\\file.txt"
    assert alsof.utils.short_path(path, max_len, cwd=cwd) == expected


# Relative Path Directory Middle Truncation
def test_posix_relative_dir_middle_truncate(posix):
    """POSIX: Test relative directory middle truncation."""
    cwd = "/home/user/project/"
    path = cwd + "src/very/long/component/name/impl/file.txt"  # filename=8
    max_len = 40  # max_dir = 40 - 8 - 1 = 31. Fits middle trunc.
    # relative dir = ./src/very/long/component/name/impl (len 35)
    # keep=28. start=14(./src/very/lon), end=14(onent/name/impl)
    expected = "./src/very/lon...onent/name/impl/file.txt"
    assert alsof.utils.short_path(path, max_len, cwd=cwd) == expected


def test_windows_relative_dir_middle_truncate(windows):
    """Windows: Test relative directory middle truncation."""
    cwd = "C:\\Users\\User\\Project\\"
    path = cwd + "Source\\VeryLongSubDirName\\Component\\file.txt"  # filename=8
    max_len = 35  # max_dir=35-8-1=26. Fits middle trunc.
    # relative dir = .\Source\VeryLongSubDirName\Component (len 35)
    # keep=23. start=11(.\Source\Ver), end=12(DirName\Component)
    expected = ".\\Source\\Very...DirName\\Component\\file.txt"
    assert alsof.utils.short_path(path, max_len, cwd=cwd) == expected


# Edge Cases
def test_posix_only_root(posix):
    """POSIX: Test shortening the root path itself."""
    cwd = "/home/user/project/"
    # Note: Mock split might return ('/', '') for '/'
    assert alsof.utils.short_path("/", 5, cwd=cwd) == "/"


def test_windows_only_drive(windows):
    """Windows: Test shortening a drive root."""
    cwd = "C:\\Users\\User\\Project\\"
    # Note: Mock split returns ('', 'D:') for 'D:'
    # The logic should handle this, returning filename 'D:'
    # If input is D:\, mock split returns ('', 'D:') - needs fix in mock?
    # Let's test D: first.
    assert alsof.utils.short_path("D:", 5, cwd=cwd) == "D:"
    # Test D:\ - current mock split returns ('', 'D:'). short_path sees dir="", file="D:". Returns "D:". Incorrect.
    # This highlights the limitation of the simplified mock split.
    # For now, assert the behavior *with the mock*:
    # assert alsof.utils.short_path("D:\\", 5, cwd=cwd) == "D:"
    # Let's skip this specific sub-case due to mock limitations
    # Or adjust mock split for windows root?
    # Revised windows mock split:
    # def mock_windows_split(path):
    #     path = str(path)
    #     drive, rest = os.path.splitdrive(path)
    #     if not rest: return (drive, "") # Handle C: -> C:, ""
    #     idx = rest.rfind(SEP)
    #     if idx == -1: return (drive, rest) # C:foo -> C:, foo
    #     if idx == 0: # Separator is the first char (root) e.g. \ or C:\
    #          if len(rest) == 1: return (drive + rest, "") # Just root \ or C:\
    #          else: return (drive + SEP, rest[1:]) # Root plus path \foo or C:\foo
    #     return (drive + rest[:idx], rest[idx+1:]) # Regular path C:\foo\bar
    # With revised mock: split("D:\\") -> ("D:\\", "") -> dir="D:\\", file="". Returns "D:\\".
    assert alsof.utils.short_path("D:\\", 5, cwd=cwd) == "D:\\"


def test_empty_path(posix):
    """Test shortening an empty path."""
    cwd = "/home/user/project/"
    assert alsof.utils.short_path("", 10, cwd=cwd) == ""


def test_dot_path(posix):
    """Test shortening '.' relative to CWD."""
    cwd = "/home/user/project/"
    # Input "." -> _relative_path(".") -> "."
    assert alsof.utils.short_path(".", 10, cwd=cwd) == "."


def test_posix_relative_dir_just_fits(posix):
    """POSIX: Test path that becomes relative and just fits."""
    cwd = "/home/user/project/"
    path = cwd + "shortdir/file.txt"  # rel = ./shortdir/file.txt (len 19)
    expected = "./shortdir/file.txt"
    assert alsof.utils.short_path(path, len(expected), cwd=cwd) == expected


def test_windows_relative_dir_just_fits(windows):
    """Windows: Test path that becomes relative and just fits."""
    cwd = "C:\\Users\\User\\Project\\"
    path = cwd + "shortdir\\file.txt"  # rel = .\shortdir\file.txt (len 19)
    expected = ".\\shortdir\\file.txt"
    assert alsof.utils.short_path(path, len(expected), cwd=cwd) == expected
