from types import SimpleNamespace

import pytest

import alsof.util.short_path
from alsof.util.short_path import short_path


def make_mock_os(sep):
    def split(path):
        parts = str(path).rsplit(sep, 1)
        return (parts[0], parts[1]) if len(parts) == 2 else ("", str(path))

    def join(*parts):
        return sep.join(str(p).strip(sep) for p in parts if p)

    path_ns = SimpleNamespace(sep=sep, split=split, join=join)
    return SimpleNamespace(sep=sep, path=path_ns)


@pytest.fixture
def posix(monkeypatch):
    mock_os = make_mock_os("/")
    monkeypatch.setattr(alsof.util.short_path, "os", mock_os)
    yield


@pytest.fixture
def windows(monkeypatch):
    mock_os = make_mock_os("\\")
    monkeypatch.setattr(alsof.util.short_path, "os", mock_os)
    yield


def test_cwd_itself(windows):
    """Returns '.' when path is exactly cwd"""
    cwd = "C:\\Users\\User\\Project\\"
    path = cwd
    max_len = 30
    actual = short_path(path, max_len, cwd=cwd)
    expected = "."
    assert actual == expected


def test_filename_only_fits(posix):
    """Returns short filename as-is if it fits"""
    cwd = "/home/user/project/"
    path = "shortfile.txt"
    max_len = 20
    actual = short_path(path, max_len, cwd=cwd)
    expected = "shortfile.txt"
    assert actual == expected


def test_filename_only_truncation(posix):
    """Truncates filename from the left if it exceeds max_length"""
    cwd = "/home/user/project/"
    path = "a_very_very_long_filename_that_needs_truncation.txt"
    max_len = 20
    actual = short_path(path, max_len, cwd=cwd)
    expected = "...ds_truncation.txt"
    assert len(actual) == max_len
    assert actual == expected


def test_middle_truncation(posix):
    """Truncates long directory in the middle and preserves filename"""
    cwd = "/home/user/project/"
    path = "/some/very/long/directory/structure/with/depth/file.txt"
    max_len = 30
    actual = short_path(path, max_len, cwd=cwd)
    expected = "/some/ver...ith/depth/file.txt"
    assert len(actual) == max_len
    assert actual == expected


def test_shrink_abs(posix):
    """Shrinking text"""
    cwd = "/home/user/project/"
    path = "/some/path/file.txt"
    assert short_path(path, 20, cwd=cwd) == "/some/path/file.txt"
    assert short_path(path, 19, cwd=cwd) == "/some/path/file.txt"
    assert short_path(path, 18, cwd=cwd) == "/so...ath/file.txt"
    assert short_path(path, 17, cwd=cwd) == "/s...ath/file.txt"
    assert short_path(path, 16, cwd=cwd) == "/s...th/file.txt"
    assert short_path(path, 15, cwd=cwd) == "/...th/file.txt"
    assert short_path(path, 14, cwd=cwd) == "/...h/file.txt"
    assert short_path(path, 13, cwd=cwd) == "...h/file.txt"
    assert short_path(path, 12, cwd=cwd) == ".../file.txt"
    assert short_path(path, 11, cwd=cwd) == "...file.txt"
    assert short_path(path, 10, cwd=cwd) == "...ile.txt"
    assert short_path(path, 9, cwd=cwd) == "...le.txt"
    assert short_path(path, 8, cwd=cwd) == "...e.txt"
    assert short_path(path, 7, cwd=cwd) == "....txt"
    assert short_path(path, 6, cwd=cwd) == "...txt"
    assert short_path(path, 5, cwd=cwd) == "...xt"
    assert short_path(path, 4, cwd=cwd) == "...t"
    assert short_path(path, 3, cwd=cwd) == "txt"
    assert short_path(path, 2, cwd=cwd) == "xt"
    assert short_path(path, 1, cwd=cwd) == "t"
    assert short_path(path, 0, cwd=cwd) == ""


def test_shrink_relative(windows):
    """shrink windows relative path"""
    cwd = "C:\\Users\\User\\Project\\"
    path = "C:\\Users\\User\\Project\\some\\path\\file.txt"
    assert short_path(path, 19, cwd=cwd) == r"some\path\file.txt"
    assert short_path(path, 18, cwd=cwd) == r"some\path\file.txt"
    assert short_path(path, 17, cwd=cwd) == r"so...ath\file.txt"
    assert short_path(path, 16, cwd=cwd) == r"so...th\file.txt"
    assert short_path(path, 15, cwd=cwd) == r"s...th\file.txt"
    assert short_path(path, 14, cwd=cwd) == r"s...h\file.txt"
    assert short_path(path, 13, cwd=cwd) == r"...h\file.txt"
    assert short_path(path, 12, cwd=cwd) == r"...\file.txt"
    assert short_path(path, 11, cwd=cwd) == r"...file.txt"
    assert short_path(path, 10, cwd=cwd) == r"...ile.txt"


def test_shrink_short(posix):
    """shrink short path"""
    cwd = "/etc"
    path = "/a/oof"
    assert short_path(path, 6, cwd=cwd) == "/a/oof"
    assert short_path(path, 5, cwd=cwd) == "...of"
    assert short_path(path, 4, cwd=cwd) == "...f"
