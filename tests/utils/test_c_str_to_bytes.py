"""
Tests for the c_str_to_bytes utility function.
"""

import pytest

from lsoph.util.string import c_str_to_bytes


def test_hex_escapes():
    """Test that hex escapes are properly converted."""
    assert c_str_to_bytes("\\x41\\x42\\x43") == b"ABC"
    # Control characters
    assert c_str_to_bytes("\\x00\\x01\\x02") == b"\x00\x01\x02"
    # Full byte range
    assert c_str_to_bytes("\\xFF\\xFE\\xFD") == b"\xff\xfe\xfd"


def test_common_escapes():
    """Test that common escapes are properly converted."""
    assert c_str_to_bytes("\\n") == b"\n"
    assert c_str_to_bytes("\\r") == b"\r"
    assert c_str_to_bytes("\\t") == b"\t"
    assert c_str_to_bytes("\\\\") == b"\\"
    assert c_str_to_bytes('\\"') == b'"'
    assert c_str_to_bytes("\\'") == b"'"


def test_octal_escapes():
    """Test that octal escapes are properly converted."""
    assert c_str_to_bytes("\\0") == b"\0"  # Null byte
    assert c_str_to_bytes("\\1\\2\\3") == b"\1\2\3"
    assert c_str_to_bytes("\\177") == b"\177"  # Octal 177 = 127 decimal


def test_mixed_content():
    """Test strings with a mix of escapes and regular characters."""
    assert c_str_to_bytes("hello\\nworld") == b"hello\nworld"
    assert c_str_to_bytes("abc\\x20def") == b"abc def"
    assert c_str_to_bytes("\\t\\r\\n\\\\") == b"\t\r\n\\"


def test_empty_string():
    """Test empty string handling."""
    assert c_str_to_bytes("") == b""


def test_strace_examples():
    """Test specific examples from strace output."""
    # Examples from the failing tests
    assert (
        c_str_to_bytes("\\x1b\\x5b\\x3f\\x32\\x30\\x30\\x34\\x6c\\x0d")
        == b"\x1b[?2004l\r"
    )
    assert (
        c_str_to_bytes(
            "\\x2f\\x65\\x74\\x63\\x2f\\x6c\\x64\\x2e\\x73\\x6f\\x2e\\x70\\x72\\x65\\x6c\\x6f\\x61\\x64"
        )
        == b"/etc/ld.so.preload"
    )
    assert (
        c_str_to_bytes(
            "\\x2f\\x65\\x74\\x63\\x2f\\x6c\\x64\\x2e\\x73\\x6f\\x2e\\x63\\x61\\x63\\x68\\x65"
        )
        == b"/etc/ld.so.cache"
    )


def test_backslash_at_end():
    """Test that a backslash at the end is handled correctly."""
    with pytest.raises(UnicodeDecodeError):
        # This should fail because a trailing backslash is invalid
        c_str_to_bytes("abc\\")


def test_malformed_escape():
    """Test handling of malformed escapes."""
    with pytest.raises(UnicodeDecodeError):
        # Incomplete hex escape
        c_str_to_bytes("\\x4")
