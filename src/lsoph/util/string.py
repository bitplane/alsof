"""
String manipulation utilities for LSOPH.
"""

import codecs


def c_str_to_bytes(s: str) -> bytes:
    """
    Convert a C-style string with escapes like \\n, \\t, \\xHH, \\0NNN to bytes.

    This is particularly useful for parsing strace output with escaped strings.

    Args:
        s: A string containing C-style escapes

    Returns:
        bytes: The decoded bytes corresponding to the string with escapes interpreted

    Examples:
        >>> c_str_to_bytes('\\x41\\x42\\x43')
        b'ABC'
        >>> c_str_to_bytes('hello\\nworld')
        b'hello\nworld'
        >>> c_str_to_bytes('\\t\\r\\n\\\\')
        b'\t\r\n\\'
    """
    # Use unicode_escape to decode C-style escapes into a string
    intermediate = codecs.decode(s, "unicode_escape")

    # Then encode to bytes using latin-1 to preserve all byte values
    # latin-1 (ISO-8859-1) is a perfect 1:1 mapping between unicode points 0-255 and bytes
    return intermediate.encode("latin-1")
