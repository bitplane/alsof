# Filename: src/lsoph/backend/strace/parser_defs.py
"""
Defines the pyparsing grammar for strace syscall output lines.
- Quoted strings -> bytes (escapes interpreted via c_str_to_bytes)
- Structs -> bytes
- Numbers (dec, hex, octal) -> int
- Flags, Constants (AT_FDCWD, NULL) -> str
- Unquoted identifiers -> str
"""

import logging
import re
from typing import Any, Dict, List, Optional

import pyparsing as pp
from pyparsing import pyparsing_common as ppc

from lsoph.util.string import c_str_to_bytes

log = logging.getLogger(__name__)


def convert_raw_string_to_bytes(tokens):
    """Convert quoted string tokens to bytes using c_str_to_bytes utility."""
    # The token might include the quotes, remove them if present
    s = tokens[0]
    if s.startswith('"') and s.endswith('"'):
        s = s[1:-1]

    try:
        result = c_str_to_bytes(s)
        return result
    except Exception as e:
        log.error(f"Error converting string to bytes: {e}, input: {s!r}")
        return s.encode("utf-8")


def convert_struct_to_bytes(tokens):
    """Convert struct content to bytes."""
    struct_text = tokens[0]

    # Make sure we have a string
    if not isinstance(struct_text, str):
        struct_text = str(struct_text)

    # Make sure the struct has braces
    if not struct_text.startswith("{"):
        struct_text = "{" + struct_text
    if not struct_text.endswith("}"):
        struct_text = struct_text + "}"

    return struct_text.encode("utf-8")


# Basic elements
LPAREN, RPAREN, LBRACE, RBRACE, LT, GT, EQ, COMMA, PIPE = map(pp.Suppress, "(){}<>=,|")

# Numeric types
integer = ppc.signed_integer
hex_integer = pp.Combine("0x" + pp.Word(pp.hexnums)).setParseAction(
    lambda t: int(t[0], 16)
)
octal_integer = pp.Combine("0" + pp.Word("01234567", min=1)).setParseAction(
    lambda t: int(t[0], 8) if len(t[0]) > 1 else int(t[0])
)
number = hex_integer | octal_integer | integer

# Basic identifiers
pid = integer.copy().setResultsName("pid")
syscall_name = pp.Word(pp.alphas + "_", pp.alphanums + "_").setResultsName("syscall")

# Strings - custom approach to preserve raw string exactly as it appears
QUOTE = pp.Literal('"').suppress()
STRING_CONTENT = pp.SkipTo('"', include=False, ignore=pp.Literal('\\"'))
quoted_string = (QUOTE + STRING_CONTENT + QUOTE).setParseAction(
    convert_raw_string_to_bytes
)

# Structs to bytes
struct_content = pp.Forward()
struct_content << pp.SkipTo("}", include=True)
struct = (LBRACE + struct_content).setParseAction(convert_struct_to_bytes)

# Constants and flags parsing
at_fdcwd = pp.Literal("AT_FDCWD")
null_ptr = pp.Literal("NULL") | pp.Literal("(null)")
flags_expr = pp.originalTextFor(
    pp.Word(pp.alphas + "_", pp.alphanums + "_")
    + pp.ZeroOrMore(PIPE + pp.Word(pp.alphas + "_", pp.alphanums + "_"))
)
identifier = pp.Word(pp.alphas + "_/", pp.alphanums + "_/.-")

# Pointers (hex addresses)
pointer = hex_integer.copy()

# Parameter values
param_value = pp.Forward()
param_value << (
    struct
    | quoted_string
    | flags_expr
    | at_fdcwd
    | null_ptr
    | pointer
    | identifier
    | number
)

# Parameter parsing
key = pp.Word(pp.alphas + "_", pp.alphanums + "_")
key_value_pair = pp.Group(key + EQ + param_value)
param = key_value_pair | pp.Group(param_value)

pp.ParserElement.setDefaultWhitespaceChars(" \t")
param_list = pp.Optional(pp.delimitedList(param, delim=COMMA)).setResultsName("args")

# Result parsing
result_val = (number | pp.Literal("?")).setResultsName("result_val")

error_name = pp.Word(pp.alphas + "_", pp.alphanums + "_").setResultsName("error_name")
error_msg_content = pp.SkipTo(")", failOn=pp.Literal(")")).setResultsName("error_msg")
error_part = pp.Group(error_name + LPAREN + error_msg_content + RPAREN).setResultsName(
    "error_part"
)

timing_val = ppc.real.copy().setResultsName("timing")
timing_part = pp.Group(LT + timing_val + GT).setResultsName("timing_part")

# Complete syscall line
syscall_body = (
    syscall_name
    + LPAREN
    + param_list
    + RPAREN
    + EQ
    + result_val
    + pp.Optional(error_part)
    + pp.Optional(timing_part)
)

# Full line parser
full_line_parser = (
    pp.Optional(pid)
    + pp.Group(syscall_body).setResultsName("syscall_complete")
    + pp.StringEnd()
)

full_line_parser.parseWithTabs()

# Separate parser for resumed suffixes
resumed_suffix_parser = (
    EQ
    + result_val
    + pp.Optional(error_part)
    + pp.Optional(timing_part)
    + pp.StringEnd()
)


def parse_line(line_str: str) -> pp.ParseResults:
    """
    Parse a single strace line into structured data.

    This parser only handles complete syscall lines (not unfinished/resumed lines or signals).

    Args:
        line_str: A line from strace output

    Returns:
        ParseResults object with structured data:
        - pid: Process ID (int)
        - syscall_complete: Group containing:
          - syscall: Syscall name (str)
          - args: List of arguments (each can be bytes, str, or int)
          - result_val: Return value (int or '?')
          - error_part: Optional error info
          - timing_part: Optional timing info

    Raises:
        ParseException: If the line doesn't match the expected format
    """
    return full_line_parser.parseString(line_str, parseAll=True)
