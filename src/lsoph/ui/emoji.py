# Filename: src/lsoph/ui/emoji.py
"""Generates emoji history strings for file activity."""

import logging
from typing import Any

from lsoph.monitor import FileInfo  # FileInfo.path is bytes

log = logging.getLogger("lsoph.ui.emoji")

# Mapping from simplified event types to single-width emojis
# Prioritize common file operations. Add more as needed.
# Ensure these render as single width in most modern terminals.
EVENT_EMOJI_MAP = {
    "OPEN": "📂",  # File Folder (Represents opening)
    "READ": "📖",  # Open Book (Represents reading)
    "WRITE": "💾",  # Floppy Disk (Represents writing/saving)
    # --- CHANGE: Changed back to Folder emoji for CLOSE ---
    "CLOSE": "📂",  # File Folder (Represents closing, matching OPEN)
    # ----------------------------------------------------
    "DELETE": "🗑️",  # Wastebasket (Represents deletion)
    "RENAME": "🔄",  # Arrows Counterclockwise (Represents renaming)
    "STAT": "👀",  # Eyes (Represents stat/access/lookup)
    "ACCESS": "👀",  # Group with STAT
    "CHDIR": "🗺️",  # Map (Represents changing directory context)
    "ERROR": "❗",  # Exclamation Mark (Represents an error state)
    # Add fallbacks or other types if necessary
    "UNKNOWN": "❔",  # Question Mark
}
DEFAULT_EMOJI = EVENT_EMOJI_MAP["UNKNOWN"]

# Special status overrides
STATUS_EMOJI_MAP = {
    "deleted": "❌",  # Cross Mark (Stronger indicator for deleted status)
    "error": "❗",  # Exclamation Mark
}


def get_emoji_history_string(file_info: FileInfo, max_len: int = 5) -> str:
    """
    Generates a string of emojis representing recent file activity history.
    Accepts FileInfo object (path attribute is bytes, but not used here).

    Args:
        file_info: The FileInfo object containing the event history.
        max_len: The maximum number of emojis to include in the string.

    Returns:
        A string of emojis (most recent first), padded with spaces.
    """
    # This function only uses status, is_open, and event_history from FileInfo.
    # It does not directly interact with the bytes path. No changes needed.

    if not file_info:
        return " " * max_len  # Return padding if no info

    # Check for overriding status first
    if file_info.status in STATUS_EMOJI_MAP:
        status_emoji = STATUS_EMOJI_MAP[file_info.status]
        return f"{status_emoji}{' ' * (max_len - 1)}"

    emojis = []
    processed_events = 0
    for event in reversed(file_info.event_history):
        if processed_events >= max_len:
            break

        event_type = str(event.get("type", "UNKNOWN")).upper()
        success = event.get("success", True)
        if not success:
            emoji = EVENT_EMOJI_MAP["ERROR"]
        else:
            emoji = EVENT_EMOJI_MAP.get(event_type, DEFAULT_EMOJI)

        # Avoid adding consecutive duplicates (e.g., multiple writes)
        if not emojis or emojis[-1] != emoji:
            emojis.append(emoji)
            processed_events += 1

    # If no history, show default
    if not emojis:
        emojis.append(DEFAULT_EMOJI)

    # Build the final string, padding with spaces if needed
    emoji_str = "".join(emojis)
    padding = " " * max(0, max_len - len(emoji_str))
    final_str = f"{emoji_str}{padding}"

    # Ensure the final string length is exactly max_len
    return final_str[:max_len]
