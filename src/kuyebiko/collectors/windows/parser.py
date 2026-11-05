import struct
from dataclasses import dataclass

from kuyebiko.collectors.models import WindowsFileAction
from kuyebiko.core.exceptions import BufferParseError

HEADER_SIZE = 12  # NextEntryOffset (4) + Action (4) + FileNameLength (4)


@dataclass(frozen=True, slots=True)
class ParsedNotification:
    """Parsed filesystem notification item from FILE_NOTIFY_INFORMATION."""

    action: WindowsFileAction
    relative_path: str


def parse_file_notify_information(
    buffer: bytes | memoryview | bytearray,
    bytes_count: int,
) -> list[ParsedNotification]:
    """Parse raw bytes returned by ReadDirectoryChangesW into structured notifications.

    Args:
        buffer: The raw memory buffer containing FILE_NOTIFY_INFORMATION entries.
        bytes_count: The number of valid bytes written by the OS.

    Returns:
        list[ParsedNotification]: Ordered list of parsed notifications.

    Raises:
        BufferParseError: If the buffer is truncated, offsets are out-of-bounds,
            or contains invalid action/length fields.
    """
    if bytes_count < 0 or bytes_count > len(buffer):
        raise BufferParseError(
            f"Invalid bytes_count {bytes_count}: must be within [0, {len(buffer)}]"
        )

    if bytes_count == 0:
        return []

    if bytes_count < HEADER_SIZE:
        raise BufferParseError(
            f"Buffer truncated: received {bytes_count} bytes, "
            f"minimum header is {HEADER_SIZE} bytes"
        )

    view = memoryview(buffer)[:bytes_count]
    entries: list[ParsedNotification] = []
    offset = 0
    total_len = len(view)

    while offset < total_len:
        if offset + HEADER_SIZE > total_len:
            raise BufferParseError(
                f"Buffer truncated at offset {offset}: "
                f"remaining bytes {total_len - offset} < {HEADER_SIZE}"
            )

        next_entry_offset, action_raw, filename_length = struct.unpack_from(
            "<III", view, offset
        )

        # Validate action
        try:
            action = WindowsFileAction(action_raw)
        except ValueError as err:
            raise BufferParseError(
                f"Invalid Windows file action value: {action_raw} at offset {offset}"
            ) from err

        # Validate filename length (must be non-zero and multiple of 2 for UTF-16LE)
        if filename_length == 0:
            raise BufferParseError(f"Invalid zero-length filename at offset {offset}")

        if filename_length % 2 != 0:
            raise BufferParseError(
                f"Odd-byte filename length {filename_length} "
                f"for UTF-16LE at offset {offset}"
            )

        name_start = offset + HEADER_SIZE
        name_end = name_start + filename_length

        if name_end > total_len:
            raise BufferParseError(
                f"Filename length {filename_length} "
                f"exceeds buffer boundary at offset {offset}"
            )

        filename_bytes = bytes(view[name_start:name_end])
        try:
            filename = filename_bytes.decode("utf-16-le")
        except UnicodeDecodeError as err:
            raise BufferParseError(
                f"Failed to decode UTF-16LE filename at offset {offset}: {err}"
            ) from err

        # Clean and normalize path
        normalized = filename.replace("\\", "/")
        if normalized.startswith("/"):
            raise BufferParseError(
                f"Absolute path rejected at offset {offset}: '{filename}'"
            )

        if not normalized:
            raise BufferParseError(
                f"Empty relative path after normalization at offset {offset}"
            )

        entries.append(
            ParsedNotification(
                action=action,
                relative_path=normalized,
            )
        )

        # Check next entry offset
        if next_entry_offset == 0:
            break

        if next_entry_offset < HEADER_SIZE or next_entry_offset % 4 != 0:
            raise BufferParseError(
                f"Malformed NextEntryOffset {next_entry_offset} "
                f"at offset {offset} (unaligned or too small)"
            )

        if offset + next_entry_offset >= total_len:
            raise BufferParseError(
                f"NextEntryOffset {next_entry_offset} "
                f"exceeds total buffer size {total_len}"
            )

        offset += next_entry_offset

    return entries
