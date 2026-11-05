import struct

import pytest

from kuyebiko.collectors.models import WindowsFileAction
from kuyebiko.collectors.windows.parser import (
    ParsedNotification,
    parse_file_notify_information,
)
from kuyebiko.core.exceptions import BufferParseError


def make_entry(next_offset: int, action: int, filename: str) -> bytes:
    """Construct a binary FILE_NOTIFY_INFORMATION entry."""
    encoded_name = filename.encode("utf-16-le")
    header = struct.pack("<III", next_offset, action, len(encoded_name))
    entry = header + encoded_name
    # Align to 4 bytes if next_offset > 0
    if next_offset > len(entry):
        entry += b"\x00" * (next_offset - len(entry))
    return entry


def test_parse_empty_buffer():
    result = parse_file_notify_information(b"", 0)
    assert result == []


def test_parse_truncated_buffer_header():
    with pytest.raises(BufferParseError, match="Buffer truncated"):
        parse_file_notify_information(b"\x00" * 8, 8)


def test_parse_single_valid_entry():
    raw = make_entry(0, 1, "test_file.txt")
    notifications = parse_file_notify_information(raw, len(raw))

    assert len(notifications) == 1
    assert notifications[0] == ParsedNotification(
        action=WindowsFileAction.ADDED,
        relative_path="test_file.txt",
    )


def test_parse_multiple_entries_in_one_buffer():
    name1 = "file_one.txt"
    name2 = "nested/file_two.docx"
    name3 = "deleted_three.pdf"

    # Compute 4-byte aligned offset for entry 1 and entry 2
    raw_e1_len = 12 + len(name1.encode("utf-16-le"))
    offset1 = (raw_e1_len + 3) & ~3

    raw_e2_len = 12 + len(name2.encode("utf-16-le"))
    offset2 = (raw_e2_len + 3) & ~3

    e1 = make_entry(offset1, WindowsFileAction.ADDED, name1)
    e2 = make_entry(offset2, WindowsFileAction.MODIFIED, name2)
    e3 = make_entry(0, WindowsFileAction.REMOVED, name3)

    buffer = e1 + e2 + e3
    notifications = parse_file_notify_information(buffer, len(buffer))

    assert len(notifications) == 3
    assert notifications[0].action == WindowsFileAction.ADDED
    assert notifications[0].relative_path == "file_one.txt"

    assert notifications[1].action == WindowsFileAction.MODIFIED
    assert notifications[1].relative_path == "nested/file_two.docx"

    assert notifications[2].action == WindowsFileAction.REMOVED
    assert notifications[2].relative_path == "deleted_three.pdf"


def test_parse_all_five_actions():
    actions = [
        (WindowsFileAction.ADDED, "a.txt"),
        (WindowsFileAction.REMOVED, "b.txt"),
        (WindowsFileAction.MODIFIED, "c.txt"),
        (WindowsFileAction.RENAMED_OLD_NAME, "old.txt"),
        (WindowsFileAction.RENAMED_NEW_NAME, "new.txt"),
    ]

    for action_enum, fname in actions:
        raw = make_entry(0, int(action_enum), fname)
        parsed = parse_file_notify_information(raw, len(raw))
        assert len(parsed) == 1
        assert parsed[0].action == action_enum
        assert parsed[0].relative_path == fname


def test_parse_unicode_and_non_ascii_filenames():
    # Japanese (Kuyebiko), Cyrillic, accented, and emojis
    unicode_names = [
        "久延毘古.txt",
        "документ_2026.pdf",
        "rapport_financier_décembre.xlsx",
        "ransomware_analysis_🔒.log",
    ]

    for name in unicode_names:
        raw = make_entry(0, WindowsFileAction.MODIFIED, name)
        parsed = parse_file_notify_information(raw, len(raw))
        assert len(parsed) == 1
        assert parsed[0].relative_path == name


def test_parse_normalizes_windows_backslashes():
    raw = make_entry(0, WindowsFileAction.ADDED, "subfolder\\nested\\doc.txt")
    parsed = parse_file_notify_information(raw, len(raw))
    assert len(parsed) == 1
    assert parsed[0].relative_path == "subfolder/nested/doc.txt"


def test_parse_rejects_invalid_action_value():
    raw = make_entry(0, 999, "invalid_action.txt")
    with pytest.raises(BufferParseError, match="Invalid Windows file action"):
        parse_file_notify_information(raw, len(raw))


def test_parse_rejects_zero_length_filename():
    header = struct.pack("<III", 0, 1, 0)
    with pytest.raises(BufferParseError, match="zero-length filename"):
        parse_file_notify_information(header, len(header))


def test_parse_rejects_odd_byte_filename_length():
    header = struct.pack("<III", 0, 1, 7) + b"1234567"
    with pytest.raises(BufferParseError, match="Odd-byte filename length"):
        parse_file_notify_information(header, len(header))


def test_parse_rejects_filename_exceeding_buffer():
    header = struct.pack("<III", 0, 1, 100) + b"short"
    with pytest.raises(BufferParseError, match="exceeds buffer boundary"):
        parse_file_notify_information(header, len(header))


def test_parse_rejects_unaligned_next_entry_offset():
    # NextEntryOffset not multiple of 4
    encoded_name = "test.txt".encode("utf-16-le")
    raw = struct.pack("<III", 15, 1, len(encoded_name)) + encoded_name + b"\x00" * 10
    with pytest.raises(BufferParseError, match="unaligned"):
        parse_file_notify_information(raw, len(raw))


def test_parse_rejects_next_offset_exceeding_buffer():
    encoded_name = "test.txt".encode("utf-16-le")
    raw = struct.pack("<III", 500, 1, len(encoded_name)) + encoded_name
    with pytest.raises(BufferParseError, match="exceeds total buffer size"):
        parse_file_notify_information(raw, len(raw))


def test_parse_rejects_malformed_utf16_surrogate():
    # An unpaired high surrogate 0xD800 without low surrogate
    malformed_utf16 = b"\x00\xd8"
    header = struct.pack("<III", 0, 1, len(malformed_utf16)) + malformed_utf16
    with pytest.raises(BufferParseError, match="Failed to decode UTF-16LE"):
        parse_file_notify_information(header, len(header))


def test_parse_rejects_negative_bytes_count():
    with pytest.raises(BufferParseError, match="must be within"):
        parse_file_notify_information(b"\x00" * 32, -1)


def test_parse_rejects_bytes_count_exceeding_buffer():
    with pytest.raises(BufferParseError, match="must be within"):
        parse_file_notify_information(b"\x00" * 32, 64)


def test_parse_rejects_leading_slash_path():
    raw = make_entry(0, WindowsFileAction.ADDED, "/root_path/file.txt")
    with pytest.raises(BufferParseError, match="Absolute path rejected"):
        parse_file_notify_information(raw, len(raw))


def test_parse_rejects_leading_backslash_path():
    raw = make_entry(0, WindowsFileAction.ADDED, "\\Windows\\System32\\cmd.exe")
    with pytest.raises(BufferParseError, match="Absolute path rejected"):
        parse_file_notify_information(raw, len(raw))
