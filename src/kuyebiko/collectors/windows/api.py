import ctypes
import sys
from ctypes import wintypes
from typing import Any

# Operating System Access Flags
FILE_LIST_DIRECTORY = 0x0001

# Share Modes
FILE_SHARE_READ = 0x0001
FILE_SHARE_WRITE = 0x0002
FILE_SHARE_DELETE = 0x0004

# Creation Disposition
OPEN_EXISTING = 3

# Flags and Attributes
FILE_FLAG_BACKUP_SEMANTICS = 0x02000000

# Notification Filters
FILE_NOTIFY_CHANGE_FILE_NAME = 0x00000001
FILE_NOTIFY_CHANGE_DIR_NAME = 0x00000002
FILE_NOTIFY_CHANGE_ATTRIBUTES = 0x00000004
FILE_NOTIFY_CHANGE_SIZE = 0x00000008
FILE_NOTIFY_CHANGE_LAST_WRITE = 0x00000010
FILE_NOTIFY_CHANGE_CREATION = 0x00000040

DEFAULT_NOTIFY_FILTER = (
    FILE_NOTIFY_CHANGE_FILE_NAME
    | FILE_NOTIFY_CHANGE_DIR_NAME
    | FILE_NOTIFY_CHANGE_ATTRIBUTES
    | FILE_NOTIFY_CHANGE_SIZE
    | FILE_NOTIFY_CHANGE_LAST_WRITE
    | FILE_NOTIFY_CHANGE_CREATION
)

# Standard Windows Error Codes
ERROR_SUCCESS = 0
ERROR_ACCESS_DENIED = 5
ERROR_INVALID_HANDLE = 6
ERROR_OPERATION_ABORTED = 995
ERROR_NOTIFY_ENUM_DIR = 1022

# Buffer and Handle Bounds
DEFAULT_BUFFER_SIZE = 65536  # 64 KB alignment boundary
INVALID_HANDLE_VALUE = -1


def is_windows_platform() -> bool:
    """Return True if executing on a native Windows platform."""
    return sys.platform == "win32"


def is_valid_handle(handle: Any) -> bool:
    """Check whether a Windows handle is non-null and not INVALID_HANDLE_VALUE."""
    if handle is None:
        return False
    try:
        val = int(handle)
        return val != 0 and val != INVALID_HANDLE_VALUE and val != 0xFFFFFFFFFFFFFFFF
    except (TypeError, ValueError):
        return False


# Platform-conditional binding
if is_windows_platform():
    kernel32 = ctypes.windll.kernel32

    # CreateFileW
    _CreateFileW = kernel32.CreateFileW
    _CreateFileW.argtypes = [
        wintypes.LPCWSTR,
        wintypes.DWORD,
        wintypes.DWORD,
        ctypes.c_void_p,
        wintypes.DWORD,
        wintypes.DWORD,
        wintypes.HANDLE,
    ]
    _CreateFileW.restype = wintypes.HANDLE

    # ReadDirectoryChangesW
    _ReadDirectoryChangesW = kernel32.ReadDirectoryChangesW
    _ReadDirectoryChangesW.argtypes = [
        wintypes.HANDLE,
        wintypes.LPVOID,
        wintypes.DWORD,
        wintypes.BOOL,
        wintypes.DWORD,
        ctypes.POINTER(wintypes.DWORD),
        ctypes.c_void_p,
        ctypes.c_void_p,
    ]
    _ReadDirectoryChangesW.restype = wintypes.BOOL

    # CancelIoEx
    _CancelIoEx = kernel32.CancelIoEx
    _CancelIoEx.argtypes = [
        wintypes.HANDLE,
        ctypes.c_void_p,
    ]
    _CancelIoEx.restype = wintypes.BOOL

    # CloseHandle
    _CloseHandle = kernel32.CloseHandle
    _CloseHandle.argtypes = [wintypes.HANDLE]
    _CloseHandle.restype = wintypes.BOOL

    # GetLastError
    _GetLastError = kernel32.GetLastError
    _GetLastError.argtypes = []
    _GetLastError.restype = wintypes.DWORD
else:
    _CreateFileW = None
    _ReadDirectoryChangesW = None
    _CancelIoEx = None
    _CloseHandle = None
    _GetLastError = None


def open_directory_handle(
    path: str,
    share_mode: int = FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
) -> int:
    """Open a directory handle configured for ReadDirectoryChangesW."""
    if not is_windows_platform():
        raise RuntimeError("open_directory_handle is only supported on Windows")

    handle = _CreateFileW(
        str(path),
        FILE_LIST_DIRECTORY,
        share_mode,
        None,
        OPEN_EXISTING,
        FILE_FLAG_BACKUP_SEMANTICS,
        None,
    )
    if not is_valid_handle(handle):
        err = get_last_error()
        raise OSError(err, f"CreateFileW failed for '{path}' (WinError {err})")
    return handle


def read_directory_changes(
    handle: int,
    buffer: Any,
    buffer_length: int,
    recursive: bool,
    notify_filter: int = DEFAULT_NOTIFY_FILTER,
) -> tuple[bool, int, int]:
    """Execute a synchronous ReadDirectoryChangesW call.

    Returns:
        tuple[bool, int, int]: (success, bytes_returned, last_error_code)
    """
    if not is_windows_platform():
        raise RuntimeError("read_directory_changes is only supported on Windows")

    bytes_returned = wintypes.DWORD(0)
    success = bool(
        _ReadDirectoryChangesW(
            wintypes.HANDLE(handle),
            buffer,
            wintypes.DWORD(buffer_length),
            wintypes.BOOL(recursive),
            wintypes.DWORD(notify_filter),
            ctypes.byref(bytes_returned),
            None,
            None,
        )
    )
    error_code = get_last_error() if not success else ERROR_SUCCESS
    return success, bytes_returned.value, error_code


def cancel_io_for_handle(handle: int) -> bool:
    """Cancel all pending asynchronous and synchronous I/O on the handle."""
    if not is_windows_platform() or not is_valid_handle(handle):
        return False
    return bool(_CancelIoEx(wintypes.HANDLE(handle), None))


def close_directory_handle(handle: int) -> bool:
    """Close an open Windows handle."""
    if not is_windows_platform() or not is_valid_handle(handle):
        return False
    return bool(_CloseHandle(wintypes.HANDLE(handle)))


def get_last_error() -> int:
    """Retrieve the calling thread's last Windows error code."""
    if not is_windows_platform() or _GetLastError is None:
        return 0
    return int(_GetLastError())

