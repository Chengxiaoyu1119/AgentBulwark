"""Strict, atomic JSON persistence helpers for runtime control-plane data."""

from __future__ import annotations

import importlib
import json
import os
import tempfile
import time
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Iterator, Protocol, cast


class _FcntlModule(Protocol):
    LOCK_EX: int
    LOCK_NB: int
    LOCK_UN: int

    def flock(self, fd: int, operation: int) -> Any: ...


def _fcntl_module() -> _FcntlModule:
    """Load the POSIX-only module without breaking Windows type checking."""
    return cast(_FcntlModule, importlib.import_module("fcntl"))


def _reject_non_finite_json(value: str) -> None:
    """Reject JavaScript-style non-finite constants accepted by ``json``."""
    raise ValueError(f"JSON does not permit non-finite number {value!r}")


def decode_json_strict(raw: str | bytes | bytearray) -> Any:
    """Decode JSON while rejecting NaN, Infinity and -Infinity."""
    return json.loads(raw, parse_constant=_reject_non_finite_json)


def encode_json_strict(payload: Any, **kwargs: Any) -> str:
    """Encode JSON according to RFC 8259, never emitting non-finite numbers."""
    if "allow_nan" in kwargs:
        raise ValueError("allow_nan is fixed to False for runtime persistence")
    return json.dumps(payload, allow_nan=False, **kwargs)


def load_json_existing(path: Path) -> Any:
    """Load an existing JSON document and surface corruption/read failures."""
    return decode_json_strict(path.read_text(encoding="utf-8"))


def load_json(path: Path) -> Any | None:
    """Load a JSON document; malformed/unreadable documents return ``None``."""
    try:
        return load_json_existing(path)
    except (OSError, UnicodeError, json.JSONDecodeError, ValueError):
        return None


def save_json(path: Path, payload: Any) -> None:
    """Strictly encode and atomically replace ``path``.

    Encoding happens before creating the temporary file.  A rejected payload
    therefore leaves both the previous file and the directory free of partial
    ``.tmp`` artifacts.
    """
    encoded = encode_json_strict(payload, ensure_ascii=False, indent=2)
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary_path: Path | None = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="w",
            encoding="utf-8",
            dir=path.parent,
            prefix=f".{path.name}.",
            suffix=".tmp",
            delete=False,
        ) as handle:
            temporary_path = Path(handle.name)
            handle.write(encoded)
            handle.flush()
            os.fsync(handle.fileno())
        temporary_path.replace(path)
        # POSIX requires syncing the containing directory for the rename itself
        # to survive a sudden restart.  Windows does not expose directory file
        # descriptors through ``os.open``; the flushed file plus atomic replace
        # is the strongest portable primitive available here.
        if os.name != "nt":
            directory_fd = os.open(path.parent, os.O_RDONLY)
            try:
                os.fsync(directory_fd)
            finally:
                os.close(directory_fd)
    finally:
        if temporary_path is not None:
            try:
                temporary_path.unlink(missing_ok=True)
            except OSError:
                pass


def _lock_handle(handle: Any) -> None:
    """Acquire byte zero of an already-open coordination handle."""
    handle.seek(0)
    if os.name == "nt":
        import msvcrt

        msvcrt_api = cast(Any, msvcrt)
        msvcrt_api.locking(handle.fileno(), msvcrt_api.LK_NBLCK, 1)
    else:
        fcntl = _fcntl_module()
        fcntl.flock(handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)


def _try_lock_handle(handle: Any) -> bool:
    try:
        _lock_handle(handle)
    except (BlockingIOError, OSError):
        return False
    return True


def _unlock_handle(handle: Any) -> None:
    handle.seek(0)
    if os.name == "nt":
        import msvcrt

        msvcrt_api = cast(Any, msvcrt)
        msvcrt_api.locking(handle.fileno(), msvcrt_api.LK_UNLCK, 1)
    else:
        fcntl = _fcntl_module()
        fcntl.flock(handle.fileno(), fcntl.LOCK_UN)


@contextmanager
def exclusive_file_lock(path: Path, *, timeout_seconds: float = 15.0) -> Iterator[None]:
    """Hold an OS-level lock associated with ``path`` across processes.

    The lock file is intentionally retained after release; removing it while a
    second process has it open would permit a new process to lock a different
    inode. Operating-system lock ownership releases it on process exit.
    """
    lock_path = path.parent / f".{path.name}.lock"
    lock_path.parent.mkdir(parents=True, exist_ok=True)
    deadline = time.monotonic() + max(0.1, float(timeout_seconds))
    # ``msvcrt.locking`` needs a byte that already exists on some Windows
    # filesystems.  Initialising that byte from every process with ``a+b``
    # creates a race: one process can acquire byte 0 while another is still
    # flushing its first byte.  Serialize only this one-time initialization
    # with an O_EXCL marker *and an OS lock on that marker*.  The marker lock is
    # important for crash recovery: if a process dies after creating the marker
    # but before seeding the stable lock inode, a later process can acquire the
    # released marker lock and finish initialization instead of timing out
    # forever on a stale marker.
    # Keep the marker's ``.lock`` suffix so runtime backup discovery treats a
    # crash-left marker as control-plane metadata rather than user data.
    init_path = lock_path.with_name(f"{lock_path.name}.init.lock")
    while True:
        try:
            if lock_path.stat().st_size >= 1:
                break
        except FileNotFoundError:
            pass
        initializer_handle = None
        initializer_acquired = False
        init_fd = -1
        try:
            init_fd = os.open(init_path, os.O_CREAT | os.O_EXCL | os.O_RDWR)
            os.write(init_fd, b"0")
            os.lseek(init_fd, 0, os.SEEK_SET)
            initializer_handle = os.fdopen(init_fd, "r+b", buffering=0)
            init_fd = -1
        except FileExistsError:
            try:
                # A previous initializer may have crashed.  Opening its
                # marker and taking the marker lock distinguishes an orphaned
                # marker from an active initializer without relying on a
                # wall-clock lease or a potentially reused PID.
                initializer_handle = init_path.open("r+b", buffering=0)
            except (FileNotFoundError, PermissionError, OSError):
                initializer_handle = None
        except (PermissionError, OSError):
            initializer_handle = None
        finally:
            if init_fd >= 0:
                os.close(init_fd)

        if initializer_handle is not None:
            try:
                initializer_acquired = _try_lock_handle(initializer_handle)
                if initializer_acquired:
                    if not lock_path.exists() or lock_path.stat().st_size == 0:
                        with lock_path.open("ab") as lock_seed:
                            lock_seed.write(b"0")
                            lock_seed.flush()
                    break
            finally:
                if initializer_acquired:
                    _unlock_handle(initializer_handle)
                initializer_handle.close()
                if initializer_acquired:
                    try:
                        init_path.unlink(missing_ok=True)
                    except OSError:
                        # On Windows another contender can still have the
                        # marker open.  It will remove the marker after it
                        # observes the released lock.
                        pass

        if time.monotonic() >= deadline:
            raise TimeoutError(f"Timed out initializing runtime file lock: {lock_path}") from None
        time.sleep(0.01)

    handle = lock_path.open("r+b")
    acquired = False
    try:
        handle.seek(0, os.SEEK_END)
        if handle.tell() == 0:
            handle.write(b"0")
            handle.flush()
        while not acquired:
            try:
                handle.seek(0)
                _lock_handle(handle)
                acquired = True
            except (BlockingIOError, OSError):
                if time.monotonic() >= deadline:
                    raise TimeoutError(f"Timed out acquiring runtime file lock: {lock_path}") from None
                time.sleep(0.01)
        yield
    finally:
        if acquired:
            try:
                handle.seek(0)
                _unlock_handle(handle)
            except OSError:
                pass
        handle.close()
