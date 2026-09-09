from __future__ import annotations

import hashlib
import hmac
import json
import os
import re
import shutil
import sqlite3
import tempfile
from contextlib import closing
from datetime import datetime, timezone
from pathlib import Path, PurePosixPath
from typing import Any, cast
from uuid import uuid4
from zipfile import ZIP_DEFLATED, BadZipFile, ZipFile, ZipInfo

from apps.api.agent_supervisor.paths import RUNTIME_DIR
from apps.api.agent_supervisor.storage.json_store import decode_json_strict, exclusive_file_lock

BACKUP_SCHEMA_VERSION = "agent-supervisor.runtime-backup.v1"
MANIFEST_NAME = "manifest.json"
DATA_PREFIX = "data/"
DATABASE_NAME = "agent_supervisor.sqlite3"
POLICY_AUDIT_OUTBOX_NAME = "policy_audit_outbox.json"
ACTIVE_RUNTIME_DIR = ".runtime-active"
RUNTIME_MAINTENANCE_RESOURCE = "runtime-maintenance"
RUNTIME_MAINTENANCE_LOCK_NAME = f".{RUNTIME_MAINTENANCE_RESOURCE}.lock"
RUNTIME_BACKUP_RESOURCE = "runtime-backup"
RUNTIME_BACKUP_LOCK_NAME = f".{RUNTIME_BACKUP_RESOURCE}.lock"
MAX_BACKUP_FILES = 100_000
MAX_BACKUP_BYTES = 16 * 1024 * 1024 * 1024
MAX_MANIFEST_BYTES = 2 * 1024 * 1024
STABLE_COPY_ATTEMPTS = 3
_ACTIVE_MAINTENANCE_LOCKS: dict[Path, Any] = {}
EXCLUDED_SUFFIXES = {"-wal", "-shm", ".tmp", ".lock"}
EXCLUDED_PREFIXES = (".runtime-active", ".restore-stage-", ".restore-rollback-", ".restore-failed-")
SHA256_RE = re.compile(r"[0-9a-fA-F]{64}\Z")


class RuntimeBackupError(ValueError):
    pass




def create_runtime_backup(
    output: Path,
    *,
    source_root: Path = RUNTIME_DIR,
    signing_key: str = "",
    signing_key_id: str = "",
    require_signature: bool = False,
) -> dict[str, Any]:
    source = source_root.resolve()
    if not source.is_dir():
        raise RuntimeBackupError(f"运行目录不存在：{source}")
    # Backups are designed to be safe while the service is serving traffic.
    # The app lifespan owns the maintenance lock for its entire lifetime, so a
    # backup must use a separate lock. Restore takes both locks (maintenance
    # first, then backup) to exclude a concurrent snapshot without blocking the
    # normal online backup path.
    try:
        with exclusive_file_lock(source / RUNTIME_BACKUP_RESOURCE, timeout_seconds=30.0):
            return _create_runtime_backup_unlocked(
                output,
                source_root=source_root,
                signing_key=signing_key,
                signing_key_id=signing_key_id,
                require_signature=require_signature,
            )
    except TimeoutError as exc:
        raise RuntimeBackupError("获取运行数据备份锁超时，请稍后重试。") from exc


def _create_runtime_backup_unlocked(
    output: Path,
    *,
    source_root: Path = RUNTIME_DIR,
    signing_key: str = "",
    signing_key_id: str = "",
    require_signature: bool = False,
) -> dict[str, Any]:
    source = source_root.resolve()
    destination = output.resolve()
    if not source.is_dir():
        raise RuntimeBackupError(f"运行目录不存在：{source}")
    if destination == source or destination.is_relative_to(source):
        raise RuntimeBackupError("备份文件必须写到运行目录之外，避免与源数据同时丢失。")
    if require_signature and not signing_key:
        raise RuntimeBackupError("生产备份要求配置 HMAC 签名密钥。")

    source_database = source / DATABASE_NAME
    if not source_database.is_file():
        raise RuntimeBackupError(f"运行数据库不存在：{source_database}")

    destination.parent.mkdir(parents=True, exist_ok=True)
    # Policy updates use the audit-outbox lock as their transaction-wide,
    # cross-process mutex (outbox -> resource).  Taking that same outer lock
    # while snapshotting the database and copying every JSON file prevents a
    # backup from combining the database from before a policy transaction with
    # its config from after the transaction.  Backup takes no inner resource
    # lock, so the established lock order cannot be inverted.
    with exclusive_file_lock(source / POLICY_AUDIT_OUTBOX_NAME):
        with tempfile.TemporaryDirectory(prefix="zhi-an-backup-stage-", dir=destination.parent) as temporary:
            stage = Path(temporary)
            data_stage = stage / "data"
            data_stage.mkdir()
            _snapshot_database(source_database, data_stage / DATABASE_NAME)

            for source_file in _runtime_source_files(source, destination):
                relative = source_file.relative_to(source)
                target = data_stage / relative
                target.parent.mkdir(parents=True, exist_ok=True)
                _copy_stable_file(source_file, target)

            file_records = [_file_record(path, data_stage) for path in sorted(data_stage.rglob("*")) if path.is_file()]
            total_bytes = sum(int(item["size_bytes"]) for item in file_records)
            if len(file_records) > MAX_BACKUP_FILES or total_bytes > MAX_BACKUP_BYTES:
                raise RuntimeBackupError("运行数据超过备份文件数量或总容量上限。")

            manifest: dict[str, Any] = {
                "schema_version": BACKUP_SCHEMA_VERSION,
                "created_at": datetime.now(timezone.utc).isoformat(),
                "database_path": DATABASE_NAME,
                "file_count": len(file_records),
                "total_bytes": total_bytes,
                "files": file_records,
                "integrity": {
                    "algorithm": "hmac-sha256" if signing_key else "sha256-file-manifest",
                    "authenticated": bool(signing_key),
                    "key_id": signing_key_id if signing_key else "",
                    "signature": "",
                },
            }
            if signing_key:
                manifest["integrity"]["signature"] = _manifest_signature(manifest, signing_key)

            temporary_archive = destination.with_name(f".{destination.name}.{uuid4().hex}.tmp")
            try:
                with ZipFile(temporary_archive, "w", compression=ZIP_DEFLATED, compresslevel=6) as archive:
                    archive.writestr(MANIFEST_NAME, _canonical_json(manifest))
                    for path in sorted(data_stage.rglob("*")):
                        if path.is_file():
                            archive.write(path, f"{DATA_PREFIX}{path.relative_to(data_stage).as_posix()}")
                os.replace(temporary_archive, destination)
            finally:
                temporary_archive.unlink(missing_ok=True)

    return {**manifest, "output": str(destination)}


def verify_runtime_backup(
    archive_path: Path,
    *,
    signing_key: str = "",
    require_signature: bool = False,
) -> dict[str, Any]:
    path = archive_path.resolve()
    if not path.is_file():
        raise RuntimeBackupError(f"备份文件不存在：{path}")
    try:
        with ZipFile(path, "r") as archive:
            infos = archive.infolist()
            _validate_archive_entries(infos)
            manifest_info = next((item for item in infos if item.filename == MANIFEST_NAME), None)
            if manifest_info is None or manifest_info.file_size > MAX_MANIFEST_BYTES:
                raise RuntimeBackupError("备份缺少有效 manifest.json。")
            try:
                manifest = decode_json_strict(archive.read(manifest_info).decode("utf-8"))
            except (UnicodeError, ValueError) as exc:
                raise RuntimeBackupError("备份清单不是有效 UTF-8 JSON。") from exc
            _validate_manifest(manifest, signing_key=signing_key, require_signature=require_signature)

            records = manifest["files"]
            expected = {f"{DATA_PREFIX}{item['path']}": item for item in records}
            actual = {item.filename: item for item in infos if item.filename.startswith(DATA_PREFIX) and not item.is_dir()}
            if set(actual) != set(expected):
                raise RuntimeBackupError("备份清单与归档文件集合不一致。")

            total_bytes = 0
            for name, record in expected.items():
                info = actual[name]
                size = int(record["size_bytes"])
                if info.file_size != size:
                    raise RuntimeBackupError(f"备份文件大小不匹配：{record['path']}")
                digest = _hash_archive_entry(archive, info)
                if not hmac.compare_digest(digest, str(record["sha256"])):
                    raise RuntimeBackupError(f"备份文件 Hash 不匹配：{record['path']}")
                total_bytes += size
            if total_bytes != int(manifest["total_bytes"]):
                raise RuntimeBackupError("备份总容量与清单不一致。")

            database_entry = f"{DATA_PREFIX}{manifest['database_path']}"
            if database_entry not in actual:
                raise RuntimeBackupError("备份缺少 SQLite 数据库快照。")
            with tempfile.TemporaryDirectory(prefix="zhi-an-backup-verify-") as temporary:
                database_copy = Path(temporary) / DATABASE_NAME
                with archive.open(actual[database_entry]) as source, database_copy.open("wb") as target:
                    shutil.copyfileobj(source, target, length=1024 * 1024)
                _verify_database(database_copy)
    except (BadZipFile, RuntimeError) as exc:
        raise RuntimeBackupError("备份不是有效 ZIP 归档。") from exc
    except OSError as exc:
        raise RuntimeBackupError(f"读取或验证备份归档失败：{exc}") from exc

    return {
        "valid": True,
        "schema_version": manifest["schema_version"],
        "created_at": manifest["created_at"],
        "file_count": manifest["file_count"],
        "total_bytes": manifest["total_bytes"],
        "authenticated": manifest["integrity"]["authenticated"],
        "key_id": manifest["integrity"]["key_id"],
        "archive": str(path),
        "database_integrity": "ok",
    }




def restore_runtime_backup(
    archive_path: Path,
    *,
    target_root: Path = RUNTIME_DIR,
    signing_key: str = "",
    require_signature: bool = True,
    offline_confirmed: bool = False,
    keep_rollback: bool = True,
) -> dict[str, Any]:
    target = target_root.resolve()
    archive = archive_path.resolve()
    if not archive.is_file():
        raise RuntimeBackupError(f"备份文件不存在：{archive}")
    if not offline_confirmed:
        raise RuntimeBackupError("恢复会替换运行数据，必须显式确认服务已停止。")
    if archive == target or archive.is_relative_to(target):
        raise RuntimeBackupError("恢复归档必须位于运行目录之外。")
    target.mkdir(parents=True, exist_ok=True)
    # Check the marker before waiting on the maintenance lock so an active
    # service is reported as an offline-precondition failure, not a lock timeout.
    _assert_runtime_offline(target)
    # Pin the input to one private file before verification and extraction.
    # This prevents a verify-then-reopen path race when a backup is atomically
    # replaced by another process between those two phases.
    try:
        with exclusive_file_lock(target / RUNTIME_MAINTENANCE_RESOURCE, timeout_seconds=30.0):
            with exclusive_file_lock(target / RUNTIME_BACKUP_RESOURCE, timeout_seconds=30.0):
                with tempfile.TemporaryDirectory(prefix="zhi-an-restore-archive-") as temporary:
                    fixed_archive = Path(temporary) / "input.zip"
                    with archive.open("rb") as source, fixed_archive.open("wb") as destination:
                        shutil.copyfileobj(source, destination, length=1024 * 1024)
                    return _restore_runtime_backup_unlocked(
                        fixed_archive,
                        target_root=target_root,
                        signing_key=signing_key,
                        require_signature=require_signature,
                        offline_confirmed=offline_confirmed,
                        keep_rollback=keep_rollback,
                    )
    except TimeoutError as exc:
        raise RuntimeBackupError("获取运行数据维护锁超时，请确认服务已停止后重试。") from exc


def _restore_runtime_backup_unlocked(
    archive_path: Path,
    *,
    target_root: Path = RUNTIME_DIR,
    signing_key: str = "",
    require_signature: bool = True,
    offline_confirmed: bool = False,
    keep_rollback: bool = True,
) -> dict[str, Any]:
    if not offline_confirmed:
        raise RuntimeBackupError("恢复会替换运行数据，必须显式确认服务已停止。")
    archive = archive_path.resolve()
    target = target_root.resolve()
    if archive == target or archive.is_relative_to(target):
        raise RuntimeBackupError("恢复归档必须位于运行目录之外。")
    verification = verify_runtime_backup(archive, signing_key=signing_key, require_signature=require_signature)
    target.mkdir(parents=True, exist_ok=True)
    _assert_runtime_offline(target)

    stage = target / f".restore-stage-{uuid4().hex}"
    rollback = target / f".restore-rollback-{datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')}-{uuid4().hex[:8]}"
    stage.mkdir()
    rollback.mkdir()
    moved_existing: list[tuple[Path, Path]] = []
    moved_restored: list[tuple[Path, Path]] = []
    try:
        with ZipFile(archive, "r") as source_archive:
            manifest = decode_json_strict(source_archive.read(MANIFEST_NAME).decode("utf-8"))
            for record in manifest["files"]:
                relative = _safe_relative_path(str(record["path"]))
                destination = stage / relative
                destination.parent.mkdir(parents=True, exist_ok=True)
                with source_archive.open(f"{DATA_PREFIX}{relative.as_posix()}") as source, destination.open("wb") as output:
                    shutil.copyfileobj(source, output, length=1024 * 1024)
        _verify_database(stage / DATABASE_NAME)

        for existing in list(target.iterdir()):
            if existing in {stage, rollback} or existing.name in {
                ACTIVE_RUNTIME_DIR,
                RUNTIME_MAINTENANCE_LOCK_NAME,
                RUNTIME_BACKUP_LOCK_NAME,
            }:
                continue
            rollback_target = rollback / existing.name
            os.replace(existing, rollback_target)
            moved_existing.append((rollback_target, existing))
        for restored in list(stage.iterdir()):
            destination = target / restored.name
            os.replace(restored, destination)
            moved_restored.append((destination, restored))
    except Exception:
        failed = target / f".restore-failed-{uuid4().hex}"
        failed.mkdir(exist_ok=True)
        for restored, _ in reversed(moved_restored):
            if restored.exists():
                os.replace(restored, failed / restored.name)
        for rollback_source, original in reversed(moved_existing):
            if rollback_source.exists():
                os.replace(rollback_source, original)
        raise
    finally:
        shutil.rmtree(stage, ignore_errors=True)

    if not keep_rollback:
        shutil.rmtree(rollback, ignore_errors=True)
        rollback_value = ""
    else:
        rollback_value = str(rollback)
    return {**verification, "restored_to": str(target), "rollback": rollback_value}


def mark_runtime_active(runtime_root: Path = RUNTIME_DIR) -> Path:
    runtime_root = runtime_root.resolve()
    runtime_root.mkdir(parents=True, exist_ok=True)
    lock = exclusive_file_lock(runtime_root / RUNTIME_MAINTENANCE_RESOURCE, timeout_seconds=30.0)
    lock.__enter__()
    active_dir = runtime_root / ACTIVE_RUNTIME_DIR
    active_dir.mkdir(parents=True, exist_ok=True)
    marker = active_dir / f"{os.getpid()}-{uuid4().hex}.json"
    try:
        marker.write_text(
            json.dumps(
                {"pid": os.getpid(), "started_at": datetime.now(timezone.utc).isoformat()},
                ensure_ascii=False,
                sort_keys=True,
            ),
            encoding="utf-8",
        )
    except BaseException as exc:
        lock.__exit__(type(exc), exc, exc.__traceback__)
        raise
    _ACTIVE_MAINTENANCE_LOCKS[marker.resolve()] = lock
    return marker


def clear_runtime_active(marker: Path) -> None:
    marker = marker.resolve()
    try:
        marker.unlink(missing_ok=True)
    finally:
        lock = _ACTIVE_MAINTENANCE_LOCKS.pop(marker, None)
        if lock is not None:
            lock.__exit__(None, None, None)
    try:
        marker.parent.rmdir()
    except OSError:
        pass


def _assert_runtime_offline(runtime_root: Path) -> None:
    active_dir = runtime_root / ACTIVE_RUNTIME_DIR
    if not active_dir.is_dir():
        return
    active_pids: list[int] = []
    for marker in active_dir.glob("*.json"):
        try:
            payload = json.loads(marker.read_text(encoding="utf-8"))
            pid = int(payload.get("pid", 0))
        except (OSError, ValueError, json.JSONDecodeError, AttributeError):
            pid = 0
        if pid > 0 and _pid_is_alive(pid):
            active_pids.append(pid)
        else:
            marker.unlink(missing_ok=True)
    if active_pids:
        raise RuntimeBackupError(f"运行服务仍处于活动状态（PID：{','.join(map(str, active_pids))}），拒绝在线恢复。")
    try:
        active_dir.rmdir()
    except OSError:
        pass


def _pid_is_alive(pid: int) -> bool:
    if pid <= 0:
        return False
    if os.name == "nt":
        return _windows_pid_is_alive(pid)
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    except OSError:
        return False
    return True


def _windows_pid_is_alive(pid: int) -> bool:
    """Query a Windows process without sending it a signal.

    Unlike POSIX, ``os.kill(pid, 0)`` calls ``TerminateProcess`` on Windows and
    can end the service that an offline restore is trying to detect.  Query the
    process exit code through a read-only handle instead.  Unknown access/query
    errors are treated as alive so restore remains fail-closed.
    """

    import ctypes

    ctypes_api = cast(Any, ctypes)
    process_query_limited_information = 0x1000
    still_active = 259
    error_invalid_parameter = 87
    kernel32 = ctypes_api.WinDLL("kernel32", use_last_error=True)
    open_process = kernel32.OpenProcess
    open_process.argtypes = (ctypes.c_uint32, ctypes.c_int, ctypes.c_uint32)
    open_process.restype = ctypes.c_void_p
    get_exit_code_process = kernel32.GetExitCodeProcess
    get_exit_code_process.argtypes = (ctypes.c_void_p, ctypes.POINTER(ctypes.c_uint32))
    get_exit_code_process.restype = ctypes.c_int
    close_handle = kernel32.CloseHandle
    close_handle.argtypes = (ctypes.c_void_p,)
    close_handle.restype = ctypes.c_int

    handle = open_process(process_query_limited_information, 0, pid)
    if not handle:
        # ERROR_INVALID_PARAMETER is the normal response for a PID that no
        # longer exists.  Access denied and unexpected query failures must not
        # be interpreted as proof that the runtime is offline.
        return ctypes_api.get_last_error() != error_invalid_parameter
    try:
        exit_code = ctypes.c_uint32()
        if not get_exit_code_process(handle, ctypes.byref(exit_code)):
            return True
        return exit_code.value == still_active
    finally:
        close_handle(handle)


def _runtime_source_files(source: Path, destination: Path) -> list[Path]:
    files: list[Path] = []
    for path in source.rglob("*"):
        if path.is_symlink():
            raise RuntimeBackupError(f"运行目录包含符号链接，拒绝备份：{path.relative_to(source)}")
        if not path.is_file() or path.resolve() == destination:
            continue
        relative = path.relative_to(source)
        if relative.as_posix() == DATABASE_NAME or _excluded_runtime_path(relative):
            continue
        files.append(path)
    return sorted(files)


def _excluded_runtime_path(relative: Path) -> bool:
    value = relative.as_posix()
    if any(part.startswith(EXCLUDED_PREFIXES) for part in relative.parts):
        return True
    return any(value.endswith(suffix) for suffix in EXCLUDED_SUFFIXES)


def _snapshot_database(source: Path, destination: Path) -> None:
    try:
        with closing(sqlite3.connect(source, timeout=10)) as source_connection, closing(
            sqlite3.connect(destination)
        ) as target_connection:
            source_connection.execute("PRAGMA busy_timeout = 10000")
            source_connection.backup(target_connection)
            target_connection.execute("PRAGMA journal_mode = DELETE")
    except sqlite3.Error as exc:
        raise RuntimeBackupError(f"SQLite 一致性快照失败：{exc}") from exc
    _verify_database(destination)


def _verify_database(path: Path) -> None:
    try:
        with closing(sqlite3.connect(f"file:{path.as_posix()}?mode=ro", uri=True)) as connection:
            result = connection.execute("PRAGMA integrity_check").fetchone()
    except sqlite3.Error as exc:
        raise RuntimeBackupError(f"SQLite 完整性检查失败：{exc}") from exc
    if not result or str(result[0]).lower() != "ok":
        raise RuntimeBackupError(f"SQLite 完整性检查未通过：{result[0] if result else 'empty'}")


def _copy_stable_file(source: Path, destination: Path) -> None:
    for _ in range(STABLE_COPY_ATTEMPTS):
        before = source.stat()
        shutil.copyfile(source, destination)
        after = source.stat()
        if before.st_size == after.st_size and before.st_mtime_ns == after.st_mtime_ns:
            return
    raise RuntimeBackupError(f"文件持续变化，无法取得稳定快照：{source}")


def _file_record(path: Path, root: Path) -> dict[str, Any]:
    return {"path": path.relative_to(root).as_posix(), "size_bytes": path.stat().st_size, "sha256": _hash_file(path)}


def _hash_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _hash_archive_entry(archive: ZipFile, info: ZipInfo) -> str:
    digest = hashlib.sha256()
    with archive.open(info) as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _validate_archive_entries(infos: list[ZipInfo]) -> None:
    names = [item.filename for item in infos]
    if len(names) != len(set(names)):
        raise RuntimeBackupError("备份归档包含重复路径。")
    if len(infos) > MAX_BACKUP_FILES + 1:
        raise RuntimeBackupError("备份归档文件数量超过上限。")
    total = 0
    for info in infos:
        pure = PurePosixPath(info.filename)
        if pure.is_absolute() or ".." in pure.parts or "\\" in info.filename:
            raise RuntimeBackupError(f"备份归档包含越界路径：{info.filename}")
        if info.filename != MANIFEST_NAME and not info.filename.startswith(DATA_PREFIX):
            raise RuntimeBackupError(f"备份归档包含未登记路径：{info.filename}")
        total += info.file_size
        if total > MAX_BACKUP_BYTES + MAX_MANIFEST_BYTES:
            raise RuntimeBackupError("备份归档解压容量超过上限。")


def _validate_manifest(manifest: Any, *, signing_key: str, require_signature: bool) -> None:
    if not isinstance(manifest, dict) or manifest.get("schema_version") != BACKUP_SCHEMA_VERSION:
        raise RuntimeBackupError("备份清单版本不受支持。")

    created_at = manifest.get("created_at")
    if not isinstance(created_at, str) or not created_at.strip():
        raise RuntimeBackupError("备份创建时间格式无效。")
    try:
        timestamp = datetime.fromisoformat(created_at.replace("Z", "+00:00"))
    except ValueError as exc:
        raise RuntimeBackupError("备份创建时间格式无效。") from exc
    if timestamp.tzinfo is None:
        raise RuntimeBackupError("备份创建时间必须包含时区。")

    database_path = manifest.get("database_path")
    if database_path != DATABASE_NAME:
        raise RuntimeBackupError("备份数据库路径无效。")

    records = manifest.get("files")
    file_count = manifest.get("file_count")
    if type(file_count) is not int or file_count < 1 or not isinstance(records, list) or file_count != len(records):
        raise RuntimeBackupError("备份文件数量与清单不一致。")
    if len(records) > MAX_BACKUP_FILES:
        raise RuntimeBackupError("备份清单文件数量超过上限。")

    total_bytes = manifest.get("total_bytes")
    if type(total_bytes) is not int or total_bytes < 0 or total_bytes > MAX_BACKUP_BYTES:
        raise RuntimeBackupError("备份总容量格式无效。")

    seen: set[str] = set()
    calculated_total = 0
    for record in records:
        if not isinstance(record, dict):
            raise RuntimeBackupError("备份文件清单格式无效。")
        raw_path = record.get("path")
        if not isinstance(raw_path, str):
            raise RuntimeBackupError("备份文件路径格式无效。")
        relative_path = _safe_relative_path(raw_path)
        relative = relative_path.as_posix()
        if relative != raw_path or relative == ".":
            raise RuntimeBackupError(f"备份文件路径格式无效：{raw_path}")
        if relative in seen:
            raise RuntimeBackupError("备份文件清单包含重复路径。")
        seen.add(relative)
        size = record.get("size_bytes")
        digest = record.get("sha256")
        if type(size) is not int or size < 0 or size > MAX_BACKUP_BYTES or not isinstance(digest, str) or not SHA256_RE.fullmatch(digest):
            raise RuntimeBackupError(f"备份文件记录无效：{relative}")
        calculated_total += size
        if calculated_total > MAX_BACKUP_BYTES:
            raise RuntimeBackupError("备份清单总容量超过上限。")
    if calculated_total != total_bytes:
        raise RuntimeBackupError("备份总容量与文件清单不一致。")

    integrity = manifest.get("integrity")
    if not isinstance(integrity, dict):
        raise RuntimeBackupError("备份缺少完整性声明。")
    algorithm = integrity.get("algorithm")
    authenticated = integrity.get("authenticated")
    key_id = integrity.get("key_id")
    signature = integrity.get("signature")
    if not isinstance(algorithm, str) or not isinstance(authenticated, bool):
        raise RuntimeBackupError("备份完整性声明格式无效。")
    if not isinstance(key_id, str) or len(key_id) > 128 or "\r" in key_id or "\n" in key_id:
        raise RuntimeBackupError("备份签名标识格式无效。")
    if not isinstance(signature, str):
        raise RuntimeBackupError("备份签名格式无效。")
    if require_signature and not authenticated:
        raise RuntimeBackupError("当前恢复策略要求经过 HMAC 认证的备份。")
    if authenticated:
        if algorithm != "hmac-sha256" or not SHA256_RE.fullmatch(signature):
            raise RuntimeBackupError("备份 HMAC 声明格式无效。")
        if not signing_key:
            raise RuntimeBackupError("验证签名备份需要提供原 HMAC 密钥。")
        expected = _manifest_signature(manifest, signing_key)
        if not signature or not hmac.compare_digest(signature, expected):
            raise RuntimeBackupError("备份 HMAC 签名校验失败。")
    elif algorithm != "sha256-file-manifest" or key_id or signature:
        raise RuntimeBackupError("备份未认证完整性声明格式无效。")


def _manifest_signature(manifest: dict[str, Any], signing_key: str) -> str:
    unsigned = decode_json_strict(_canonical_json(manifest))
    unsigned["integrity"]["signature"] = ""
    return hmac.new(signing_key.encode("utf-8"), _canonical_json(unsigned), hashlib.sha256).hexdigest()


def _safe_relative_path(value: str) -> Path:
    pure = PurePosixPath(value)
    if not value or pure.is_absolute() or ".." in pure.parts or "\\" in value:
        raise RuntimeBackupError(f"备份清单包含越界路径：{value}")
    return Path(*pure.parts)


def _canonical_json(value: Any) -> bytes:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False).encode("utf-8")
