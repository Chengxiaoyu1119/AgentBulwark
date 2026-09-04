from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
from typing import Any

from apps.api.agent_supervisor.domains.runtime.runtime_backup import (
    RuntimeBackupError,
    create_runtime_backup,
    restore_runtime_backup,
    verify_runtime_backup,
)
from apps.api.agent_supervisor.domains.runtime.security_profile import production_security_profile
from apps.api.agent_supervisor.domains.runtime.server_security import load_environment_file


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="智安哨运营数据一致性备份、验证与离线恢复")
    subparsers = parser.add_subparsers(dest="command", required=True)

    create = subparsers.add_parser("create", help="创建 SQLite 一致性快照和运行文件归档")
    create.add_argument("--output", required=True, type=Path)
    create.add_argument("--allow-unsigned", action="store_true")

    verify = subparsers.add_parser("verify", help="验证清单、HMAC、文件 Hash 和 SQLite 完整性")
    verify.add_argument("--input", required=True, type=Path)
    verify.add_argument("--allow-unsigned", action="store_true")

    restore = subparsers.add_parser("restore", help="在服务停止后恢复完整运行目录")
    restore.add_argument("--input", required=True, type=Path)
    restore.add_argument("--target", type=Path)
    restore.add_argument("--confirm-offline-restore", action="store_true")
    restore.add_argument("--allow-unsigned", action="store_true")
    restore.add_argument("--discard-rollback", action="store_true")
    return parser


def main() -> None:
    load_environment_file()
    args = _parser().parse_args()
    key = (os.getenv("AGENT_SUPERVISOR_AUDIT_HMAC_KEY") or "").strip()
    key_id = (os.getenv("AGENT_SUPERVISOR_AUDIT_HMAC_KEY_ID") or "runtime-backup-v1").strip()
    require_signature = production_security_profile() and not args.allow_unsigned
    try:
        if args.command == "create":
            result = create_runtime_backup(
                args.output,
                signing_key=key,
                signing_key_id=key_id,
                require_signature=require_signature,
            )
        elif args.command == "verify":
            result = verify_runtime_backup(args.input, signing_key=key, require_signature=require_signature)
        else:
            options: dict[str, Any] = {
                "signing_key": key,
                "require_signature": require_signature,
                "offline_confirmed": args.confirm_offline_restore,
                "keep_rollback": not args.discard_rollback,
            }
            if args.target is not None:
                options["target_root"] = args.target
            result = restore_runtime_backup(args.input, **options)
    except RuntimeBackupError as exc:
        raise SystemExit(str(exc)) from exc
    print(json.dumps(result, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
