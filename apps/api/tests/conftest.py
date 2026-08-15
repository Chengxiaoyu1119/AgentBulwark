"""pytest 共享配置：把运行时数据重定向到系统临时目录。

背景（2026-08-15 Week6 全面测试定位）：仓库目录树上任意文件删除耗时约 2s
（文件系统过滤驱动所致，系统 Temp 仅 0.4ms）。SQLite WAL 模式每次连接关闭
都要删除 -wal/-shm 两个临时文件（约 3.5s/次），测试套件数百次开关连接后
表现为无限挂起。

处理：在导入被测模块前设置 AGENT_SUPERVISOR_RUNTIME_DIR 指向系统 Temp
下的独立目录（paths.py 原生支持），使测试运行时数据库与策略覆盖写入快目录，
同时实现测试与开发运行库隔离，避免审计数据在仓库内无限累积。
"""

from __future__ import annotations

import os
import tempfile
from pathlib import Path

_TEST_RUNTIME_DIR = Path(tempfile.gettempdir()) / "agent-supervisor-test-runtime"
_TEST_RUNTIME_DIR.mkdir(parents=True, exist_ok=True)
os.environ.setdefault("AGENT_SUPERVISOR_RUNTIME_DIR", str(_TEST_RUNTIME_DIR))
