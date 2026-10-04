"""全局配置。"""
from __future__ import annotations

import os
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent
DATA_DIR = Path(os.environ.get("PROMPTGOV_DATA", BASE_DIR / "data"))
DATA_DIR.mkdir(parents=True, exist_ok=True)

DB_PATH = DATA_DIR / "promptgov.db"

# 发布门槛：测试用例通过率达到该阈值才允许发布
PASS_THRESHOLD = float(os.environ.get("PROMPTGOV_PASS_THRESHOLD", "1.0"))

# HTTP 服务
HOST = os.environ.get("PROMPTGOV_HOST", "127.0.0.1")
PORT = int(os.environ.get("PROMPTGOV_PORT", "8080"))

# 固定测试集目录（按模板族 family_id 组织），内建一份演示集
SEED = os.environ.get("PROMPTGOV_SEED", "1") == "1"
