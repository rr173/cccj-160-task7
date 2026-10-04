"""服务层异常类型（独立于 services，供服务/隔离/证据模块共享，避免循环导入）。

app 层据此映射 HTTP 状态码：DomainError=400，NotFound=404，Conflict=409。
"""
from __future__ import annotations


class DomainError(Exception):
    """400 级业务错误。"""


class NotFound(DomainError):
    """404。"""


class Conflict(DomainError):
    """409：并发冲突 / 状态不允许。"""
