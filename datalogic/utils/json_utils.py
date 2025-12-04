"""通用 JSON 安全转换工具。"""

import base64
from datetime import date, datetime
from pathlib import Path
from typing import Any


def json_safe(obj: Any):
    """递归转换对象以便安全序列化为 JSON。

    - bytes → base64 字符串
    - datetime/date → ISO8601
    - Path → 字符串路径
    - set/tuple → list
    - 其他可迭代类型保持递归转换
    """

    if isinstance(obj, dict):
        return {k: json_safe(v) for k, v in obj.items()}
    if isinstance(obj, (list, tuple)):
        return [json_safe(v) for v in obj]
    if isinstance(obj, set):
        return [json_safe(v) for v in sorted(obj, key=lambda x: str(x))]
    if isinstance(obj, bytes):
        return base64.b64encode(obj).decode("utf-8")
    if isinstance(obj, (datetime, date)):
        return obj.isoformat()
    if isinstance(obj, Path):
        return str(obj)
    return obj
