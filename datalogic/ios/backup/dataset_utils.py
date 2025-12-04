"""Dataset detection and preparation helpers for iOS backups.

该模块用于自动判断输入目录类型（已还原备份、iTunes 解密备份、提权备份）并在需要时自动还原
Manifest.db 中记录的目录结构。"""

import os
from dataclasses import dataclass, field
from typing import List, Optional

from datalogic.ios.backup import restore_ios_backup


RESTORED_HINTS = [
    "HomeDomain",
    "AppDomain-com.apple.Preferences",
    "SystemPreferencesDomain",
]


@dataclass
class DatasetContext:
    root: str
    kind: str
    display_prefix: str
    restore_dir: Optional[str] = None
    notes: List[str] = field(default_factory=list)


def _looks_like_restored_tree(path: str) -> bool:
    return any(os.path.exists(os.path.join(path, hint)) for hint in RESTORED_HINTS)


def _looks_like_privileged_dump(path: str) -> bool:
    return any(
        os.path.exists(os.path.join(path, candidate))
        for candidate in ["private/var", "var", "System/Library"]
    )


def resolve_dataset(input_path: str, out_path: Optional[str]) -> DatasetContext:
    """Identify dataset type and ensure a restored tree is available when needed."""

    # 1) 已经是还原后的目录
    if _looks_like_restored_tree(input_path):
        return DatasetContext(
            root=input_path,
            kind="restored_tree",
            display_prefix="restored_tree",
            notes=["检测到已还原的目录结构"],
        )

    manifest_db = os.path.join(input_path, "Manifest.db")
    manifest_plist = os.path.join(input_path, "Manifest.plist")

    # 2) iTunes 解密备份（尚未还原）
    if os.path.exists(manifest_db) or os.path.exists(manifest_plist):
        restore_base = out_path or os.path.join(os.getcwd(), "output")
        restore_dir = os.path.join(restore_base, "restored_tree")
        os.makedirs(restore_base, exist_ok=True)

        # 若已经有还原结果则复用，避免重复耗时
        if not _looks_like_restored_tree(restore_dir):
            print("[INFO] 检测到解密后的 iTunes 备份，自动还原目录结构 ...")
            restore_ios_backup.restore_backup_structure(input_path, restore_dir)
        else:
            print(f"[INFO] 发现现有还原目录，直接复用：{restore_dir}")

        return DatasetContext(
            root=restore_dir,
            kind="itunes_backup",
            display_prefix="restored_tree",
            restore_dir=restore_dir,
            notes=["根据 Manifest 自动还原目录结构"],
        )

    # 3) 提权备份 / 完整文件系统转储
    if _looks_like_privileged_dump(input_path):
        return DatasetContext(
            root=input_path,
            kind="privileged_dump",
            display_prefix="privileged_dump",
            notes=["检测到包含 /var 或 System 分区的提权备份"],
        )

    # 4) 兜底：未知格式，按原路径处理
    return DatasetContext(
        root=input_path,
        kind="unknown",
        display_prefix="restored_tree",
        notes=["未识别的目录结构，按输入路径直接解析"],
    )

