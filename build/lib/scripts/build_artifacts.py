#!/usr/bin/env python3
"""构建发布产物并存放到 dist/ 目录，便于在不直接拉取二进制的场景下本地生成 wheel 与源码包。"""
import pathlib
import subprocess
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent
DIST = ROOT / "dist"


def ensure_build_backend() -> None:
    try:
        import build  # type: ignore  # noqa: F401
    except ImportError:
        print("[build_artifacts] 未检测到 build 模块，正在尝试安装 python-build...", file=sys.stderr)
        subprocess.check_call([sys.executable, "-m", "pip", "install", "build"])


def build_release() -> None:
    ensure_build_backend()
    DIST.mkdir(exist_ok=True)
    print(f"[build_artifacts] 输出目录: {DIST}")
    subprocess.check_call([sys.executable, "-m", "build", "--wheel", "--sdist", "--outdir", str(DIST)], cwd=ROOT)


if __name__ == "__main__":
    build_release()
