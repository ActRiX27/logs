#!/usr/bin/env python3
"""从 GitHub Releases 拉取 wheel 与源码包，解决无法直接提交或同步二进制产物的场景。

示例：
    python scripts/fetch_release_assets.py \
        --repo org/datalogic \
        --tag v0.2.0 \
        --asset datalogic-0.2.0-py3-none-any.whl \
        --asset datalogic-0.2.0.tar.gz \
        --out dist/

支持使用环境变量 GITHUB_TOKEN 减少 API 频率限制。
"""

import argparse
import json
import os
import sys
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Dict, Iterable, List, Optional

API_TEMPLATE = "https://api.github.com/repos/{repo}/releases/tags/{tag}"
DEFAULT_TOKEN_ENV = "GITHUB_TOKEN"


def _build_request(url: str, token: Optional[str]) -> urllib.request.Request:
    headers = {"User-Agent": "datalogic-fetcher/1.0"}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    return urllib.request.Request(url, headers=headers)


def _load_release(tag: str, repo: str, token: Optional[str]) -> Dict:
    url = API_TEMPLATE.format(repo=repo, tag=urllib.parse.quote(tag))
    req = _build_request(url, token)
    with urllib.request.urlopen(req) as resp:  # noqa: S310
        return json.loads(resp.read().decode("utf-8"))


def _download(url: str, dest: Path, token: Optional[str]) -> None:
    dest.parent.mkdir(parents=True, exist_ok=True)
    req = _build_request(url, token)
    with urllib.request.urlopen(req) as resp:  # noqa: S310
        total = int(resp.headers.get("Content-Length", "0"))
        chunk = 8192
        written = 0
        with dest.open("wb") as f:
            while True:
                data = resp.read(chunk)
                if not data:
                    break
                f.write(data)
                written += len(data)
        print(f"[fetch] 下载完成: {dest} ({written} bytes, expected {total} bytes)")


def fetch_assets(tag: str, repo: str, assets: Iterable[str], out_dir: Path, token: Optional[str]) -> List[Path]:
    release = _load_release(tag, repo, token)
    available = {asset["name"]: asset["browser_download_url"] for asset in release.get("assets", [])}
    downloaded: List[Path] = []

    for name in assets:
        url = available.get(name)
        if not url:
            raise ValueError(f"未在 release {tag} 中找到资产 {name}; 可用资产: {list(available)}")
        dest = out_dir / name
        _download(url, dest, token)
        downloaded.append(dest)

    return downloaded


def parse_args(argv: Optional[List[str]] = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="从 GitHub Releases 下载 wheel 与 tar.gz 发布产物")
    parser.add_argument("--repo", required=True, help="GitHub 仓库，格式如 owner/repo")
    parser.add_argument("--tag", required=True, help="Release tag，例如 v0.2.0")
    parser.add_argument("--asset", action="append", dest="assets", required=True, help="需要下载的资产名称，可重复指定")
    parser.add_argument("--out", type=Path, required=False, default=Path("dist"), help="输出目录，默认 dist/")
    parser.add_argument("--token-env", default=DEFAULT_TOKEN_ENV, help="用于读取 token 的环境变量名，默认 GITHUB_TOKEN")
    return parser.parse_args(argv)


def main(argv: Optional[List[str]] = None) -> int:
    args = parse_args(argv)
    token = os.environ.get(args.token_env)

    try:
        downloaded = fetch_assets(
            tag=args.tag,
            repo=args.repo,
            assets=args.assets,
            out_dir=args.out,
            token=token,
        )
    except urllib.error.HTTPError as e:
        print(f"[fetch] GitHub API 请求失败: {e}", file=sys.stderr)
        return 1
    except Exception as exc:  # noqa: BLE001
        print(f"[fetch] 下载失败: {exc}", file=sys.stderr)
        return 1

    for path in downloaded:
        print(f"[fetch] 已保存: {path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
