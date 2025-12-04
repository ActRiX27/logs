import argparse
import subprocess
from importlib import resources
from pathlib import Path

SCRIPT_NAME = "parse_ios_backup.sh"


def _resolve_script_path():
    try:
        return resources.files(__package__).joinpath(SCRIPT_NAME)
    except AttributeError:
        return Path(__file__).with_name(SCRIPT_NAME)


def run(backup_dir, out_dir):
    script_path = _resolve_script_path()
    if not script_path.exists():
        raise FileNotFoundError(f"脚本未找到: {script_path}")

    subprocess.run([
        "zsh",
        str(script_path),
        "--backup",
        str(backup_dir),
        "--out",
        str(out_dir),
    ], check=True)

    return out_dir


def main():
    parser = argparse.ArgumentParser(description="iOS Backup 全功能取证解析器")
    parser.add_argument("--backup", required=True, help="已解密的 iOS 备份目录")
    parser.add_argument("--out", required=True, help="分析输出目录")
    args = parser.parse_args()

    run(args.backup, args.out)


if __name__ == "__main__":
    main()
