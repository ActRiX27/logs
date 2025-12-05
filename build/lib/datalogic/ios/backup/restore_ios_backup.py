import sqlite3
import os
import shutil
import argparse

def restore_backup_structure(backup_dir, output_dir):
    db_path = os.path.join(backup_dir, "Manifest.db")
    if not os.path.exists(db_path):
        print("❌ 未找到 Manifest.db，确认输入是否为解密后的 iOS 备份目录")
        return

    conn = sqlite3.connect(db_path)
    cur = conn.cursor()
    cur.execute("SELECT fileID, domain, relativePath FROM Files")

    rows = cur.fetchall()
    print(f"📦 共发现 {len(rows)} 个文件记录，准备还原目录结构…")

    for fid, domain, rel_path in rows:
        if not fid or not rel_path:
            continue

        # 源文件 hashed 路径
        src = os.path.join(backup_dir, fid[:2], fid)
        if not os.path.exists(src):
            continue

        # domain 作为顶级目录
        safe_domain = domain.replace(":", "_").replace("/", "_")

        dst = os.path.join(output_dir, safe_domain, rel_path)
        os.makedirs(os.path.dirname(dst), exist_ok=True)

        try:
            shutil.copy2(src, dst)
        except Exception as e:
            print(f"⚠️ 文件复制失败：{src} → {dst} ：{e}")
            continue

    conn.close()
    print(f"🎉 完成！所有文件已还原至：{output_dir}")


def run(input_path, output_path):
    """Command wrapper for CLI usage."""
    restore_backup_structure(input_path, output_path)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Restore iOS backup structure using Manifest.db")
    parser.add_argument("--input", required=True, help="解密后的备份目录（包含 Manifest.db）")
    parser.add_argument("--output", required=True, help="输出还原目录")

    args = parser.parse_args()
    run(args.input, args.output)
