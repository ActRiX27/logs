import argparse
import json
import os
import re

DEFAULT_MD_FILE = "ios_sysdiagnose_report.md"
DEFAULT_OUT_FILE = "device_info.json"


def clean_text(text):
    """Remove markdown bold markers and trim whitespace."""
    return re.sub(r"\*\*", "", text).strip()


def clean_value(value):
    if not value:
        return "Unknown"
    return clean_text(value).strip()


def parse_device_info(md_file, out_file):
    result = {
        "device_name": "Unknown",
        "product_type": "Unknown",
        "ios_version": "Unknown",
        "build": "Unknown",
        "scan_time": "Unknown",
        "mvt_version": "Unknown",
    }

    patterns = {
        "device_name": r"检测设备[：:]\s*(.+)",
        "product_type": r"(?:设备型号|ProductType).*?[：:]\s*([A-Za-z0-9_,\.]+)",
        "ios_version": r"iOS\s*版本[：:]\s*([\d\.]+)",
        "build": r"Build[：:]\s*([A-Za-z0-9]+)",
        "scan_time": r"(?:扫描时间|生成时间)[：:]\s*([0-9:\- +]+)",
        "mvt_version": r"MVT\s*版本[：:]\s*([\w\.]+)",
    }

    with open(md_file, "r", encoding="utf-8", errors="ignore") as f:
        lines = f.readlines()

    for line in lines:
        text = clean_text(line)
        for key, pattern in patterns.items():
            matches = re.findall(pattern, text)
            if matches and result[key] == "Unknown":
                result[key] = clean_value(matches[0])

    out_dir = os.path.dirname(out_file)
    if out_dir:
        os.makedirs(out_dir, exist_ok=True)

    with open(out_file, "w", encoding="utf-8") as f:
        json.dump(result, f, indent=2, ensure_ascii=False)

    print("[+] 已提取设备信息：")
    print(json.dumps(result, indent=2, ensure_ascii=False))
    print(f"[+] 输出文件：{out_file}")
    return result


def run(src_md, out_path=None):
    return parse_device_info(src_md, out_path or DEFAULT_OUT_FILE)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Extract device info from sysdiagnose markdown report")
    parser.add_argument("--src", required=True, help="ios_sysdiagnose_report.md 路径")
    parser.add_argument("--out", required=False, default=DEFAULT_OUT_FILE, help="输出 JSON 路径")
    args = parser.parse_args()

    run(args.src, args.out)
