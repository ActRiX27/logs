import re
import json

md_file = "ios_sysdiagnose_report.md"
out_file = "device_info.json"

# 去掉 Markdown 加粗符号
def clean_text(t):
    return re.sub(r"\*\*", "", t).strip()

# 去掉 Markdown 干扰后处理字段内容
def clean_value(v):
    if not v:
        return "Unknown"
    return clean_text(v).strip()

# 准备结果字典
result = {
    "device_name": "Unknown",
    "product_type": "Unknown",
    "ios_version": "Unknown",
    "build": "Unknown",
    "scan_time": "Unknown",
    "mvt_version": "Unknown"
}

# 正则模式（更宽松）
patterns = {
    "device_name": r"检测设备[：:]\s*(.+)",
    "product_type": r"(?:设备型号|ProductType).*?[：:]\s*([A-Za-z0-9_,\.]+)",
    "ios_version": r"iOS\s*版本[：:]\s*([\d\.]+)",
    "build": r"Build[：:]\s*([A-Za-z0-9]+)",
    "scan_time": r"(?:扫描时间|生成时间)[：:]\s*([0-9:\- +]+)",
    "mvt_version": r"MVT\s*版本[：:]\s*([\w\.]+)"
}

# 读取 MD 内容
with open(md_file, "r", encoding="utf-8", errors="ignore") as f:
    lines = f.readlines()

# 逐行扫描（允许一行多个字段）
for line in lines:
    text = clean_text(line)

    for key, pattern in patterns.items():
        matches = re.findall(pattern, text)
        if matches and result[key] == "Unknown":
            result[key] = clean_value(matches[0])

# 将结果写入 JSON
with open(out_file, "w", encoding="utf-8") as f:
    json.dump(result, f, indent=2, ensure_ascii=False)

print("[+] 已提取设备信息：")
print(json.dumps(result, indent=2, ensure_ascii=False))
print(f"[+] 输出文件：{out_file}")
