#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
iOS 越狱 / 插件 / 系统分区新增文件 检测脚本
最终版：v10（基于 v9，适配 iOS 17，新增日志落盘）
"""

import os
import json

# ============================================================
# 1. 越狱路径规则（文件系统侧） —— 适配 iOS 17 / rootless
# ============================================================
JB_PATH_RULES = [
    # 经典越狱 App
    "/Applications/Cydia.app",
    "/Applications/Sileo.app",
    "/Applications/Zebra.app",

    # 旧体系
    "/Library/MobileSubstrate",
    "/usr/lib/TweakInject",
    "/usr/lib/substrate",
    "/etc/apt",
    "/usr/bin/ssh",
    "/bin/bash",

    # iOS 15–17 rootless 越狱关键路径
    "/var/jb",
    "/private/preboot",
    "/var/containers/Bundle/jb",
    "/usr/libexec/substituted",
    "/usr/libexec/substitute-inserter",
    "/usr/libexec/ellekit/loader",
    "/usr/lib/ellekit",
]

# ============================================================
# 2. 系统分区前缀（用于“系统分区新增文件检测”）
# ============================================================
SYSTEM_PARTITIONS = [
    "/System/",
    "/usr/",
    "/sbin/",
    "/bin/",
    "/private/preboot/",
    "/private/var/db/",
    "/Library/Preferences/",
    "/Library/Extensions/",
]

# ============================================================
# 3. 行为侧关键字（OSLog） —— 含 iOS17 关键字
# ============================================================

# 越狱框架关键字（包括 rootless / ElleKit）
JB_KEYWORDS = [
    "Substrate",
    "MobileSubstrate",
    "Substitute",
    "ElleKit",
    "libhooker",
    "TweakInject",
    "tweakinject",
    "jailbreakd",
    "substituted",
    "rootless",
]

# task_for_pid / 权限提升相关关键字
TFP_KEYWORDS = [
    "task_for_pid",
    "violated policy: task_for_pid",
    "get-task-allow",
    "req_tfp_policy",
    "mac_task_check",
    "SecTaskCopyValueForEntitlement",
]

# 签名异常 / CoreTrust / amfid 相关关键字
SIGNATURE_KEYWORDS = [
    "amfid",
    "CoreTrust",
    "coretrustd",
    "signature invalid",
    "signature evaluation",
    "CTEvaluateSignature",
    "ProcessSignaturePolicy",
    "failed to validate",
    "no matching provisioning",
]

# ============================================================
# load_device_info
# ============================================================
def load_device_info(path="device_info.json"):
    if not os.path.exists(path):
        print(f"[!] 未找到设备信息文件：{path}")
        return {}
    try:
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
        return data if isinstance(data, dict) else {}
    except Exception as e:
        print(f"[!] 读取设备信息失败：{e}")
        return {}

# ============================================================
# load_filesystem
# ============================================================
def load_filesystem(path="filesystem.json"):
    if not os.path.exists(path):
        print(f"[!] 未找到 filesystem.json：{path}")
        return []

    try:
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
    except Exception as e:
        print(f"[!] 解析 filesystem.json 失败：{e}")
        return []

    paths = []

    # 常见格式：list
    if isinstance(data, list):
        for item in data:
            if isinstance(item, str):
                paths.append(item)
            elif isinstance(item, dict) and "path" in item:
                paths.append(item["path"])
        return sorted(set(paths))

    # 兼容 dict 包装的情况
    if isinstance(data, dict):
        for v in data.values():
            if isinstance(v, list):
                for item in v:
                    if isinstance(item, str):
                        paths.append(item)
                    elif isinstance(item, dict) and "path" in item:
                        paths.append(item["path"])
        return sorted(set(paths))

    return []

# ============================================================
# load_system_baseline
# ============================================================
def load_system_baseline(path="system_baseline.json"):
    if not os.path.exists(path):
        print(f"[!] 未找到 system_baseline.json，系统分区新增文件检测将跳过。")
        return set()
    try:
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
        if isinstance(data, list):
            return set([x for x in data if isinstance(x, str)])
        return set()
    except Exception as e:
        print(f"[!] 解析 system_baseline.json 失败：{e}")
        return set()

# ============================================================
# 文件系统越狱路径扫描
# ============================================================
def scan_fs(paths):
    hits = []
    for p in paths:
        for rule in JB_PATH_RULES:
            if rule in p:
                hits.append(p)
    return sorted(set(hits))

# ============================================================
# 插件 / Tweak 扫描
# ============================================================
def scan_tweaks(paths):
    tweaks = []
    for p in paths:
        if not isinstance(p, str):
            continue

        # 动态库 + 典型越狱目录
        if ".dylib" in p and (
            "Substrate" in p or
            "TweakInject" in p or
            "/var/jb" in p or
            "ellekit" in p.lower()
        ):
            tweaks.append(p)

        # DynamicLibraries / Tweak 注入规则
        if p.endswith(".plist") and (
            "DynamicLibraries" in p or
            "TweakInject" in p
        ):
            tweaks.append(p)

    return sorted(set(tweaks))

# ============================================================
# 系统分区新增文件（与 baseline diff）
# ============================================================
def scan_system_new_files(fs_paths, baseline_set):
    if not baseline_set:
        return [], []

    new_files = []
    suspicious = []

    for p in fs_paths:
        if not isinstance(p, str):
            continue

        # 只关心系统分区
        if not any(p.startswith(pref) for pref in SYSTEM_PARTITIONS):
            continue

        if p not in baseline_set:
            new_files.append(p)

            base = os.path.basename(p)

            # /bin /usr/bin /sbin 下的无后缀文件，可能是新增可执行
            if ("/bin/" in p or "/usr/bin/" in p or "/sbin/" in p) and "." not in base:
                suspicious.append(p)

            # 新增 dylib
            if p.endswith(".dylib"):
                suspicious.append(p)

    return sorted(set(new_files)), sorted(set(suspicious))

# ============================================================
# OSLog 扫描（行为侧）
# ============================================================
def scan_oslog(path="oslog_full.txt", log_dir="output/logs"):
    results = {
        "jb": [],
        "tfp": [],
        "signature": [],
        "stats": {
            "total_lines": 0,
            "jb_rules": len(JB_KEYWORDS),
            "tfp_rules": len(TFP_KEYWORDS),
            "sig_rules": len(SIGNATURE_KEYWORDS),
        },
    }

    if not os.path.exists(path):
        print(f"[!] 未找到 OSLog：{path}")
        return results

    with open(path, "r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            results["stats"]["total_lines"] += 1
            L = line.strip()

            if any(k in L for k in JB_KEYWORDS):
                results["jb"].append(L)

            if any(k in L for k in TFP_KEYWORDS):
                results["tfp"].append(L)

            if any(k in L for k in SIGNATURE_KEYWORDS):
                results["signature"].append(L)

    # === 新增：将命中的日志全部落盘，便于后续核查 ===
    os.makedirs(log_dir, exist_ok=True)

    with open(os.path.join(log_dir, "jb_keyword_hits.txt"), "w", encoding="utf-8") as f:
        f.write("\n".join(results["jb"]))

    with open(os.path.join(log_dir, "tfp_hits.txt"), "w", encoding="utf-8") as f:
        f.write("\n".join(results["tfp"]))

    with open(os.path.join(log_dir, "signature_hits.txt"), "w", encoding="utf-8") as f:
        f.write("\n".join(results["signature"]))

    print(f"[+] 行为日志命中已保存到目录：{log_dir}")

    return results

# ============================================================
# 生成 Markdown 报告（保持 v9 风格）
# ============================================================
def generate_report(out_path, device_info, fs_hits, tweaks, log_hits, new_sys, exec_hits):
    with open(out_path, "w", encoding="utf-8") as md:
        md.write("# iOS 越狱 / 插件 / 系统分区新增文件 检测报告（v10 / iOS17 扩展版）\n\n")

        md.write("## 0. 设备信息\n")
        md.write(f"- iOS 版本：{device_info.get('ios_version')}\n")
        md.write(f"- 设备型号：{device_info.get('product_type')}\n\n")

        md.write("## 1. 文件系统越狱路径扫描\n")
        if fs_hits:
            for p in fs_hits:
                md.write(f"> {p}\n")
        else:
            md.write("- 未命中越狱路径\n\n")

        md.write("## 2. 插件扫描（Tweak）\n")
        if tweaks:
            for p in tweaks:
                md.write(f"> {p}\n")
        else:
            md.write("- 未发现疑似插件\n\n")

        md.write("## 3. OSLog 行为侧检测\n")
        md.write(f"- 日志行数：{log_hits['stats']['total_lines']}\n")
        md.write(f"- 越狱关键字规则数：{log_hits['stats']['jb_rules']}\n")
        md.write(f"- task_for_pid 规则数：{log_hits['stats']['tfp_rules']}\n")
        md.write(f"- 签名异常规则数：{log_hits['stats']['sig_rules']}\n\n")
        md.write("> 说明：所有命中的原始日志已完整保存在 `output/logs/` 目录中，报告中仅展示部分样例。\n\n")

        md.write("### 3.1 越狱框架关键字样例\n")
        if log_hits["jb"]:
            for ln in log_hits["jb"][:20]:
                md.write(f"> {ln}\n")
        else:
            md.write("- 无命中\n")

        md.write("\n### 3.2 task_for_pid 越权样例\n")
        if log_hits["tfp"]:
            for ln in log_hits["tfp"][:20]:
                md.write(f"> {ln}\n")
        else:
            md.write("- 未检测到越权 tfp\n")

        md.write("\n### 3.3 签名异常（amfid / CoreTrust）样例\n")
        if log_hits["signature"]:
            for ln in log_hits["signature"][:20]:
                md.write(f"> {ln}\n")
        else:
            md.write("- 未见签名异常\n")

        md.write("\n## 4. 系统分区新增文件（基于 baseline）\n")
        if new_sys:
            for p in new_sys[:50]:
                md.write(f"> {p}\n")
            if len(new_sys) > 50:
                md.write(f"\n… 共 {len(new_sys)} 条，详见原始数据。\n")
        else:
            md.write("- 未发现新增系统分区文件\n")

        md.write("\n### 4.1 可疑可执行 / 动态库\n")
        if exec_hits:
            for p in exec_hits:
                md.write(f"> {p}\n")
        else:
            md.write("- 无可疑可执行文件\n")

    print(f"[+] 报告已生成：{out_path}")

# ============================================================
# main
# ============================================================
if __name__ == "__main__":
    print("[+] 加载设备信息 device_info.json ...")
    device = load_device_info()

    print("[+] 加载文件系统快照 filesystem.json ...")
    fs_paths = load_filesystem()

    print("[+] 加载系统分区基线 system_baseline.json ...")
    baseline = load_system_baseline()

    print("[+] 扫描文件系统越狱路径 ...")
    fs_hits = scan_fs(fs_paths)

    print("[+] 扫描插件 / Tweak 文件 ...")
    tweaks = scan_tweaks(fs_paths)

    print("[+] 扫描行为日志 oslog_full.txt ...")
    log_hits = scan_oslog(path="oslog_full.txt", log_dir="output/logs")

    print("[+] 扫描系统分区新增文件 ...")
    new_sys, exec_hits = scan_system_new_files(fs_paths, baseline)

    print("[+] 生成越狱检测报告 jailbreak_report.md ...")
    generate_report("jailbreak_report.md", device, fs_hits, tweaks, log_hits, new_sys, exec_hits)

    print("[+] 完成。jailbreak_report.md 已生成。")
