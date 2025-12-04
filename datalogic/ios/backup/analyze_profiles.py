#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
iOS 备份可检测配置项（最终成品版）
==========================================
仅检测备份能提供的数据：
 - 描述文件（Profile / Payload / MDM）
 - 全局偏好（.GlobalPreferences.plist）
 - 应用访问限制（com.apple.applicationaccess.plist）

满足你的要求：
 - 扫描路径显示为 restored_tree 相对路径
 - Markdown 显示完整 GlobalPreferences 内容
 - bytes 自动转 base64 或摘要形式
 - JSON 输出安全序列化
"""

import os
import sys
import json
import plistlib
import argparse
import base64
from datetime import datetime


# ==========================================================
# JSON 安全转换（bytes → base64）
# ==========================================================

def json_safe(obj):
    if isinstance(obj, dict):
        return {k: json_safe(v) for k, v in obj.items()}
    elif isinstance(obj, list):
        return [json_safe(v) for v in obj]
    elif isinstance(obj, bytes):
        return base64.b64encode(obj).decode("utf-8")
    return obj


# ==========================================================
# 用于 Markdown 的 bytes 简化显示
# ==========================================================

def md_safe_value(value):
    if isinstance(value, bytes):
        return f"<bytes: {len(value)} bytes base64 encoded>"
    if isinstance(value, list):
        out = ""
        for v in value:
            out += f"  - {md_safe_value(v)}\n"
        return out
    if isinstance(value, dict):
        out = ""
        for k, v in value.items():
            out += f"  - {k}: {md_safe_value(v)}\n"
        return out
    return str(value)


# ==========================================================
# 备份中“真实存在”的配置项路径
# ==========================================================

PROFILE_FILES = [
    "HomeDomain/Library/Preferences/com.apple.managedconfiguration.profiled.plist",
    "ManagedConfigurationDomain/Library/Preferences/com.apple.managedconfiguration.profiled.plist",
    "HomeDomain/Library/ConfigurationProfiles/EffectiveUserSettings.plist",
    "ConfigurationProfilesDomain/Library/ConfigurationProfiles/profiled.plist",
]

GLOBAL_PREFS = [
    "HomeDomain/Library/Preferences/.GlobalPreferences.plist",
]

APP_ACCESS = [
    "HomeDomain/Library/Preferences/com.apple.applicationaccess.plist",
]


# ==========================================================
# 工具函数
# ==========================================================

def load_plist(path):
    with open(path, "rb") as f:
        return plistlib.load(f)

def make_rel_path(root, abs_path):
    if abs_path.startswith(root):
        return "restored_tree" + abs_path[len(root):]
    return abs_path

def find_first(root, candidates):
    tried = []
    for rel in candidates:
        abs_path = os.path.join(root, rel)
        tried.append(make_rel_path(root, abs_path))
        if os.path.exists(abs_path):
            return abs_path, tried
    return None, tried


# ==========================================================
# 描述文件解析逻辑
# ==========================================================

def analyze_profile_manifest(manifest):
    profiles = []
    flags = {
        "profiles_present": False,
        "mdm_present": False,
        "vpn_payload_present": False,
        "root_ca_present": False,
        "wifi_managed_present": False,
        "web_filter_present": False,
    }

    for uuid, pf in manifest.items():
        flags["profiles_present"] = True

        entry = {
            "UUID": uuid,
            "Name": pf.get("PayloadDisplayName"),
            "Organization": pf.get("PayloadOrganization"),
            "Description": pf.get("PayloadDescription"),
            "Type": pf.get("PayloadType"),
            "Payloads": [],
            "Risks": [],
        }

        for payload in pf.get("PayloadContent", []):
            ptype = payload.get("PayloadType")
            pidentifier = payload.get("PayloadIdentifier")

            entry["Payloads"].append({
                "PayloadType": ptype,
                "PayloadIdentifier": pidentifier,
            })

            if ptype == "com.apple.mdm":
                flags["mdm_present"] = True
                entry["Risks"].append("MDM 管控策略")

            if ptype == "com.apple.vpn.managed":
                flags["vpn_payload_present"] = True
                entry["Risks"].append("VPN 管控策略")

            if ptype == "com.apple.security.root":
                flags["root_ca_present"] = True
                entry["Risks"].append("Root CA 证书强制注入")

            if ptype == "com.apple.wifi.managed":
                flags["wifi_managed_present"] = True
                entry["Risks"].append("受控 WiFi 策略")

            if ptype == "com.apple.webcontent-filter":
                flags["web_filter_present"] = True
                entry["Risks"].append("Web 内容过滤（监控/家长控制）")

        profiles.append(entry)

    return profiles, flags


def detect_profiles(root):
    abs_path, tried = find_first(root, PROFILE_FILES)

    info = {
        "scan_paths": tried,
        "found_path": None,
        "profiles": [],
        "flags": {},
        "note": "",
    }

    if not abs_path:
        info["note"] = "设备未安装任何描述文件（Profile/MDM）"
        return info

    info["found_path"] = make_rel_path(root, abs_path)

    data = load_plist(abs_path)
    manifest = data.get("ProfileManifest") or data.get("_MCProfile")

    if not manifest:
        info["note"] = "描述文件配置存在，但不包含 Profile 内容（设备无 Profile）"
        return info

    profiles, flags = analyze_profile_manifest(manifest)
    info["profiles"] = profiles
    info["flags"] = flags
    info["note"] = "检测到描述文件并成功解析"

    return info


# ==========================================================
# 通用可检测项
# ==========================================================

def detect_simple(root, candidates, title):
    abs_path, tried = find_first(root, candidates)

    info = {
        "scan_paths": tried,
        "found_path": None,
        "keys": [],
        "raw": None,
        "note": "",
    }

    if not abs_path:
        info["note"] = f"{title} 文件不存在（可能未写入，全属正常）"
        return info

    info["found_path"] = make_rel_path(root, abs_path)

    data = load_plist(abs_path)
    info["raw"] = data
    info["keys"] = list(data.keys())
    info["note"] = f"{title} 已解析"

    return info


# ==========================================================
# Markdown 输出
# ==========================================================

def write_md(path, result):
    with open(path, "w", encoding="utf-8") as f:
        f.write("# 📱 iOS 备份可检测配置项报告（最终成品版）\n\n")
        f.write(f"- 生成时间：{datetime.now()}\n")
        f.write("- 包含：描述文件 / 全局偏好 / 应用限制\n\n")

        for name, data in result.items():

            f.write(f"## 🔹 {name}\n\n")

            f.write("### 扫描路径\n")
            for p in data["scan_paths"]:
                f.write(f"- {p}\n")
            f.write("\n")

            f.write(f"### 解析说明\n{data['note']}\n\n")

            if data["found_path"]:
                f.write(f"**找到文件：** `{data['found_path']}`\n\n")

            # Profiles
            if name == "profiles" and data["profiles"]:
                f.write("### 描述文件列表\n")
                for p in data["profiles"]:
                    f.write(f"- 名称：{p['Name']}\n")
                    f.write(f"  - 组织：{p['Organization']}\n")
                    f.write(f"  - 风险：{p['Risks']}\n")
                    f.write(f"  - Payloads：\n")
                    for pl in p["Payloads"]:
                        f.write(f"    - {pl['PayloadType']} ({pl['PayloadIdentifier']})\n")
                f.write("\n")

            # 全局偏好设置 — 输出完整内容
            if name == "global_prefs" and data["raw"]:
                f.write("### 全局偏好内容\n")
                for k, v in data["raw"].items():
                    f.write(f"- {k}: {md_safe_value(v)}\n")
                f.write("\n")

            # ApplicationAccess 也输出全部内容
            if name == "app_access" and data["raw"]:
                f.write("### 应用访问限制内容\n")
                for k, v in data["raw"].items():
                    f.write(f"- {k}: {md_safe_value(v)}\n")
                f.write("\n")


# ==========================================================
# 主逻辑
# ==========================================================

def main(root, out):
    if not out:
        out = os.getcwd()

    os.makedirs(out, exist_ok=True)

    result = {
        "profiles": detect_profiles(root),
        "global_prefs": detect_simple(root, GLOBAL_PREFS, "全局偏好设置"),
        "app_access": detect_simple(root, APP_ACCESS, "应用访问限制"),
    }

    # JSON 输出
    safe_json = json_safe(result)
    json_path = os.path.join(out, "backup_config_analysis.json")
    with open(json_path, "w", encoding="utf-8") as f:
        json.dump(safe_json, f, ensure_ascii=False, indent=2)

    # Markdown 输出
    md_path = os.path.join(out, "backup_config_report.md")
    write_md(md_path, result)

    print("✔ JSON 输出：", json_path)
    print("✔ Markdown 输出：", md_path)
    print("🎉 完成！")


# ==========================================================
# 程序入口
# ==========================================================


def run(input_path, out_path=None):
    """Command wrapper for CLI usage."""
    return main(input_path, out_path)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="iOS 备份可检测配置项（最终成品版）")
    parser.add_argument("--input", required=True, help="restored_tree 根目录")
    parser.add_argument("--out", required=False, help="输出目录")
    args = parser.parse_args()

    run(args.input, args.out)
