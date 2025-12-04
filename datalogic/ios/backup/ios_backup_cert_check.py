#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
iOS 备份证书检测脚本（描述文件证书 + App 企业签名）
======================================================
可检测内容：
 - 描述文件中的证书（Root / PEM / PKCS1 / PKCS12）
 - App embedded.mobileprovision（TeamID / TeamName / 企业信息）
 - 证书标识、证书信息、签发应用、所属企业

无法检测（备份无法提供）：
 - 系统 Root CA（TrustStore）
 - Keychain 客户端证书
 - WiFi/VPN 客户端证书
"""

import os
import json
import plistlib
import base64
import argparse
from datalogic.utils import json_safe


# ===========================================
# JSON 安全（由 datalogic.utils.json_safe 统一处理）
# ===========================================


# ===========================================
# 相对路径 (restored_tree/...)
# ===========================================

def rel(root, abs_path):
    if abs_path.startswith(root):
        return "restored_tree" + abs_path[len(root):]
    return abs_path


# ===========================================
# 文件搜索
# ===========================================

def find_files(base, filename):
    results = []
    for root, dirs, files in os.walk(base):
        if filename in files:
            results.append(os.path.join(root, filename))
    return results


# ===========================================
# 解析描述文件（Profile）中的证书
# ===========================================

def parse_profile_certs(root):
    profile_candidates = [
        "HomeDomain/Library/Preferences/com.apple.managedconfiguration.profiled.plist",
        "ManagedConfigurationDomain/Library/Preferences/com.apple.managedconfiguration.profiled.plist",
        "HomeDomain/Library/ConfigurationProfiles/EffectiveUserSettings.plist",
    ]

    plist_path = None
    for c in profile_candidates:
        p = os.path.join(root, c)
        if os.path.exists(p):
            plist_path = p
            break

    if not plist_path:
        return []

    data = plistlib.load(open(plist_path, "rb"))
    manifest = data.get("ProfileManifest") or data.get("_MCProfile")
    if not manifest:
        return []

    results = []
    for uuid, pf in manifest.items():

        for payload in pf.get("PayloadContent", []):
            ptype = payload.get("PayloadType")

            if ptype not in [
                "com.apple.security.root",
                "com.apple.security.pem",
                "com.apple.security.pkcs1",
                "com.apple.security.pkcs12",
            ]:
                continue

            cert_bytes = payload.get("PayloadContent", b"")

            results.append({
                "Source": "Profile",
                "ProfileName": pf.get("PayloadDisplayName"),
                "Organization": pf.get("PayloadOrganization"),
                "PayloadIdentifier": payload.get("PayloadIdentifier"),
                "PayloadType": ptype,
                "CertificateBase64": base64.b64encode(cert_bytes).decode("utf-8"),
                "Path": rel(root, plist_path),
            })

    return results


# ===========================================
# 解析 App embedded.mobileprovision（企业签名）
# ===========================================

def parse_app_provision(path, root):

    with open(path, "rb") as f:
        raw = f.read()

    try:
        plist_part = raw.split(b"<?xml")[1]
        plist_data = plistlib.loads(b"<?xml" + plist_part)
    except:
        return None

    team_id = plist_data.get("TeamIdentifier", ["Unknown"])[0]
    team_name = plist_data.get("TeamName", "Unknown")
    app_id = plist_data.get("Entitlements", {}).get("application-identifier", "Unknown")

    return {
        "Source": "AppSignature",
        "AppIdentifier": app_id,
        "TeamIdentifier": team_id,
        "Organization": team_name,
        "Path": rel(root, path),
    }


# ===========================================
# Markdown 输出
# ===========================================

def write_md(path, profile_certs, app_certs):
    with open(path, "w", encoding="utf-8") as f:

        f.write("# 📜 iOS 备份证书检测报告\n\n")
        f.write(f"- 生成时间：{datetime.now()}\n")
        f.write("- 本报告基于 iOS 备份数据（restored_tree）生成。\n")
        f.write("- 检测内容：描述文件证书 + 企业签名证书。\n")
        f.write("- 无法检测：系统 Root CA、Keychain、WiFi/VPN 证书（备份不包含）。\n\n")

        f.write("## 🔹 1. 描述文件证书（Profile Installed Certificates）\n\n")
        if not profile_certs:
            f.write("未检测到描述文件证书。\n\n")
        else:
            for c in profile_certs:
                f.write(f"- Profile：{c['ProfileName']}\n")
                f.write(f"  - PayloadIdentifier：{c['PayloadIdentifier']}\n")
                f.write(f"  - 组织：{c['Organization']}\n")
                f.write(f"  - 类型：{c['PayloadType']}\n")
                f.write(f"  - 路径：{c['Path']}\n\n")

        f.write("\n## 🔹 2. App 企业签名证书（Enterprise Signing Certificates）\n\n")
        if not app_certs:
            f.write("未检测到企业签名 App。\n\n")
        else:
            for a in app_certs:
                f.write(f"- 应用：{a['AppIdentifier']}\n")
                f.write(f"  - TeamIdentifier（企业标识）：{a['TeamIdentifier']}\n")
                f.write(f"  - 企业名称：{a['Organization']}\n")
                f.write(f"  - 路径：{a['Path']}\n\n")


# ===========================================
# 主入口
# ===========================================

def main(root, out):
    if not out:
        out = os.getcwd()

    os.makedirs(out, exist_ok=True)

    profile_certs = parse_profile_certs(root)

    prov_files = find_files(root, "embedded.mobileprovision")
    app_certs = []
    for p in prov_files:
        info = parse_app_provision(p, root)
        if info:
            app_certs.append(info)

    final = {
        "profile_certificates": profile_certs,
        "app_certificates": app_certs,
        "note": (
            "iOS 备份不包含 TrustStore 和 Keychain，因此无法检测系统根证书、"
            "WiFi/VPN 客户端证书、私钥。可检测的部分包括："
            "描述文件证书和 App 企业签名证书。"
        )
    }

    with open(os.path.join(out, "cert_analysis.json"), "w", encoding="utf-8") as f:
        json.dump(json_safe(final), f, ensure_ascii=False, indent=2)

    write_md(os.path.join(out, "cert_report.md"), profile_certs, app_certs)

    print("✔ JSON：", os.path.join(out, "cert_analysis.json"))
    print("✔ Markdown：", os.path.join(out, "cert_report.md"))
    print("完成！")


def run(input_path, out_path=None):
    """Command wrapper for CLI usage."""
    return main(input_path, out_path)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="iOS 备份证书检测脚本")
    parser.add_argument("--input", required=True, help="restored_tree 根目录")
    parser.add_argument("--out", required=False, help="输出目录")
    args = parser.parse_args()

    run(args.input, args.out)
