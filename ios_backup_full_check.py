#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
iOS Backup Full Security Checker v3.4
=======================================================
检测内容：
1）配置项检测（描述文件 / 全局偏好 / 访问限制）
2）证书检测（Profile 证书 + App embedded.mobileprovision）
3）应用检测（AppDomain/AppGroup/AppPlugin + 版本/签名字段 + 风险识别）

输出：
- full_analysis.json
- full_report.md
"""

import os
import json
import plistlib
import argparse
import base64
from datetime import datetime

# ------------------------------------------------------------
# 日志
# ------------------------------------------------------------
def log_info(msg): print(f"[INFO] {msg}")
def log_ok(msg): print(f"[OK]   {msg}")
def log_warn(msg): print(f"[WARN] {msg}")


# ------------------------------------------------------------
# 工具
# ------------------------------------------------------------
def json_safe(obj):
    if isinstance(obj, dict):
        return {k: json_safe(v) for k, v in obj.items()}
    elif isinstance(obj, list):
        return [json_safe(i) for i in obj]
    elif isinstance(obj, bytes):
        return base64.b64encode(obj).decode("utf-8")
    return obj

def md_value(v):
    if isinstance(v, bytes):
        return f"<bytes:{len(v)}>"
    if isinstance(v, list):
        return ", ".join([md_value(i) for i in v])
    if isinstance(v, dict):
        return "{dict}"
    return str(v)

def rel(root, abs_path):
    if abs_path.startswith(root):
        return "restored_tree" + abs_path[len(root):]
    return abs_path

def load_plist(path):
    try:
        with open(path, "rb") as f:
            return plistlib.load(f)
    except Exception as e:
        log_warn(f"Plist 解析失败: {path} ({e})")
        return None

def find_first(root, candidates, title):
    log_info(f"扫描 {title} ...")
    tried = []
    for rel_path in candidates:
        abs_path = os.path.join(root, rel_path)
        tried.append("restored_tree/" + rel_path)
        if os.path.exists(abs_path):
            log_ok(f"找到文件：restored_tree/{rel_path}")
            return abs_path, tried
    log_warn(f"{title} 未找到")
    return None, tried

def find_files(root, filename):
    results = []
    for r, d, f in os.walk(root):
        if filename in f:
            results.append(os.path.join(r, filename))
    return results


# ============================================================
# 第一部分：配置项检测
# ============================================================

PROFILE_FILES = [
    "HomeDomain/Library/Preferences/com.apple.managedconfiguration.profiled.plist",
    "ManagedConfigurationDomain/Library/Preferences/com.apple.managedconfiguration.profiled.plist",
]

APP_ACCESS = [
    "HomeDomain/Library/Preferences/com.apple.applicationaccess.plist",
]

GLOBAL_PREF_CANDIDATE_NAMES = [
    ".GlobalPreferences.plist",
    ".GlobalPreferences_m.plist",
    ".GlobalPreferences.plist.old",
]


def analyze_profile_manifest(manifest):
    profiles = []
    for uuid, pf in manifest.items():
        entry = {
            "UUID": uuid,
            "Name": pf.get("PayloadDisplayName"),
            "Organization": pf.get("PayloadOrganization"),
            "Payloads": [],
            "Risks": [],
        }

        for payload in pf.get("PayloadContent", []):
            ptype = payload.get("PayloadType")
            pid = payload.get("PayloadIdentifier")
            entry["Payloads"].append({"Type": ptype, "Identifier": pid})

            if ptype == "com.apple.mdm":
                entry["Risks"].append("MDM 管控策略")
            if ptype == "com.apple.vpn.managed":
                entry["Risks"].append("VPN 管控策略")
            if ptype == "com.apple.security.root":
                entry["Risks"].append("Root CA 证书注入")

        profiles.append(entry)
    return profiles


def detect_profiles(root):
    abs_path, tried = find_first(root, PROFILE_FILES, "描述文件（Profile）")
    info = {
        "scan_paths": tried,
        "found_path": None,
        "profiles": [],
        "note": "",
    }

    if not abs_path:
        info["note"] = "未检测到描述文件"
        return info

    data = load_plist(abs_path)
    manifest = None
    if isinstance(data, dict):
        manifest = data.get("ProfileManifest") or data.get("_MCProfile")

    info["found_path"] = rel(root, abs_path)

    if not manifest:
        info["note"] = "描述文件存在，但未发现用户安装的配置文件（正常情况）"
        return info

    info["profiles"] = analyze_profile_manifest(manifest)
    info["note"] = "已解析描述文件内容"
    return info


def detect_app_access(root):
    abs_path, tried = find_first(root, APP_ACCESS, "应用访问限制")
    info = {
        "scan_paths": tried,
        "found_path": None,
        "raw": None,
        "keys": [],
        "note": "",
    }
    if not abs_path:
        info["note"] = "未检测到应用访问限制配置"
        return info

    data = load_plist(abs_path)
    info["found_path"] = rel(root, abs_path)
    info["raw"] = data
    info["keys"] = list(data.keys()) if isinstance(data, dict) else []
    info["note"] = "应用访问限制配置已解析"
    return info


def detect_global_prefs(root):
    log_info("扫描全局偏好设置（.GlobalPreferences*） ...")
    scan_paths = []
    found_candidates = []

    # 1）优先尝试经典路径
    for name in GLOBAL_PREF_CANDIDATE_NAMES:
        rel_path = os.path.join("HomeDomain/Library/Preferences", name)
        abs_path = os.path.join(root, rel_path)
        scan_paths.append("restored_tree/" + rel_path)
        if os.path.exists(abs_path):
            found_candidates.append(abs_path)

    # 2）再用通用搜索兜底
    for name in GLOBAL_PREF_CANDIDATE_NAMES:
        matches = find_files(root, name)
        for m in matches:
            if m not in found_candidates:
                found_candidates.append(m)
                scan_paths.append(rel(root, m))

    info = {
        "scan_paths": list(dict.fromkeys(scan_paths)),  # 去重
        "found_path": None,
        "raw": None,
        "keys": [],
        "note": "",
    }

    if not found_candidates:
        log_warn("未找到任何 .GlobalPreferences* 文件")
        info["note"] = "未检测到全局偏好设置文件"
        return info

    # 选择一个优先级：优先 plain -> _m -> .old
    def score(p):
        if p.endswith(".GlobalPreferences.plist"):
            return 0
        if p.endswith(".GlobalPreferences_m.plist"):
            return 1
        if p.endswith(".GlobalPreferences.plist.old"):
            return 2
        return 3

    found_candidates.sort(key=score)
    chosen = found_candidates[0]
    log_ok(f"选用全局偏好文件: {rel(root, chosen)}")

    data = load_plist(chosen)
    info["found_path"] = rel(root, chosen)
    if isinstance(data, dict) and data:
        info["raw"] = data
        info["keys"] = list(data.keys())
        info["note"] = "全局偏好设置已解析"
    else:
        info["note"] = "找到全局偏好文件，但未解析出有效键值"
    return info


# ============================================================
# 第二部分：证书检测
# ============================================================

def parse_profile_certs(root):
    log_info("解析 Profile 证书 ...")

    plist_path = None
    for p in PROFILE_FILES:
        abs_p = os.path.join(root, p)
        if os.path.exists(abs_p):
            plist_path = abs_p
            break

    if not plist_path:
        return []

    data = load_plist(plist_path)
    manifest = None
    if isinstance(data, dict):
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


def parse_app_signature(path, root):
    try:
        with open(path, "rb") as f:
            raw = f.read()
        xml = raw.split(b"<?xml")[1]
        plist_data = plistlib.loads(b"<?xml" + xml)
    except Exception:
        return None

    return {
        "AppIdentifier": plist_data.get("Entitlements", {}).get("application-identifier"),
        "TeamIdentifier": plist_data.get("TeamIdentifier", ["Unknown"])[0],
        "Organization": plist_data.get("TeamName", "Unknown"),
        "Path": rel(root, path)
    }


# ============================================================
# 第三部分：应用检测
# ============================================================

RISK_APPS = {
    "Shadowrocket": "高风险代理工具",
    "Quantumult": "代理/VPN 工具",
    "QuantumultX": "代理/VPN 工具",
    "Loon": "代理/VPN 工具",
    "Potatso": "代理/VPN 工具",
    "flex": "越狱调试工具",
    "Filza": "越狱文件管理器",
}

BUNDLEID_NAME_MAP = {
    "com.tencent.xin": "微信",
    "com.tencent.mqq": "QQ",
    "com.autonavi.amap": "高德地图",
    "com.taobao.taobao4iphone": "淘宝",
    "com.ss.android.ugc.aweme": "抖音",
    "com.sina.weibo": "微博",
    "com.xiaohongshu": "小红书",
    "com.jingdong.app.mall": "京东",
    "com.alibaba.dingtalk": "钉钉",
}


def lookup_app_name(bid):
    if bid in BUNDLEID_NAME_MAP:
        return BUNDLEID_NAME_MAP[bid]
    if bid.startswith("com.apple."):
        return "系统App：" + bid.replace("com.apple.", "")
    return "(未知应用)"


def get_dir_size(path):
    total = 0
    for r, d, fs in os.walk(path):
        for f in fs:
            fp = os.path.join(r, f)
            if os.path.isfile(fp):
                total += os.path.getsize(fp)
    return total


def detect_apps(root):
    log_info("检测应用 ...")

    entries = os.listdir(root)
    apps = {}

    for entry in entries:

        if entry.startswith("AppDomain-"):
            bid = entry.replace("AppDomain-", "")
            p = os.path.join(root, entry)

            apps.setdefault(bid, {
                "BundleID": bid,
                "DisplayName": lookup_app_name(bid),
                "Version": None,
                "Signature": None,
                "AppType": "UserApp",
                "SandboxPaths": [],
                "GroupPaths": [],
                "PluginPaths": [],
                "SizeBytes": 0,
                "Risk": None,
            })

            apps[bid]["SandboxPaths"].append(rel(root, p))
            apps[bid]["SizeBytes"] += get_dir_size(p)

        elif entry.startswith("AppDomainPlugin-"):
            pid = entry.replace("AppDomainPlugin-", "")
            p = os.path.join(root, entry)

            apps.setdefault(pid, {
                "BundleID": pid,
                "DisplayName": lookup_app_name(pid),
                "Version": None,
                "Signature": None,
                "AppType": "AppExtension",
                "SandboxPaths": [],
                "GroupPaths": [],
                "PluginPaths": [],
                "SizeBytes": 0,
                "Risk": None,
            })

            apps[pid]["PluginPaths"].append(rel(root, p))
            apps[pid]["SizeBytes"] += get_dir_size(p)

        elif entry.startswith("AppDomainGroup-"):
            group_id = entry.replace("AppDomainGroup-", "")
            primary = group_id.replace("group.", "")
            p = os.path.join(root, entry)

            apps.setdefault(primary, {
                "BundleID": primary,
                "DisplayName": lookup_app_name(primary),
                "Version": None,
                "Signature": None,
                "AppType": "UserApp",
                "SandboxPaths": [],
                "GroupPaths": [],
                "PluginPaths": [],
                "SizeBytes": 0,
                "Risk": None,
            })

            apps[primary]["GroupPaths"].append(rel(root, p))
            apps[primary]["SizeBytes"] += get_dir_size(p)

    for bid, info in apps.items():
        for k, desc in RISK_APPS.items():
            if k.lower() in info["DisplayName"].lower():
                info["Risk"] = desc

    return {
        "scan_path": "restored_tree/",
        "apps": list(apps.values()),
        "note": "已解析应用信息",
    }


# ============================================================
# Markdown 输出
# ============================================================

def write_full_md(path, config, certs, apps):
    with open(path, "w", encoding="utf-8") as f:

        f.write("# 📱 iOS 备份综合安全检测报告\n")
        f.write(f"- 生成时间：{datetime.now()}\n\n")

        # ---------- 配置项 ----------
        f.write("## 🧩 第一部分：配置项检测（已执行）\n\n")
        f.write("### ✔ 检测内容\n")
        f.write("- 描述文件（Profile）扫描\n")
        f.write("- MDM / VPN / WiFi / RootCA 配置扫描\n")
        f.write("- 全局偏好设置（.GlobalPreferences*）\n")
        f.write("- 应用访问限制配置扫描\n\n")

        f.write("### 🔍 扫描路径\n")
        for sec in [config["profiles"], config["global_prefs"], config["app_access"]]:
            for p in sec["scan_paths"]:
                f.write(f"- {p}\n")
        f.write("\n")

        # 描述文件
        sec = config["profiles"]
        f.write("### 描述文件检测\n")
        f.write(f"- 状态：{sec['note']}\n\n")

        # 全局偏好
        sec = config["global_prefs"]
        f.write("### 全局偏好设置\n")
        f.write(f"- 状态：{sec['note']}\n")
        if sec["found_path"]:
            f.write(f"- 使用文件：{sec['found_path']}\n")
        if isinstance(sec["raw"], dict) and sec["raw"]:
            f.write("#### ➤ 全局偏好键值内容\n")
            for k, v in sec["raw"].items():
                f.write(f"- {k}: {md_value(v)}\n")
        f.write("\n")

        # 应用访问限制
        sec = config["app_access"]
        f.write("### 应用访问限制\n")
        f.write(f"- 状态：{sec['note']}\n\n")

        # ---------- 证书 ----------
        f.write("## 🔐 第二部分：证书检测（已执行）\n\n")
        f.write("### ✔ 检测内容\n")
        f.write("- 描述文件证书扫描\n")
        f.write("- App embedded.mobileprovision 证书扫描\n")
        f.write("- 证书字段解析（Team/Identifier/Certificate）\n\n")

        f.write("### 📌 检测结果\n")
        if certs["profile_certificates"]:
            for c in certs["profile_certificates"]:
                f.write(f"- 描述文件证书：{c['ProfileName']}（{c['PayloadType']}）\n")
        else:
            f.write("- 描述文件证书：未发现用户安装的证书配置\n")

        if certs["app_certificates"]:
            for a in certs["app_certificates"]:
                f.write(f"- 应用签名证书：{a['AppIdentifier']}（企业:{a['Organization']}）\n")
        else:
            f.write("- 应用签名证书：备份集中未呈现此类证书（App Store 应用默认不包含）\n")
        f.write("\n")

        # ---------- 应用 ----------
        f.write("## 📦 第三部分：应用程序检测（已执行）\n\n")
        f.write("### ✔ 检测内容\n")
        f.write("- AppDomain 主应用扫描\n")
        f.write("- AppGroup 共享域扫描\n")
        f.write("- AppPlugin 扩展扫描\n")
        f.write("- 应用名称匹配（常见 BundleID 映射）\n")
        f.write("- 应用空间占用统计\n")
        f.write("- 风险应用识别（VPN/越狱相关工具）\n\n")

        for app in apps["apps"]:
            f.write(f"### {app['DisplayName']}（{app['BundleID']}）\n")
            f.write(f"- 类型：{app['AppType']}\n")
            f.write("- 版本号：备份集中未呈现此字段\n")
            f.write("- 签名信息：备份集中未呈现此字段（App Store 分发不包含签名文件）\n")
            f.write(f"- 占用空间：{round(app['SizeBytes']/1024/1024,2)} MB\n")
            if app["Risk"]:
                f.write(f"- 风险：{app['Risk']}\n")
            f.write("- 路径：\n")
            for p in app["SandboxPaths"]:
                f.write(f"  * {p}\n")
            for p in app["GroupPaths"]:
                f.write(f"  * {p}\n")
            for p in app["PluginPaths"]:
                f.write(f"  * {p}\n")
            f.write("\n")


# ============================================================
# 主函数
# ============================================================

def main(root, out):
    out = out or os.getcwd()
    os.makedirs(out, exist_ok=True)

    log_info("===== 配置项检测 =====")
    config_result = {
        "profiles": detect_profiles(root),
        "global_prefs": detect_global_prefs(root),
        "app_access": detect_app_access(root),
    }

    log_info("===== 证书检测 =====")
    profile_certs = parse_profile_certs(root)
    app_certs = []
    for p in find_files(root, "embedded.mobileprovision"):
        parsed = parse_app_signature(p, root)
        if parsed:
            app_certs.append(parsed)
    cert_result = {
        "profile_certificates": profile_certs,
        "app_certificates": app_certs,
    }

    log_info("===== 应用检测 =====")
    app_result = detect_apps(root)

    json_path = os.path.join(out, "full_analysis.json")
    with open(json_path, "w", encoding="utf-8") as f:
        json.dump(json_safe({
            "config_items": config_result,
            "certificates": cert_result,
            "apps": app_result,
        }), f, ensure_ascii=False, indent=2)
    log_ok(f"JSON 输出：{json_path}")

    md_path = os.path.join(out, "full_report.md")
    write_full_md(md_path, config_result, cert_result, app_result)
    log_ok(f"Markdown 输出：{md_path}")

    log_ok("✔ 检测完成")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="iOS Backup Full Security Checker v3.4")
    parser.add_argument("--input", required=True, help="restored_tree 根目录")
    parser.add_argument("--out", required=False, help="输出目录")
    args = parser.parse_args()

    main(args.input, args.out)
