#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
iOS Privileged FS Full Checker · FS++

版本：2025.02-FS++

适用于：
  ✓ 提权备份文件系统（private/var/...）
  ✓ 解密备份 restored_tree

保持原有能力（无删减）：
  ✓ 自动识别 FS 类型
  ✓ 高速构建文件索引（仅扫描一次）
  ✓ 描述文件检测（ConfigurationProfiles）
  ✓ GlobalPreferences / Managed Preferences 检测
  ✓ 应用扫描（Info.plist）
  ✓ embedded.mobileprovision 解析（若存在）
  ✓ 输出 JSON + Markdown 报告

新增能力：
  ✓ App 数据容器扫描（mobile/Containers/Data/Application）
  ✓ AppGroup 容器扫描（mobile/Containers/Shared/AppGroup）
  ✓ 越狱 / tweak / 签名绕过路径检测
  ✓ 系统分区新增文件对比（可选：baseline JSON）
  ✓ OSLog 行为侧关键字统计（可选：oslog_full.txt）
"""

import os
import sys
import json
import plistlib
import argparse
from typing import Dict, Any, List
from datetime import datetime


# ============================================================
# 基础日志
# ============================================================

def log(msg: str):
    print(f"[INFO] {msg}")

def warn(msg: str):
    print(f"[WARN] {msg}")

def ok(msg: str):
    print(f"[OK] {msg}")


# ============================================================
# JSON 安全转换（解决 datetime / 其他不可序列化对象）
# ============================================================

def make_json_safe(obj):
    if isinstance(obj, dict):
        return {k: make_json_safe(v) for k, v in obj.items()}
    elif isinstance(obj, list):
        return [make_json_safe(i) for i in obj]
    elif isinstance(obj, datetime):
        return obj.isoformat()
    else:
        return obj


# ============================================================
# 1. 根路径规范化
# ============================================================

def normalize_root(path: str) -> str:
    """
    自动识别提权备份结构：
    - 输入 private 根目录 → 自动定位到 private/var
    - 输入 var 根目录 → 直接使用
    - 其他情况保留原始路径（兼容 restored_tree）
    """
    p = os.path.abspath(path)
    base = os.path.basename(p)

    if base == "private" and os.path.isdir(os.path.join(p, "var")):
        var_path = os.path.join(p, "var")
        log(f"检测到提权备份 private 根目录，已经切换到 {var_path}")
        return var_path

    if base == "var" and os.path.isdir(os.path.join(p, "mobile")):
        log(f"检测到提权备份 var 根目录：{p}")
        return p

    log(f"可能是 restored_tree 结构：{p}")
    return p


# ============================================================
# 2. 构建文件系统索引（提速关键）
# ============================================================

def build_fs_index(root: str) -> Dict[str, Any]:
    """
    一次性扫描全盘，加速后续查找。
    返回：
        files_map: {文件名: [绝对路径列表]}
        info_plists: 全部 Info.plist 绝对路径
        mobileprov: embedded.mobileprovision 路径
        all_files: 全部文件绝对路径列表（用于系统分区对比）
    """
    log("正在构建文件系统索引（可能需要几秒）...")

    files_map: Dict[str, List[str]] = {}
    info_plists: List[str] = []
    mobileprov: List[str] = []
    all_files: List[str] = []

    for cur, dirs, files in os.walk(root):
        for name in files:
            abs_path = os.path.join(cur, name)
            all_files.append(abs_path)

            files_map.setdefault(name, []).append(abs_path)

            if name == "Info.plist":
                info_plists.append(abs_path)

            if name == "embedded.mobileprovision":
                mobileprov.append(abs_path)

    ok(f"索引构建完成：共 {len(files_map)} 类文件，Info.plist 数量 {len(info_plists)}")
    return {
        "files_map": files_map,
        "info_plists": info_plists,
        "mobileprov": mobileprov,
        "all_files": all_files,
    }


# ============================================================
# 3. 读取 plist
# ============================================================

def read_plist(path: str):
    try:
        with open(path, "rb") as f:
            return plistlib.load(f)
    except Exception as e:
        warn(f"读取 plist 失败：{path} → {e}")
        return None


# ============================================================
# 4. 描述文件检测（ConfigurationProfiles）
# ============================================================

def detect_profiles_fs(root: str) -> Dict[str, Any]:
    cp_root = os.path.join(
        root,
        "containers/Shared/SystemGroup/systemgroup.com.apple.configurationprofiles/Library/ConfigurationProfiles"
    )

    if not os.path.isdir(cp_root):
        warn("未找到 ConfigurationProfiles 目录（可能无配置描述文件）")
        return {"exists": False}

    results: Dict[str, Any] = {"exists": True, "path": cp_root, "files": []}

    for f in os.listdir(cp_root):
        fp = os.path.join(cp_root, f)
        if f.endswith(".plist") and os.path.isfile(fp):
            pl = read_plist(fp)
            results["files"].append({
                "name": f,
                "path": fp,
                "content_keys": list(pl.keys()) if isinstance(pl, dict) else None,
            })

    ok(f"描述文件目录扫描完成，文件数：{len(results['files'])}")
    return results


# ============================================================
# 5. GlobalPreferences + ManagedPreferences 检测
# ============================================================

def detect_preferences(root: str) -> Dict[str, Any]:
    paths = [
        os.path.join(root, "mobile/Library/Preferences/.GlobalPreferences.plist"),
        os.path.join(root, "Managed Preferences/mobile/.GlobalPreferences.plist")
    ]

    res: Dict[str, Any] = {"global": None, "managed": None}

    if os.path.exists(paths[0]):
        res["global"] = {
            "path": paths[0],
            "plist": read_plist(paths[0])
        }

    if os.path.exists(paths[1]):
        res["managed"] = {
            "path": paths[1],
            "plist": read_plist(paths[1])
        }

    ok(f"偏好设置检测完成（global：{bool(res['global'])}, managed：{bool(res['managed'])}）")
    return res


# ============================================================
# 6. 应用扫描（Info.plist）
# ============================================================

def _is_app_info_plist(path: str) -> bool:
    p = path.replace("\\", "/")
    lower = p.lower()

    # 用户应用容器
    if "/containers/bundle/application/" in lower:
        return True

    # 系统应用
    if "/applications/" in lower:
        return True

    return False


def detect_applications(fs_index: Dict[str, Any], root: str) -> List[Dict[str, Any]]:
    apps: List[Dict[str, Any]] = []

    for info in fs_index.get("info_plists", []):
        if not _is_app_info_plist(info):
            continue

        pl = read_plist(info) or {}

        apps.append({
            "info_path": info,
            "name": pl.get("CFBundleDisplayName") or pl.get("CFBundleName"),
            "bundle_id": pl.get("CFBundleIdentifier"),
            "version": pl.get("CFBundleShortVersionString"),
            "build": pl.get("CFBundleVersion"),
        })

    ok(f"应用扫描完成，共识别 {len(apps)} 个应用")
    return apps


# ============================================================
# 7. embedded.mobileprovision 解析
# ============================================================

def detect_mobileprovision(fs_index: Dict[str, Any]) -> List[Dict[str, Any]]:
    provs: List[Dict[str, Any]] = []

    for p in fs_index.get("mobileprov", []):
        pl = read_plist(p)
        if not isinstance(pl, dict):
            continue

        ent = pl.get("Entitlements", {})
        provs.append({
            "path": p,
            "app_id": ent.get("application-identifier"),
            "team_id": ent.get("com.apple.developer.team-identifier"),
            "get_task_allow": ent.get("get-task-allow"),
        })

    ok(f"mobileprovision 证书检测完毕，数量 {len(provs)}")
    return provs


# ============================================================
# 8. App 数据容器扫描（mobile/Containers/Data/Application）
# ============================================================

def scan_data_containers(root: str) -> Dict[str, Any]:
    data_root = os.path.join(root, "mobile/Containers/Data/Application")
    result: Dict[str, Any] = {
        "exists": False,
        "path": data_root,
        "containers": []
    }

    if not os.path.isdir(data_root):
        warn("未找到 App 数据容器目录（mobile/Containers/Data/Application）")
        return result

    result["exists"] = True

    # 避免超慢：只做轻量统计（文件数 + 是否存在关键子目录）
    for uuid in sorted(os.listdir(data_root)):
        cpath = os.path.join(data_root, uuid)
        if not os.path.isdir(cpath):
            continue

        has_docs = os.path.isdir(os.path.join(cpath, "Documents"))
        has_lib = os.path.isdir(os.path.join(cpath, "Library"))
        has_tmp = os.path.isdir(os.path.join(cpath, "tmp"))

        # 轻量级文件数统计（不计算体积，避免杀硬盘）
        file_count = 0
        for cur, dirs, files in os.walk(cpath):
            file_count += len(files)

        result["containers"].append({
            "uuid": uuid,
            "path": cpath,
            "has_documents": has_docs,
            "has_library": has_lib,
            "has_tmp": has_tmp,
            "file_count": file_count,
        })

    ok(f"App 数据容器扫描完成，共 {len(result['containers'])} 个容器")
    return result


# ============================================================
# 9. AppGroup 容器扫描（mobile/Containers/Shared/AppGroup）
# ============================================================

def scan_app_groups(root: str) -> Dict[str, Any]:
    grp_root = os.path.join(root, "mobile/Containers/Shared/AppGroup")
    result: Dict[str, Any] = {
        "exists": False,
        "path": grp_root,
        "groups": []
    }

    if not os.path.isdir(grp_root):
        warn("未找到 AppGroup 目录（mobile/Containers/Shared/AppGroup）")
        return result

    result["exists"] = True

    for name in sorted(os.listdir(grp_root)):
        gpath = os.path.join(grp_root, name)
        if not os.path.isdir(gpath):
            continue

        file_count = 0
        for cur, dirs, files in os.walk(gpath):
            file_count += len(files)

        result["groups"].append({
            "name": name,
            "path": gpath,
            "file_count": file_count,
        })

    ok(f"AppGroup 容器扫描完成，共 {len(result['groups'])} 个 AppGroup")
    return result


# ============================================================
# 10. 越狱 / Tweak / 签名绕过路径检测
# ============================================================

_JB_SUSPECT_PATHS = [
    "/Applications/Cydia.app",
    "/Applications/Zebra.app",
    "/Applications/Sileo.app",
    "/Applications/Saily.app",
    "/Library/MobileSubstrate/MobileSubstrate.dylib",
    "/Library/MobileSubstrate/DynamicLibraries",
    "/usr/lib/substrate",
    "/usr/lib/TweakInject",
    "/var/jb",
    "/var/root/Media/Cydia",
    "/private/var/stash",
]

_JB_KEYWORDS_IN_PATH = [
    "Substrate",
    "Substitute",
    "ElleKit",
    "libhooker",
    "jailbreak",
    "tweak",
    "substrate",
    "jailbreakd",
]

def detect_jailbreak(root: str, fs_index: Dict[str, Any]) -> Dict[str, Any]:
    result: Dict[str, Any] = {
        "suspect_paths_exists": [],
        "keyword_hits": [],
    }

    # 绝对路径存在性检测（适配 root 前缀）
    for rel in _JB_SUSPECT_PATHS:
        # rel 可能以 / 开头，拼接时剥离一个斜杠
        normalized_rel = rel.lstrip("/")
        candidate = os.path.join(root, "..", normalized_rel)
        if os.path.exists(candidate):
            result["suspect_paths_exists"].append(candidate)

    # 关键字命中（在索引中搜索）
    for path in fs_index.get("all_files", []):
        lower = path.lower()
        for kw in _JB_KEYWORDS_IN_PATH:
            if kw.lower() in lower:
                result["keyword_hits"].append(path)
                break

    ok(f"越狱 / Tweak 路径检测完成：疑似路径 {len(result['suspect_paths_exists'])} 个，关键字命中 {len(result['keyword_hits'])} 条")
    return result


# ============================================================
# 11. 系统分区新增文件检测（可选 baseline）
# ============================================================

def load_baseline(baseline_path: str):
    if not baseline_path:
        return None
    if not os.path.isfile(baseline_path):
        warn(f"系统基线文件不存在：{baseline_path}")
        return None
    try:
        with open(baseline_path, "r", encoding="utf-8") as f:
            data = json.load(f)
        # 允许两种形式：{"files": [...]} 或直接 [... path list ...]
        if isinstance(data, dict) and "files" in data:
            return set(data["files"])
        elif isinstance(data, list):
            return set(data)
        else:
            warn("系统基线 JSON 格式不符合预期，忽略")
            return None
    except Exception as e:
        warn(f"读取系统基线失败：{e}")
        return None


def detect_system_new_files(root: str, fs_index: Dict[str, Any], baseline_path: str) -> Dict[str, Any]:
    """
    仅在提供 baseline 的情况下执行。
    baseline 应包含系统分区“正常文件列表”，用于对比检测新增条目。
    """
    if not baseline_path:
        return {
            "enabled": False,
            "reason": "未提供 baseline 路径",
            "new_files": []
        }

    baseline_set = load_baseline(baseline_path)
    if baseline_set is None:
        return {
            "enabled": False,
            "reason": "baseline 读取失败或格式不正确",
            "new_files": []
        }

    # 提取看起来属于系统分区的路径
    system_like_prefixes = (
        "/System/",
        "/usr/",
        "/bin/",
        "/sbin/",
        "/Applications/",
        "/private/var/staged_system_apps/",
    )

    new_files: List[str] = []

    for p in fs_index.get("all_files", []):
        # 把 root 上层当作 /（粗略归一化）
        # root 形如 .../private/var，我们取其上级作为“伪根”
        pseudo_root = os.path.abspath(os.path.join(root, ".."))
        rel = os.path.relpath(p, pseudo_root)
        rel_slash = "/" + rel.replace("\\", "/")

        if not rel_slash.startswith(system_like_prefixes):
            continue

        if rel_slash not in baseline_set:
            new_files.append(rel_slash)

    ok(f"系统分区新增文件检测完成：新增 {len(new_files)} 条")
    return {
        "enabled": True,
        "reason": "baseline 生效",
        "new_files": new_files,
    }


# ============================================================
# 12. OSLog 行为侧关键字检测（可选 oslog_full.txt）
# ============================================================

_OSLOG_KEYWORDS = {
    "coretrust": ["coretrust", "CTEvaluation", "CTEvaluateTrust"],
    "amfid": ["amfid", "AMFI", "AppleMobileFileIntegrity"],
    "task_for_pid": ["task_for_pid", "TFP", "tfp0"],
    "jailbreak": ["Substrate", "Substitute", "ElleKit", "jailbreak", "libhooker"],
    "containermanagerd": ["containermanagerd"],
    "mdm": ["ManagedConfiguration", "MCProfile", "MDM", "MCXPC"],
}

def analyze_oslog(oslog_path: str) -> Dict[str, Any]:
    if not oslog_path:
        return {
            "enabled": False,
            "reason": "未提供 oslog_full.txt 路径",
            "summary": {},
        }

    if not os.path.isfile(oslog_path):
        return {
            "enabled": False,
            "reason": f"OSLog 文件不存在：{oslog_path}",
            "summary": {},
        }

    counts = {k: 0 for k in _OSLOG_KEYWORDS.keys()}
    total_lines = 0

    try:
        with open(oslog_path, "r", encoding="utf-8", errors="ignore") as f:
            for line in f:
                total_lines += 1
                lower = line.lower()
                for tag, kws in _OSLOG_KEYWORDS.items():
                    for kw in kws:
                        if kw.lower() in lower:
                            counts[tag] += 1
                            break
    except Exception as e:
        return {
            "enabled": False,
            "reason": f"读取 OSLog 失败：{e}",
            "summary": {},
        }

    ok(f"OSLog 行为检测完成：共 {total_lines} 行，关键字命中统计：{counts}")
    return {
        "enabled": True,
        "reason": "OSLog 分析成功",
        "summary": {
            "total_lines": total_lines,
            "keyword_counts": counts,
        },
    }


# ============================================================
# 13. 输出报告（JSON + Markdown）
# ============================================================

def write_json(path: str, data: Dict[str, Any]):
    safe = make_json_safe(data)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(safe, f, ensure_ascii=False, indent=2)
    ok(f"JSON 输出：{path}")


def write_md(path: str, data: Dict[str, Any]):
    with open(path, "w", encoding="utf-8") as f:
        f.write("# iOS 提权文件系统检测报告（FS Full Check · FS++）\n\n")

        # 1. 描述文件
        f.write("## 描述文件（MDM/Profiles）\n")
        p = data.get("profiles", {})
        if p.get("exists"):
            f.write(f"- 路径：`{p['path']}`\n")
            f.write(f"- 数量：{len(p.get('files', []))}\n")
            for item in p.get("files", []):
                f.write(f"  - {item.get('name')}\n")
        else:
            f.write("- 未找到描述文件目录\n")

        # 2. 偏好设置
        f.write("\n## 偏好设置（Preferences）\n")
        prefs = data.get("preferences", {})
        if prefs.get("global"):
            f.write(f"- GlobalPreferences：`{prefs['global']['path']}`\n")
        if prefs.get("managed"):
            f.write(f"- Managed Preferences：`{prefs['managed']['path']}`\n")

        # 3. 应用列表
        f.write("\n## 应用列表（来自 Info.plist 扫描）\n")
        apps = data.get("apps", [])
        if not apps:
            f.write("- 未识别到应用（可能为精简提权备份或系统分区缺失）\n")
        else:
            for app in apps[:50]:
                name = app.get("name") or "<未知名称>"
                bid = app.get("bundle_id") or "<无 Bundle ID>"
                f.write(f"- {name} ({bid})\n")
            f.write("\n（仅展示前 50 个）\n")

        # 4. embedded.mobileprovision
        f.write("\n## embedded.mobileprovision\n")
        provs = data.get("provision", [])
        if not provs:
            f.write("- 未检测到 embedded.mobileprovision\n")
        else:
            for prov in provs:
                f.write(f"- {prov.get('path')} → AppID: {prov.get('app_id')}\n")

        # 5. App 数据容器
        f.write("\n## App 数据容器（mobile/Containers/Data/Application）\n")
        dc = data.get("data_containers", {})
        if not dc.get("exists"):
            f.write("- 未找到数据容器目录\n")
        else:
            f.write(f"- 路径：`{dc['path']}`\n")
            f.write(f"- 容器数量：{len(dc.get('containers', []))}\n")
            for c in dc.get("containers", [])[:20]:
                f.write(
                    f"  - {c.get('uuid')}（files={c.get('file_count')}, "
                    f"Documents={c.get('has_documents')}, "
                    f"Library={c.get('has_library')}, "
                    f"tmp={c.get('has_tmp')}）\n"
                )
            if len(dc.get("containers", [])) > 20:
                f.write("  - ...（仅展示前 20 个）\n")

        # 6. AppGroup 容器
        f.write("\n## AppGroup 容器（mobile/Containers/Shared/AppGroup）\n")
        ag = data.get("app_groups", {})
        if not ag.get("exists"):
            f.write("- 未找到 AppGroup 目录\n")
        else:
            f.write(f"- 路径：`{ag['path']}`\n")
            f.write(f"- AppGroup 数量：{len(ag.get('groups', []))}\n")
            for g in ag.get("groups", [])[:20]:
                f.write(
                    f"  - {g.get('name')}（files={g.get('file_count')}）\n"
                )
            if len(ag.get("groups", [])) > 20:
                f.write("  - ...（仅展示前 20 个）\n")

        # 7. 越狱 / Tweak 检测
        f.write("\n## 越狱 / 插件（Tweak）检测\n")
        jb = data.get("jailbreak", {})
        sp = jb.get("suspect_paths_exists", [])
        kh = jb.get("keyword_hits", [])
        f.write(f"- 可疑绝对路径命中：{len(sp)} 条\n")
        for pth in sp[:20]:
            f.write(f"  - {pth}\n")
        if len(sp) > 20:
            f.write("  - ...（仅展示前 20 条）\n")

        f.write(f"- 关键字命中（Substrate/ElleKit 等）：{len(kh)} 条\n")
        if len(kh) > 0:
            for pth in kh[:20]:
                f.write(f"  - {pth}\n")
            if len(kh) > 20:
                f.write("  - ...（仅展示前 20 条）\n")

        # 8. 系统分区新增文件
        f.write("\n## 系统分区新增文件检测\n")
        sd = data.get("system_diff", {})
        if not sd.get("enabled"):
            f.write(f"- 未启用：{sd.get('reason', '未提供 baseline')}\n")
        else:
            nf = sd.get("new_files", [])
            f.write(f"- 新增文件数量：{len(nf)}\n")
            for pth in nf[:50]:
                f.write(f"  - {pth}\n")
            if len(nf) > 50:
                f.write("  - ...（仅展示前 50 条）\n")

        # 9. OSLog 行为检测
        f.write("\n## OSLog 行为检测概览\n")
        osres = data.get("oslog", {})
        if not osres.get("enabled"):
            f.write(f"- 未启用：{osres.get('reason', '未提供 OSLog 文件')}\n")
        else:
            summary = osres.get("summary", {})
            f.write(f"- OSLog 总行数：{summary.get('total_lines', 0)}\n")
            kc = summary.get("keyword_counts", {})
            for tag, cnt in kc.items():
                f.write(f"  - {tag}: {cnt} 条\n")

    ok(f"Markdown 输出：{path}")


# ============================================================
# 14. 主流程
# ============================================================

def main(input_path: str, out_path: str, baseline_path: str = None, oslog_path: str = None):
    root = normalize_root(input_path)
    os.makedirs(out_path, exist_ok=True)

    fs_index = build_fs_index(root)

    profiles = detect_profiles_fs(root)
    prefs = detect_preferences(root)
    apps = detect_applications(fs_index, root)
    prov = detect_mobileprovision(fs_index)
    data_containers = scan_data_containers(root)
    app_groups = scan_app_groups(root)
    jb = detect_jailbreak(root, fs_index)
    system_diff = detect_system_new_files(root, fs_index, baseline_path)
    oslog_res = analyze_oslog(oslog_path)

    result: Dict[str, Any] = {
        "profiles": profiles,
        "preferences": prefs,
        "apps": apps,
        "provision": prov,
        "data_containers": data_containers,
        "app_groups": app_groups,
        "jailbreak": jb,
        "system_diff": system_diff,
        "oslog": oslog_res,
    }

    write_json(os.path.join(out_path, "fs_analysis.json"), result)
    write_md(os.path.join(out_path, "fs_report.md"), result)

    ok("检测流程结束")


# ============================================================
# 启动
# ============================================================

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="iOS 提权备份文件系统全量扫描工具 · FS++")
    parser.add_argument("--input", "-i", required=True, help="提权备份根目录（private 或 var，亦可为 restored_tree 根）")
    parser.add_argument("--out", "-o", required=True, help="输出目录")
    parser.add_argument("--baseline", "-b", required=False, help="系统基线 JSON 文件（可选）")
    parser.add_argument("--oslog", required=False, help="OSLog 文本文件路径（oslog_full.txt，可选）")
    args = parser.parse_args()

    main(args.input, args.out, baseline_path=args.baseline, oslog_path=args.oslog)
