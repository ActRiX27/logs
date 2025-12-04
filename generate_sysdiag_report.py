#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
iOS sysdiagnose 综合安全分析脚本（含路径脱敏，融合原 v13_t2 功能）

能力：
- 文件系统扫描（越狱路径 / 调试路径 / IOC 文本匹配 / 扩展名统计）
- 解码 system_logs.logarchive（使用 macOS `log show --archive`）
- trustd / TLS、NetworkExtension、RunningBoard、Profile / MDM 日志分析
- 提权 / 越狱行为侧特征（CoreTrust / amfid / MFI / sandbox / entitlement / task_for_pid）
- IOC 匹配（FS + OSLog）
- 输出 JSON + Markdown 报告
- 为每个模块生成 raw 日志文件（out/raw/*.log）
- 对分析中涉及本机源目录的路径进行脱敏（<SRC_ROOT>）
"""

import os
import sys
import json
import plistlib
import argparse
import subprocess
from datetime import datetime
from collections import Counter

# ---------------------------
# 规则定义
# ---------------------------

JAILBREAK_PATH_RULES = [
    "/Applications/Cydia.app",
    "/Applications/Sileo.app",
    "/Applications/Zebra.app",
    "/Applications/Filza.app",
    "/bin/bash",
    "/usr/sbin/sshd",
    "/usr/bin/ssh",
    "/etc/apt",
    "/var/lib/apt",
    "/var/lib/dpkg",
    "/Library/MobileSubstrate",
    "/MobileSubstrate/DynamicLibraries",
    "/var/jb",
    "/.installed_yaluX",
    "/.cydia_no_stash",
    "/usr/libexec/ssh-keysign",
    "/usr/libexec/substrate",
    "SubstrateLoader.dylib",
    "TweakInject",
]

DEV_DEBUG_PATH_RULES = [
    "/Developer",
    "Xcode.app",
    ".xcodeproj",
    ".xcworkspace",
    ".lldb",
    "debugserver",
    "/usr/lib/libimobiledevice",
    "/usr/bin/lldb",
    "frida-server",
    "frida-gadget",
    "cycript",
    "gdb",
]

IOC_KEYWORDS = [
    "apple-cloud-service.com",
    "mobileconfig.apple-exe-sync.com",
    "icloud-sync-update.com",
    "data-storage-cloud-update.com",
]

TEXT_EXTS = {
    ".txt", ".log", ".conf", ".cfg", ".ini", ".json",
    ".xml", ".plist", ".csv", ".md", ".html", ".htm"
}

# ---------------------------
# 工具函数
# ---------------------------

def classify_severity(count, high, medium):
    if count >= high:
        return "HIGH"
    if count >= medium:
        return "MEDIUM"
    if count > 0:
        return "LOW"
    return "NORMAL"


def safe_read_text(path, max_bytes=64 * 1024):
    try:
        with open(path, "rb") as f:
            data = f.read(max_bytes)
        return data.decode("utf-8", errors="ignore")
    except Exception:
        return ""


# ---------------------------
# 主类：综合分析器（由 v13_t2 版本整合）
# ---------------------------

class SysDiagReport:
    def __init__(self, src_dir, out_dir):
        # 真实 sysdiagnose 根目录（仅内部使用，不写入报告）
        self.src_dir_real = os.path.abspath(src_dir)
        self.src_dir = self.src_dir_real

        self.out_dir = os.path.abspath(out_dir)
        os.makedirs(self.out_dir, exist_ok=True)

        self.raw_dir = os.path.join(self.out_dir, "raw")
        os.makedirs(self.raw_dir, exist_ok=True)

        self.report = {
            "version": "merged_sysdiag",
            "generated_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "src_dir": "<SRC_ROOT>",  # 报告中不暴露真实路径
            "device_info": {},
            "summary": {},
            "chapters": []
        }

        self.fs_ext_counter = Counter()
        self.jb_matches = []
        self.dev_matches = []
        self.fs_ioc_matches = []
        self.oslog_ioc_matches = []

        self.total_files_scanned = 0
        self.total_text_files = 0
        self.device_info_source = "N/A"

    # 路径脱敏：把真实 src 根目录替换为 <SRC_ROOT>
    def sanitize_path(self, text: str) -> str:
        if not text:
            return text
        return text.replace(self.src_dir_real, "<SRC_ROOT>")

    # ---------------------------
    # 1. 设备信息（Info.plist）
    # ---------------------------
    def extract_device_info(self):
        candidates = [
            os.path.join(self.src_dir, "system_logs.logarchive", "Info.plist"),
            os.path.join(self.src_dir, "Info.plist"),
        ]
        info = {}
        log_path = os.path.join(self.raw_dir, "device_info.log")

        with open(log_path, "w") as log:
            log.write("[device_info] search paths:\n")
            for p in candidates:
                log.write(f"  check: {self.sanitize_path(p)}\n")
                if os.path.exists(p):
                    try:
                        with open(p, "rb") as f:
                            info = plistlib.load(f)
                        # 脱敏后的 Info.plist 来源路径
                        self.device_info_source = self.sanitize_path(p)
                        log.write(f"  -> FOUND & LOADED: {self.sanitize_path(p)}\n")
                        break
                    except Exception as e:
                        log.write(f"  -> FOUND but failed to load: {e}\n")
                else:
                    log.write("  -> not exists\n")

        dev = {
            "archive_id": info.get("ArchiveIdentifier", "N/A"),
            "os_version": info.get("OSVersion", "N/A"),
            "build": info.get("BuildVersion", "N/A"),
            "timezone": info.get("TimeZoneName", "N/A"),
        }

        self.report["device_info"] = dev
        self.report["chapters"].append({
            "id": "device_info",
            "title": "1. 设备信息",
            "severity": "INFO",
            "result": dev,
            "explain": (
                "从 sysdiagnose 或 system_logs.logarchive 内的 Info.plist 中解析设备基本信息，包括系统版本、"
                "构建号、采集时区等，仅用于环境描述，不直接参与异常判定。"
            )
        })

    # ---------------------------
    # 2. 文件系统扫描（路径规则 + 文本规则）
    # ---------------------------
    def scan_filesystem(self, max_paths=200000):
        jb_hits = []
        dev_hits = []
        ioc_hits = []
        walked = 0

        paths_log_path = os.path.join(self.raw_dir, "fs_paths_scanned.log")
        jb_log_path = os.path.join(self.raw_dir, "fs_jailbreak_rules_hits.log")
        dev_log_path = os.path.join(self.raw_dir, "fs_dev_debug_rules_hits.log")
        text_hits_log_path = os.path.join(self.raw_dir, "fs_text_keywords_hits.log")

        paths_log = open(paths_log_path, "w")
        jb_log = open(jb_log_path, "w")
        dev_log = open(dev_log_path, "w")
        text_hits_log = open(text_hits_log_path, "w")

        for root, dirs, files in os.walk(self.src_dir):
            for name in files:
                walked += 1
                full_path = os.path.join(root, name)
                # 只记录相对 sysdiagnose 根目录的路径，不暴露本机绝对路径
                rel_path = os.path.relpath(full_path, self.src_dir)
                paths_log.write(rel_path + "\n")

                ext = os.path.splitext(name)[1].lower()
                if ext:
                    self.fs_ext_counter[ext] += 1

                # 路径规则：越狱
                for r in JAILBREAK_PATH_RULES:
                    if r in rel_path:
                        jb_hits.append(rel_path)
                        jb_log.write(f"[PATH] rule={r} path={rel_path}\n")
                        break

                # 路径规则：开发/调试
                for r in DEV_DEBUG_PATH_RULES:
                    if r in rel_path:
                        dev_hits.append(rel_path)
                        dev_log.write(f"[PATH] rule={r} path={rel_path}\n")
                        break

                # 文本内容规则
                if ext in TEXT_EXTS:
                    self.total_text_files += 1
                    text = safe_read_text(full_path)
                    if not text:
                        continue

                    for r in JAILBREAK_PATH_RULES:
                        if r in text:
                            jb_hits.append(f"{rel_path} :: {r}")
                            text_hits_log.write(f"[JB_TEXT] rule={r} file={rel_path}\n")
                            break

                    for r in DEV_DEBUG_PATH_RULES:
                        if r in text:
                            dev_hits.append(f"{rel_path} :: {r}")
                            text_hits_log.write(f"[DEV_TEXT] rule={r} file={rel_path}\n")
                            break

                    for kw in IOC_KEYWORDS:
                        if kw in text:
                            ioc_hits.append(f"{rel_path} :: {kw}")
                            text_hits_log.write(f"[IOC_TEXT] ioc={kw} file={rel_path}\n")
                            break

                if walked >= max_paths:
                    break
            if walked >= max_paths:
                break

        paths_log.close()
        jb_log.close()
        dev_log.close()
        text_hits_log.close()

        self.total_files_scanned = walked
        self.jb_matches = jb_hits
        self.dev_matches = dev_hits
        self.fs_ioc_matches = ioc_hits

        # 扩展名统计日志
        ext_log_path = os.path.join(self.raw_dir, "fs_ext_stats.log")
        with open(ext_log_path, "w") as f:
            for ext, cnt in self.fs_ext_counter.most_common():
                f.write(f"{ext} {cnt}\n")

        jb_sev = classify_severity(len(jb_hits), high=5, medium=2)
        dev_sev = classify_severity(len(dev_hits), high=5, medium=2)

        self.report["chapters"].append({
            "id": "jailbreak_signs",
            "title": "2.1 越狱迹象（路径 & 内容规则）",
            "severity": jb_sev,
            "count": len(jb_hits),
            "samples": jb_hits[:50],
            "explain": (
                "遍历 sysdiagnose 解压目录，使用加强版越狱路径规则（如 /Applications/Cydia.app、"
                "/Library/MobileSubstrate、/var/jb 等）对文件路径以及文本内容进行匹配。"
            )
        })

        self.report["chapters"].append({
            "id": "dev_debug_signs",
            "title": "2.2 开发 / 调试迹象（路径 & 内容规则）",
            "severity": dev_sev,
            "count": len(dev_hits),
            "samples": dev_hits[:50],
            "explain": (
                "使用开发/调试相关路径规则（/Developer、Xcode、frida-server、debugserver 等），"
                "对路径和文本内容进行扫描，用于发现是否存在调试器、逆向工具、Hook 框架等痕迹。"
            )
        })

        top_ext = self.fs_ext_counter.most_common(30)
        self.report["chapters"].append({
            "id": "fs_ext_stats",
            "title": "2.3 文件系统扩展名统计（Top 30）",
            "severity": "INFO",
            "ext_stats": top_ext,
            "explain": (
                "对 sysdiagnose 中可见文件按扩展名进行统计，便于观察整体数据类型分布（日志、配置、脚本、动态库等）。"
            )
        })

    # ---------------------------
    # 3. 解码 OSLog（tracev3 -> raw/oslog_full.txt）
    # ---------------------------
    def decode_oslog(self):
        logarchive_path = os.path.join(self.src_dir, "system_logs.logarchive")
        if not os.path.isdir(logarchive_path):
            raise RuntimeError(f"未找到 system_logs.logarchive 目录: {logarchive_path}")

        from shutil import which
        if which("log") is None:
            raise RuntimeError("未找到 macOS `log` 命令，请在 macOS 环境运行本脚本。")

        oslog_txt = os.path.join(self.raw_dir, "oslog_full.txt")
        cmd = [
            "log", "show",
            "--archive", logarchive_path,
            "--info", "--debug"
        ]
        with open(oslog_txt, "w") as f:
            subprocess.run(cmd, stdout=f, stderr=subprocess.DEVNULL)
        return oslog_txt

    # ---------------------------
    # 4. OSLog 子系统分析
    # ---------------------------
    def analyze_oslog_subsystems(self, oslog_txt):
        trustd_lines = []
        ne_lines = []
        rb_lines = []
        profile_lines = []
        ioc_oslog_hits = []

        with open(oslog_txt, "r", errors="ignore") as f:
            for line in f:
                l = line.strip()
                lower = l.lower()

                if "trustd" in lower or "sectrust" in lower or "certificate" in lower:
                    trustd_lines.append(l)

                if "networkextension" in lower or "nevpn" in lower or "ikev2" in lower:
                    ne_lines.append(l)

                if "runningboard" in lower or "runningboardd" in lower:
                    rb_lines.append(l)

                if "profile" in lower or "mdm" in lower or "configurationprofile" in lower:
                    profile_lines.append(l)

                for kw in IOC_KEYWORDS:
                    if kw in l:
                        ioc_oslog_hits.append(l)
                        break

        # 写入 raw 日志
        with open(os.path.join(self.raw_dir, "oslog_trustd.log"), "w") as f:
            for l in trustd_lines:
                f.write(l + "\n")
        with open(os.path.join(self.raw_dir, "oslog_network_extension.log"), "w") as f:
            for l in ne_lines:
                f.write(l + "\n")
        with open(os.path.join(self.raw_dir, "oslog_runningboard.log"), "w") as f:
            for l in rb_lines:
                f.write(l + "\n")
        with open(os.path.join(self.raw_dir, "oslog_profile.log"), "w") as f:
            for l in profile_lines:
                f.write(l + "\n")

        self.oslog_ioc_matches = ioc_oslog_hits
        with open(os.path.join(self.raw_dir, "oslog_ioc_hits.log"), "w") as f:
            for l in ioc_oslog_hits:
                f.write(l + "\n")

        trustd_error_count = sum(
            1 for l in trustd_lines
            if any(x in l.lower() for x in ["error", "fail", "denied", "untrusted", "revoked"])
        )
        trustd_sev = classify_severity(trustd_error_count, high=10, medium=3)
        self.report["chapters"].append({
            "id": "trustd_tls",
            "title": "3.1 trustd / TLS 证书异常",
            "severity": trustd_sev,
            "total_entries": len(trustd_lines),
            "error_entries": trustd_error_count,
            "samples": trustd_lines[:50],
            "explain": (
                "从 OSLog 文本中筛选包含 trustd、SecTrust、certificate 的日志，并统计其中包含 "
                "error/fail/denied/untrusted 等字样的条目数量，用于评估 TLS 证书链验证是否异常。"
            )
        })

        ne_error_count = sum(
            1 for l in ne_lines
            if any(x in l.lower() for x in ["error", "fail", "cannot", "denied"])
        )
        ne_sev = classify_severity(ne_error_count, high=5, medium=1)
        self.report["chapters"].append({
            "id": "network_extension",
            "title": "3.2 VPN / NetworkExtension 事件",
            "severity": ne_sev,
            "total_entries": len(ne_lines),
            "error_entries": ne_error_count,
            "samples": ne_lines[:50],
            "explain": (
                "从 OSLog 中筛选 NetworkExtension / NEVPN / IKEv2 相关日志，用于识别 VPN / 代理 / 隧道配置与错误。"
            )
        })

        rb_sev = classify_severity(len(rb_lines), high=100, medium=10)
        self.report["chapters"].append({
            "id": "runningboard",
            "title": "3.3 RunningBoard 进程活跃情况",
            "severity": rb_sev if rb_lines else "NORMAL",
            "total_entries": len(rb_lines),
            "samples": rb_lines[:50],
            "explain": (
                "RunningBoard / runningboardd 负责进程生命周期管理，其日志可以反映前后台切换、后台运行、"
                "进程被系统终止等行为，可用于辅助判断是否存在异常常驻进程。"
            )
        })

        profile_sev = classify_severity(len(profile_lines), high=10, medium=1)
        self.report["chapters"].append({
            "id": "profiles_mdm",
            "title": "3.4 描述文件 / MDM 相关日志",
            "severity": profile_sev if profile_lines else "NORMAL",
            "total_entries": len(profile_lines),
            "samples": profile_lines[:50],
            "explain": (
                "从 OSLog 中筛选 profile / MDM / ConfigurationProfile 关键字日志，用于识别描述文件安装、"
                "MDM 控制、证书下发等行为。"
            )
        })

    # ---------------------------
    # 5. 提权 / 越狱行为侧特征（OSLog）
    # ---------------------------
    def analyze_priv_esc_from_oslog(self, oslog_txt):
        suspicious_lines = []
        coretrust_allow = []
        entitlement_issues = []
        sandbox_exceptions = []
        task_for_pid_events = []

        priv_raw_path = os.path.join(self.raw_dir, "oslog_priv_esc_raw.log")
        priv_hits_path = os.path.join(self.raw_dir, "oslog_priv_esc_hits.log")

        priv_raw = open(priv_raw_path, "w")
        priv_hits = open(priv_hits_path, "w")

        with open(oslog_txt, "r", errors="ignore") as f:
            for line in f:
                l = line.strip()
                lower = l.lower()

                # 关注的行全部写入 raw
                if ("coretrust" in lower or "amfid" in lower or "mobilefileintegrity" in lower
                    or "code signature" in lower or "cs_invalid" in lower
                    or "entitlement" in lower
                    or "task_for_pid" in lower or "get-task-allow" in lower
                    or "sandbox" in lower):
                    priv_raw.write(l + "\n")

                # CoreTrust / amfid / MFI
                if ("coretrust" in lower or "amfid" in lower or "mobilefileintegrity" in lower
                    or "code signature" in lower or "cs_invalid" in lower):
                    if any(x in lower for x in ["error", "fail", "invalid", "denied"]) and \
                       any(x in lower for x in ["allow", "allowed", "override", "overriding", "bypass"]):
                        coretrust_allow.append(l)
                        priv_hits.write("[CORETRUST_ALLOW] " + l + "\n")
                    else:
                        suspicious_lines.append(l)

                # entitlement 异常
                if "entitlement" in lower:
                    if any(x in lower for x in ["invalid", "unsatisfied", "violation", "denied"]):
                        entitlement_issues.append(l)
                        priv_hits.write("[ENTITLEMENT] " + l + "\n")

                # task_for_pid / get-task-allow
                if "task_for_pid" in lower or "get-task-allow" in lower:
                    task_for_pid_events.append(l)
                    priv_hits.write("[TASK_FOR_PID] " + l + "\n")

                # sandbox 异常
                if "sandbox" in lower:
                    if any(x in lower for x in [
                        "exception", "add", "added", "grant", "granted",
                        "unsandbox", "remove profile", "no sandbox"
                    ]):
                        sandbox_exceptions.append(l)
                        priv_hits.write("[SANDBOX] " + l + "\n")

        priv_raw.close()
        priv_hits.close()

        score = (
            len(coretrust_allow) * 3 +
            len(entitlement_issues) * 2 +
            len(task_for_pid_events) * 2 +
            len(sandbox_exceptions)
        )

        if score >= 20:
            sev = "HIGH"
        elif score >= 8:
            sev = "MEDIUM"
        elif score > 0:
            sev = "LOW"
        else:
            sev = "NORMAL"

        self.report["chapters"].append({
            "id": "priv_esc_behavior",
            "title": "3.5 提权 / 越狱行为侧特征（OSLog）",
            "severity": sev,
            "score": score,
            "coretrust_allow_samples": coretrust_allow[:30],
            "entitlement_issue_samples": entitlement_issues[:30],
            "task_for_pid_samples": task_for_pid_events[:30],
            "sandbox_exception_samples": sandbox_exceptions[:30],
            "explain": (
                "基于 OSLog 文本，从 CoreTrust / amfid / MobileFileIntegrity / sandbox 子系统日志中抽取：\n"
                "1）签名验证错误但仍被 allow/override/bypass 的日志\n"
                "2）entitlement 权限违规（invalid/violation/denied）以及 get-task-allow/task_for_pid 相关事件\n"
                "3）sandbox profile 被修改、增加例外或出现 unsandbox/no sandbox 等关键词\n"
                "这些行为往往与提权、越狱、持久化注入等风险强相关。"
            )
        })

    # ---------------------------
    # 6. IOC 情报匹配（FS + OSLog）
    # ---------------------------
    def analyze_ioc(self):
        total_fs = len(self.fs_ioc_matches)
        total_oslog = len(self.oslog_ioc_matches)
        total = total_fs + total_oslog
        sev = classify_severity(total, high=5, medium=1)

        fs_ioc_log = os.path.join(self.raw_dir, "fs_ioc_hits.log")
        with open(fs_ioc_log, "w") as f:
            for l in self.fs_ioc_matches:
                f.write(l + "\n")

        self.report["chapters"].append({
            "id": "ioc_matches",
            "title": "4. IOC 情报匹配（文件系统 + OSLog）",
            "severity": sev,
            "fs_count": total_fs,
            "oslog_count": total_oslog,
            "fs_samples": self.fs_ioc_matches[:30],
            "oslog_samples": self.oslog_ioc_matches[:30],
            "explain": (
                "使用内置 IOC 关键字，对文件系统中文本文件及 OSLog 文本进行关键字匹配，"
                "用于发现是否与已知攻击基础设施（域名/IP/路径）存在关联。"
            )
        })

    # ---------------------------
    # 7. 汇总 & 报告输出
    # ---------------------------
    def finalize_summary(self):
        severity_rank = {"NORMAL": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3, "INFO": 0}
        worst = "NORMAL"
        for ch in self.report["chapters"]:
            sev = ch.get("severity", "NORMAL")
            if severity_rank.get(sev, 0) > severity_rank.get(worst, 0):
                worst = sev

        self.report["summary"] = {
            "overall_severity": worst,
            "note": "该结论为规则驱动的初步评估，需要结合业务场景、样本背景和额外证据做最终判断。"
        }

    def save_report(self):
        self.finalize_summary()

        json_path = os.path.join(self.out_dir, "report_sysdiagnose.json")
        md_path = os.path.join(self.out_dir, "report_sysdiagnose.md")

        with open(json_path, "w") as f:
            json.dump(self.report, f, ensure_ascii=False, indent=2)

        # raw 文件映射（章节 -> 对应原始日志）
        raw_map = {
            "device_info": ["raw/device_info.log"],
            "jailbreak_signs": [
                "raw/fs_jailbreak_rules_hits.log",
                "raw/fs_paths_scanned.log",
                "raw/fs_text_keywords_hits.log",
            ],
            "dev_debug_signs": [
                "raw/fs_dev_debug_rules_hits.log",
                "raw/fs_paths_scanned.log",
                "raw/fs_text_keywords_hits.log",
            ],
            "fs_ext_stats": [
                "raw/fs_ext_stats.log",
            ],
            "trustd_tls": [
                "raw/oslog_trustd.log",
                "raw/oslog_full.txt",
            ],
            "network_extension": [
                "raw/oslog_network_extension.log",
                "raw/oslog_full.txt",
            ],
            "runningboard": [
                "raw/oslog_runningboard.log",
                "raw/oslog_full.txt",
            ],
            "profiles_mdm": [
                "raw/oslog_profile.log",
                "raw/oslog_full.txt",
            ],
            "priv_esc_behavior": [
                "raw/oslog_priv_esc_raw.log",
                "raw/oslog_priv_esc_hits.log",
            ],
            "ioc_matches": [
                "raw/fs_ioc_hits.log",
                "raw/oslog_ioc_hits.log",
            ],
        }

        with open(md_path, "w") as f:
            f.write("# iOS Sysdiagnose 综合安全分析报告（含路径脱敏）\n\n")
            f.write(f"- 生成时间：{self.report['generated_at']}\n")
            f.write(f"- 源目录：<SRC_ROOT>\n")
            f.write(f"- 综合严重等级：{self.report['summary']['overall_severity']}\n")
            f.write(f"- 说明：{self.report['summary']['note']}\n\n")

            for ch in self.report["chapters"]:
                cid = ch.get("id")
                f.write("## {}\n\n".format(ch["title"]))
                f.write("- 严重等级：{}\n".format(ch.get("severity", "INFO")))
                if "count" in ch:
                    f.write("- 命中数量：{}\n".format(ch["count"]))
                if "total_entries" in ch:
                    f.write("- 日志条目数：{}\n".format(ch["total_entries"]))
                if "error_entries" in ch:
                    f.write("- 错误/异常条目数：{}\n".format(ch["error_entries"]))
                if "score" in ch:
                    f.write("- 评分：{}\n".format(ch["score"]))
                f.write("\n")

                # 分析过程摘要
                f.write("### 分析过程摘要\n\n")
                if cid == "device_info":
                    f.write("- 搜索 Info.plist 路径：<SRC_ROOT>/system_logs.logarchive/Info.plist 和 <SRC_ROOT>/Info.plist\n")
                    f.write(f"- 实际使用的 Info.plist：{self.device_info_source}\n\n")
                elif cid in ("jailbreak_signs", "dev_debug_signs", "fs_ext_stats"):
                    f.write(f"- 扫描文件总量（上限 {self.total_files_scanned}）：{self.total_files_scanned}\n")
                    f.write(f"- 文本文件数量：{self.total_text_files}\n")
                    f.write(f"- 越狱规则数量：{len(JAILBREAK_PATH_RULES)}\n")
                    f.write(f"- 开发/调试规则数量：{len(DEV_DEBUG_PATH_RULES)}\n\n")
                elif cid in ("trustd_tls", "network_extension", "runningboard", "profiles_mdm"):
                    f.write("- 基于解码后的 OSLog 文本（raw/oslog_full.txt）筛选对应子系统关键字日志。\n\n")
                elif cid == "priv_esc_behavior":
                    f.write("- 从 OSLog 中筛选 coretrust/amfid/MobileFileIntegrity/entitlement/task_for_pid/sandbox 相关日志，计算提权评分。\n\n")
                elif cid == "ioc_matches":
                    f.write("- 对文件系统文本文件和 OSLog 文本执行 IOC 关键字匹配，统计命中次数。\n\n")
                else:
                    f.write("- 本章节为简单结果展示，分析过程参见对应 raw 日志文件。\n\n")

                # 原始日志文件列表
                f.write("### 原始日志文件\n\n")
                raw_files = raw_map.get(cid, [])
                if raw_files:
                    for rp in raw_files:
                        f.write(f"- {rp}\n")
                else:
                    f.write("- （无专门原始日志文件记录）\n")
                f.write("\n")

                # 检测结果 / 样例
                if "result" in ch:
                    f.write("### 检测结果\n\n```\n{}\n```\n\n".format(
                        json.dumps(ch["result"], ensure_ascii=False, indent=2)
                    ))

                if "samples" in ch and ch["samples"]:
                    f.write("### 样例（最多 50 条）\n\n```\n{}\n```\n\n".format(
                        "\n".join(ch["samples"])
                    ))

                if "ext_stats" in ch:
                    f.write("### 扩展名统计（前 30）\n\n```\n{}\n```\n\n".format(
                        json.dumps(ch["ext_stats"], ensure_ascii=False, indent=2)
                    ))

                if "fs_samples" in ch or "oslog_samples" in ch:
                    f.write("### IOC 命中样例\n\n")
                    if ch.get("fs_samples"):
                        f.write("#### 文件系统命中\n```\n{}\n```\n\n".format(
                            "\n".join(ch["fs_samples"])
                        ))
                    if ch.get("oslog_samples"):
                        f.write("#### OSLog 命中\n```\n{}\n```\n\n".format(
                            "\n".join(ch["oslog_samples"])
                        ))

                # 原理说明
                f.write("### 原理说明\n\n{}\n\n".format(ch.get("explain", "")))

        return json_path, md_path

    # ---------------------------
    # 8. 主流程
    # ---------------------------
    def run(self):
        self.extract_device_info()
        self.scan_filesystem()
        oslog_txt = self.decode_oslog()
        self.analyze_oslog_subsystems(oslog_txt)
        self.analyze_priv_esc_from_oslog(oslog_txt)
        self.analyze_ioc()
        return self.save_report()


# ---------------------------
# 命令行入口
# ---------------------------

def main():
    parser = argparse.ArgumentParser(description="iOS sysdiagnose 综合分析（含路径脱敏）")
    parser.add_argument("--src", required=True, help="sysdiagnose 解压后的根目录")
    parser.add_argument("--out", required=True, help="报告输出目录")
    args = parser.parse_args()

    analyzer = SysDiagReport(args.src, args.out)
    json_path, md_path = analyzer.run()

    print("分析完成：")
    print("JSON 报告：", json_path)
    print("Markdown 报告：", md_path)
    print("原始日志目录：", os.path.join(args.out, "raw"))


if __name__ == "__main__":
    if sys.version_info < (3, 7):
        print("需要 Python 3.7 及以上版本")
        sys.exit(1)
    main()
