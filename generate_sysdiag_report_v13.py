#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
V13 至尊版：
- 结合原 v11 文件系统规则（越狱、开发/调试、IOC 基于路径/内容）
- 加入 OSLog (tracev3 / system_logs.logarchive) 解码与富集
- 每个章节包含：检测结果、异常等级、样例、原理说明
- 输入：--src  sysdiagnose 解压目录
- 输出：--out  报告目录（JSON + Markdown + oslog.txt）
"""

import os
import sys
import json
import plistlib
import argparse
import subprocess
from datetime import datetime
from collections import Counter, defaultdict

# ---------------------------
# 规则定义（加强版 C2）
# ---------------------------

JAILBREAK_PATH_RULES = [
    "/Applications/Cydia.app",
    "/Applications/Sileo.app",
    "/Applications/Zebra.app",
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
    "/usr/libexec/filza",
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
    "/usr/bin/python3",   # 仅在 iOS FS dump 中有才算可疑
    "frida-server",
    "frida-gadget",
    "cycript",
    "gdb",
]

IOC_KEYWORDS = [
    # 示例 IOC，可按需扩展
    "apple-cloud-service.com",
    "mobileconfig.apple-exe-sync.com",
    "icloud-sync-update.com",
    "whatsapp-cloud-service.net",
]

TEXT_EXTS = {".txt", ".log", ".conf", ".cfg", ".ini", ".json", ".xml", ".plist", ".csv", ".md"}

# ---------------------------
# 工具函数
# ---------------------------

def classify_severity(count, high, medium):
    """
    简单的数量阈值 -> 严重等级
    """
    if count >= high:
        return "HIGH"
    if count >= medium:
        return "MEDIUM"
    if count > 0:
        return "LOW"
    return "NORMAL"


def safe_read_text(path, max_bytes=64 * 1024):
    """
    安全读取文本文件前 max_bytes 字节，用于内容规则匹配
    """
    try:
        with open(path, "rb") as f:
            data = f.read(max_bytes)
        return data.decode("utf-8", errors="ignore")
    except Exception:
        return ""


# ---------------------------
# 主类：V13 + V11 融合
# ---------------------------

class SysDiagV13:
    def __init__(self, src_dir, out_dir):
        self.src_dir = os.path.abspath(src_dir)
        self.out_dir = os.path.abspath(out_dir)
        os.makedirs(self.out_dir, exist_ok=True)

        self.report = {
            "version": "v13-fs+oslog",
            "generated_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "src_dir": self.src_dir,
            "device_info": {},
            "summary": {},
            "chapters": []
        }

        # 收集全局统计
        self.fs_ext_counter = Counter()
        self.jb_matches = []
        self.dev_matches = []
        self.fs_ioc_matches = []
        self.oslog_ioc_matches = []

    # ---------------------------
    # 1. 设备信息（Info.plist）
    # ---------------------------
    def extract_device_info(self):
        candidates = [
            os.path.join(self.src_dir, "system_logs.logarchive", "Info.plist"),
            os.path.join(self.src_dir, "Info.plist"),
        ]
        info = {}

        for p in candidates:
            if os.path.exists(p):
                try:
                    with open(p, "rb") as f:
                        info = plistlib.load(f)
                    break
                except Exception:
                    continue

        dev = {
            "archive_id": info.get("ArchiveIdentifier", "N/A"),
            "os_version": info.get("OSVersion", "N/A"),
            "build": info.get("BuildVersion", "N/A"),
            "timezone": info.get("TimeZoneName", "N/A"),
        }

        self.report["device_info"] = dev
        self.report["chapters"].append({
            "id": "device_info",
            "title": "设备信息",
            "severity": "INFO",
            "result": dev,
            "explain": "从 sysdiagnose 或 system_logs.logarchive 内的 Info.plist 中解析设备基本信息，包括 "
                       "系统版本、构建号和采集时区，仅用于环境描述，不参与异常判断。"
        })

    # ---------------------------
    # 2. 文件系统扫描（V11 能力）
    # ---------------------------
    def scan_filesystem(self, max_paths=200000):
        """
        遍历 sysdiagnose 解压目录：
        - 统计文件扩展名
        - 基于路径规则检测越狱 / 开发痕迹
        - 对文本类文件做内容规则匹配（支持你那个 trigger_all_signals.txt）
        """
        jb_hits = []
        dev_hits = []
        ioc_hits = []

        walked = 0

        for root, dirs, files in os.walk(self.src_dir):
            for name in files:
                walked += 1
                if walked > max_paths:
                    break

                full_path = os.path.join(root, name)
                rel_path = os.path.relpath(full_path, self.src_dir)

                # 扩展名统计
                ext = os.path.splitext(name)[1].lower()
                if ext:
                    self.fs_ext_counter[ext] += 1

                # 路径规则匹配（越狱 / 调试）
                for r in JAILBREAK_PATH_RULES:
                    if r in rel_path:
                        jb_hits.append(rel_path)
                        break

                for r in DEV_DEBUG_PATH_RULES:
                    if r in rel_path:
                        dev_hits.append(rel_path)
                        break

                # IOC & 规则的内容匹配（只在文本类文件上做）
                if ext in TEXT_EXTS:
                    text = safe_read_text(full_path)
                    if not text:
                        continue

                    for r in JAILBREAK_PATH_RULES:
                        if r in text:
                            jb_hits.append(f"{rel_path} :: {r}")
                            break

                    for r in DEV_DEBUG_PATH_RULES:
                        if r in text:
                            dev_hits.append(f"{rel_path} :: {r}")
                            break

                    for kw in IOC_KEYWORDS:
                        if kw in text:
                            ioc_hits.append(f"{rel_path} :: {kw}")
                            break

            if walked > max_paths:
                break

        self.jb_matches = jb_hits
        self.dev_matches = dev_hits
        self.fs_ioc_matches = ioc_hits

        # 越狱严重度
        jb_sev = classify_severity(len(jb_hits), high=5, medium=2)
        dev_sev = classify_severity(len(dev_hits), high=5, medium=2)

        self.report["chapters"].append({
            "id": "jailbreak_signs",
            "title": "2.3 越狱迹象（路径 & 内容规则）",
            "severity": jb_sev,
            "count": len(jb_hits),
            "samples": jb_hits[:50],
            "explain": (
                "通过遍历 sysdiagnose 解压目录，使用加强版越狱路径规则（如 /Applications/Cydia.app、"
                "/Library/MobileSubstrate、/var/jb 等）对文件路径和文本内容进行匹配。\n\n"
                "如果命中多条典型越狱路径或相关字样，则认为存在明显越狱可能；若完全无命中，则认为暂未发现越狱痕迹。"
            )
        })

        self.report["chapters"].append({
            "id": "dev_debug_signs",
            "title": "2.4 开发 / 调试迹象（路径 & 内容规则）",
            "severity": dev_sev,
            "count": len(dev_hits),
            "samples": dev_hits[:50],
            "explain": (
                "使用加强版开发/调试路径规则（如 /Developer、Xcode、.lldb、frida-server 等）对文件路径以及"
                "文本文件内容进行匹配，以发现是否存在调试环境、逆向工具或注入框架的痕迹。\n\n"
                "大量命中往往意味着设备曾连接开发环境或运行过调试/Hook 工具。"
            )
        })

        # 扩展名统计章节（类似 v11）
        top_ext = self.fs_ext_counter.most_common(30)
        self.report["chapters"].append({
            "id": "fs_ext_stats",
            "title": "文件系统扩展名统计（Top 30）",
            "severity": "INFO",
            "ext_stats": top_ext,
            "explain": (
                "对 sysdiagnose 中可见的所有文件按扩展名进行统计，可用于判断数据类型分布（日志 / 配置 / "
                "脚本 / 动态库等）。某些异常扩展（如大量 .dylib / 可疑脚本）可能提示存在额外组件。"
            )
        })

    # ---------------------------
    # 3. 解码 OSLog（tracev3 -> oslog.txt）
    # ---------------------------
    def decode_oslog(self):
        """
        使用 macOS log 工具解码 system_logs.logarchive 为纯文本 oslog.txt
        """
        logarchive_path = os.path.join(self.src_dir, "system_logs.logarchive")
        if not os.path.exists(logarchive_path):
            raise RuntimeError(f"未找到 system_logs.logarchive: {logarchive_path}")

        oslog_txt = os.path.join(self.out_dir, "oslog.txt")

        cmd = [
            "log", "show",
            "--archive", logarchive_path,
            "--info", "--debug"
        ]
        with open(oslog_txt, "w") as f:
            subprocess.run(cmd, stdout=f, stderr=subprocess.DEVNULL)

        return oslog_txt

    # ---------------------------
    # 4.x OSLog 子系统分析
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

                if "trustd" in l or "SecTrust" in l or "certificate" in l:
                    trustd_lines.append(l)

                if "NetworkExtension" in l or "NEVPN" in l or "NEConfiguration" in l:
                    ne_lines.append(l)

                if "RunningBoard" in l or "runningboardd" in l:
                    rb_lines.append(l)

                if "profile" in l or "MDM" in l or "ConfigurationProfile" in l:
                    profile_lines.append(l)

                for kw in IOC_KEYWORDS:
                    if kw in l:
                        ioc_oslog_hits.append(l)
                        break

        # trustd 异常粗略判定：包含 error/fail 的行数
        trustd_error_count = sum(
            1 for l in trustd_lines
            if any(x in l.lower() for x in ["error", "fail", "denied", "untrusted", "revoked"])
        )
        trustd_sev = classify_severity(trustd_error_count, high=10, medium=3)

        self.report["chapters"].append({
            "id": "trustd_tls",
            "title": "4.1 trustd / TLS 证书异常",
            "severity": trustd_sev,
            "total_entries": len(trustd_lines),
            "error_entries": trustd_error_count,
            "samples": trustd_lines[:50],
            "explain": (
                "从解码后的 OSLog 文本中筛选包含 trustd、SecTrust、certificate 等关键字的日志行，"
                "并统计其中包含 error/fail/denied/untrusted 等字样的条目数量，用于判断 TLS 证书验证是否存在异常。\n\n"
                "如果错误条目数量较多，可能意味着存在中间人攻击、伪造证书或违规拦截流量行为。"
            )
        })

        ne_error_count = sum(
            1 for l in ne_lines
            if any(x in l.lower() for x in ["error", "fail", "cannot", "denied"])
        )
        ne_sev = classify_severity(ne_error_count, high=5, medium=1)
        self.report["chapters"].append({
            "id": "network_extension",
            "title": "4.3 VPN / NetworkExtension 事件",
            "severity": ne_sev,
            "total_entries": len(ne_lines),
            "error_entries": ne_error_count,
            "samples": ne_lines[:50],
            "explain": (
                "筛选 OSLog 中包含 NetworkExtension / NEVPN / NEConfiguration 的日志，"
                "用于识别 VPN / 代理 / 隧道相关的配置与错误。如果出现大量错误或异常断开，"
                "可能意味着配置异常或存在非正常的网络劫持行为。"
            )
        })

        rb_sev = classify_severity(len(rb_lines), high=100, medium=10)
        self.report["chapters"].append({
            "id": "runningboard",
            "title": "4.5 进程活跃候选（RunningBoard）",
            "severity": rb_sev if rb_lines else "NORMAL",
            "total_entries": len(rb_lines),
            "samples": rb_lines[:50],
            "explain": (
                "RunningBoard/ runningboardd 是 iOS 负责进程生命周期管理的组件，"
                "其日志可以反映前台/后台进程切换、进程被挂起或因资源压力被系统终止等情况。\n\n"
                "本章节列出出现频率较高或与特定进程相关的日志条目，用于辅助判断是否有异常进程活动。"
            )
        })

        profile_sev = classify_severity(len(profile_lines), high=10, medium=1)
        self.report["chapters"].append({
            "id": "profiles_mdm",
            "title": "4.4 描述文件 / MDM 相关日志",
            "severity": profile_sev if profile_lines else "NORMAL",
            "total_entries": len(profile_lines),
            "samples": profile_lines[:50],
            "explain": (
                "从 OSLog 中筛选包含 profile / MDM / ConfigurationProfile 的日志，用于识别配置描述文件 "
                "(mobileconfig) 的安装、更新及 MDM 管理活动。如果存在未知来源的 MDM 绑定或大量配置变更，"
                "则可能存在被远程控制的风险。"
            )
        })

        self.oslog_ioc_matches = ioc_oslog_hits

    # ---------------------------
    # 5. IOC 情报匹配（FS + OSLog）
    # ---------------------------
    def analyze_ioc(self):
        total_fs = len(self.fs_ioc_matches)
        total_oslog = len(self.oslog_ioc_matches)
        total = total_fs + total_oslog

        sev = classify_severity(total, high=5, medium=1)

        self.report["chapters"].append({
            "id": "ioc_matches",
            "title": "5. IOC 情报匹配（FS + OSLog）",
            "severity": sev,
            "fs_count": total_fs,
            "oslog_count": total_oslog,
            "fs_samples": self.fs_ioc_matches[:30],
            "oslog_samples": self.oslog_ioc_matches[:30],
            "explain": (
                "使用内置 IOC 关键字（可扩展为域名/IP/路径特征）对文件系统中的文本文件、以及 OSLog 文本进行扫描，"
                "若命中已知恶意指标或可疑域名，即认为存在潜在威胁，需要结合其他证据进一步研判。"
            )
        })

    # ---------------------------
    # 6. 生成报告（JSON + Markdown）
    # ---------------------------
    def finalize_summary(self):
        # 取各章节的最高严重级别作为整体评估
        severity_rank = {"NORMAL": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3, "INFO": 0}
        worst = "NORMAL"
        for ch in self.report["chapters"]:
            sev = ch.get("severity", "NORMAL")
            if severity_rank.get(sev, 0) > severity_rank.get(worst, 0):
                worst = sev

        self.report["summary"] = {
            "overall_severity": worst,
            "note": "此结论为基于规则的初步评估，需结合业务场景与额外证据作最终判断。"
        }

    def save_report(self):
        self.finalize_summary()

        json_path = os.path.join(self.out_dir, "report_v13.json")
        md_path = os.path.join(self.out_dir, "report_v13.md")

        with open(json_path, "w") as f:
            json.dump(self.report, f, ensure_ascii=False, indent=2)

        with open(md_path, "w") as f:
            f.write("# iOS Sysdiagnose 综合安全分析报告 v13\n\n")
            f.write(f"- 生成时间：{self.report['generated_at']}\n")
            f.write(f"- 源目录：{self.report['src_dir']}\n")
            f.write(f"- 综合严重等级：{self.report['summary']['overall_severity']}\n")
            f.write(f"- 说明：{self.report['summary']['note']}\n\n")

            for ch in self.report["chapters"]:
                f.write("## {}\n\n".format(ch["title"]))
                f.write("- 严重等级：{}\n".format(ch.get("severity", "INFO")))
                if "count" in ch:
                    f.write("- 命中数量：{}\n".format(ch["count"]))
                if "total_entries" in ch:
                    f.write("- 日志条目数：{}\n".format(ch["total_entries"]))
                if "error_entries" in ch:
                    f.write("- 错误/异常条目数：{}\n".format(ch["error_entries"]))
                f.write("\n")

                # 内容/样例
                if "result" in ch:
                    f.write("### 检测结果\n\n```\n{}\n```\n\n".format(
                        json.dumps(ch["result"], ensure_ascii=False, indent=2)
                    ))
                if "samples" in ch and ch["samples"]:
                    f.write("### 样例（最多 50 条）\n\n```\n{}\n```\n\n".format(
                        "\n".join(ch["samples"])
                    ))
                if "ext_stats" in ch:
                    f.write("### 扩展名统计\n\n```\n{}\n```\n\n".format(
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
    # 7. 主流程
    # ---------------------------
    def run(self):
        self.extract_device_info()
        self.scan_filesystem()
        oslog_txt = self.decode_oslog()
        self.analyze_oslog_subsystems(oslog_txt)
        self.analyze_ioc()
        return self.save_report()


# ---------------------------
# 命令行入口
# ---------------------------

def main():
    parser = argparse.ArgumentParser(description="iOS sysdiagnose 综合分析（V11+V13 融合版）")
    parser.add_argument("--src", required=True, help="sysdiagnose 解压后的根目录")
    parser.add_argument("--out", required=True, help="报告输出目录")
    args = parser.parse_args()

    analyzer = SysDiagV13(args.src, args.out)
    json_path, md_path = analyzer.run()

    print("报告生成完成：")
    print("JSON 报告：", json_path)
    print("Markdown 报告：", md_path)


if __name__ == "__main__":
    if sys.version_info < (3, 7):
        print("需要 Python 3.7 及以上版本")
        sys.exit(1)
    main()
