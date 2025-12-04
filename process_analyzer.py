#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
# 进程日志分析脚本
#
# 功能：
#   1. 解析 sysdiagnose / OSLog / part_xx 日志，识别所有进程名
#   2. 抓取对应进程的所有日志
#   3. 识别签名事件（AMFID / CoreTrust / signature error）
#   4. 识别沙盒 / entitlement / task_for_pid 等高危行为
#   5. 基于路径构建签名推断（系统签名、App 签名、越狱目录、非法目录）
#   6. 自动输出各类结果文件
#   7. 自动判断：是否包含进程路径相关信息
#
# 使用方法:
#   python3 process_analyzer.py --src ./sysdiagnose --fs filesystem.json --out ./output
#

import os
import re
import json
import argparse
from collections import defaultdict

# -----------------------------------------------------
# 关键词规则
# -----------------------------------------------------
PROCESS_REGEX = re.compile(
    r'(com\.[A-Za-z0-9\.\-_]+|SpringBoard|runningboardd|assertiond|neagent|containermanagerd)',
    re.IGNORECASE
)

SIGNATURE_KEYWORDS = [
    "amfid", "signature", "code signature", "CoreTrust", "cdhash", "invalid", "rejected",
    "CS_FAIL", "LibraryValidationFailed"
]

SANDBOX_KEYWORDS = ["sandbox", "deny", "violation"]

ENTITLEMENT_KEYWORDS = ["entitlement", "invalid entitlement", "denied"]

TASK_KEYWORDS = ["task_for_pid", "tfp", "get-task-allow"]

PROCESS_EVENTS = ["RunningBoard", "crash", "jetsam", "killed"]

ALL_KEYWORDS = SIGNATURE_KEYWORDS + SANDBOX_KEYWORDS + ENTITLEMENT_KEYWORDS + TASK_KEYWORDS + PROCESS_EVENTS

# -----------------------------------------------------
# 提取日志文件路径
# -----------------------------------------------------
def collect_logs(src_dir):
    logs = []
    for root, _, files in os.walk(src_dir):
        for f in files:
            if f.startswith("part_") or f.endswith((".log", ".txt", ".out")):
                logs.append(os.path.join(root, f))
    return logs

# -----------------------------------------------------
# 解析 filesystem.json（App 路径信息）
# -----------------------------------------------------
def load_filesystem(fs_path):
    if not fs_path or not os.path.exists(fs_path):
        return None
    try:
        with open(fs_path, "r") as f:
            return json.load(f)
    except:
        return None

# -----------------------------------------------------
# 根据路径推断签名类型
# -----------------------------------------------------
def infer_signature_type(path):
    if not path:
        return "unknown"

    if "/System/Library" in path or "/usr/libexec" in path:
        return "apple_signed"

    if "/private/var/mobile/Containers" in path:
        return "app_store_signed"

    if "/Library/MobileSubstrate" in path or "/var/jb" in path:
        return "jailbreak_environment"

    if "/private/var/root" in path:
        return "illegal_location"

    return "unknown"

# -----------------------------------------------------
# 主分析
# -----------------------------------------------------
def analyze_processes(log_files, filesystem, out_dir):
    os.makedirs(out_dir, exist_ok=True)
    proc_logs = defaultdict(list)
    proc_sig_events = defaultdict(list)
    proc_sandbox_events = defaultdict(list)
    proc_entitlement_events = defaultdict(list)
    proc_task_events = defaultdict(list)
    proc_path_map = defaultdict(set)  # 记录路径

    for lf in log_files:
        try:
            with open(lf, "r", errors="ignore") as f:
                for line in f:
                    # 提取进程名
                    m = PROCESS_REGEX.search(line)
                    if not m:
                        continue
                    proc = m.group(0)

                    # 保存行
                    proc_logs[proc].append(line.strip())

                    # 匹配路径（从日志提取）
                    path_match = re.findall(r'(/[A-Za-z0-9_\-\/\.]+)', line)
                    for p in path_match:
                        proc_path_map[proc].add(p)

                    # 分类事件
                    low = line.lower()

                    if any(k in low for k in SIGNATURE_KEYWORDS):
                        proc_sig_events[proc].append(line.strip())

                    if any(k in low for k in SANDBOX_KEYWORDS):
                        proc_sandbox_events[proc].append(line.strip())

                    if any(k in low for k in ENTITLEMENT_KEYWORDS):
                        proc_entitlement_events[proc].append(line.strip())

                    if any(k in low for k in TASK_KEYWORDS):
                        proc_task_events[proc].append(line.strip())

        except:
            continue

    # 输出所有进程日志
    proc_dir = os.path.join(out_dir, "process_logs")
    sig_dir = os.path.join(out_dir, "process_signature_status")
    os.makedirs(proc_dir, exist_ok=True)
    os.makedirs(sig_dir, exist_ok=True)

    # 是否包含路径信息
    has_path_info = False

    # 为每个进程生成结果
    for proc in proc_logs.keys():
        # 写入原始日志
        with open(os.path.join(proc_dir, f"{proc}.log"), "w") as f:
            for ln in proc_logs[proc]:
                f.write(ln + "\n")

        # 推断路径签名类型
        inferred_type = "unknown"
        if proc_path_map[proc]:
            has_path_info = True
            best_path = list(proc_path_map[proc])[0]
            inferred_type = infer_signature_type(best_path)
        else:
            best_path = None

        # 写入签名状态
        sig_path = os.path.join(sig_dir, f"{proc}.sig")
        with open(sig_path, "w") as f:
            f.write(f"process_name: {proc}\n")
            f.write(f"sample_path: {best_path}\n")
            f.write(f"path_signature_type: {inferred_type}\n")
            f.write("\nsignature_events:\n")
            for ln in proc_sig_events[proc][:20]:
                f.write(f"  - {ln}\n")
            f.write("\nsandbox_events:\n")
            for ln in proc_sandbox_events[proc][:20]:
                f.write(f"  - {ln}\n")
            f.write("\nentitlement_events:\n")
            for ln in proc_entitlement_events[proc][:20]:
                f.write(f"  - {ln}\n")
            f.write("\ntask_for_pid_events:\n")
            for ln in proc_task_events[proc][:20]:
                f.write(f"  - {ln}\n")

    # 输出 overview
    with open(os.path.join(out_dir, "processes_overview.txt"), "w") as f:
        for proc in sorted(proc_logs.keys()):
            f.write(f"{proc} — logs={len(proc_logs[proc])} sig={len(proc_sig_events[proc])} sandbox={len(proc_sandbox_events[proc])}\n")

    # 可疑进程
    with open(os.path.join(out_dir, "suspicious_processes.txt"), "w") as f:
        for proc in sorted(proc_logs.keys()):
            score = len(proc_sig_events[proc]) + len(proc_entitlement_events[proc]) + len(proc_task_events[proc])
            if score > 0:
                f.write(f"[RISK {score}] {proc}\n")

    # 输出路径信息判断结果
    with open(os.path.join(out_dir, "path_info_status.txt"), "w") as f:
        if has_path_info:
            f.write("YES: 日志中包含进程路径相关信息。\n")
        else:
            f.write("NO: 日志中未发现任何可用于推断进程路径的信息。\n")


    generate_markdown_report(out_dir, proc_logs, proc_sig_events, proc_sandbox_events, proc_entitlement_events, proc_task_events, proc_path_map)

def generate_markdown_report(
    out_dir,
    proc_logs,
    proc_sig_events,
    proc_sandbox_events,
    proc_entitlement_events,
    proc_task_events,
    proc_path_map
):
    md_path = os.path.join(out_dir, "process_report.md")

    # ======== 风险分类（按进程聚合）========
    HIGH = {}
    MEDIUM = {}
    LOW = {}

    for proc in proc_logs.keys():
        sigs = len(proc_sig_events.get(proc, []))
        sands = len(proc_sandbox_events.get(proc, []))
        ents = len(proc_entitlement_events.get(proc, []))
        tasks = len(proc_task_events.get(proc, []))

        score = sigs * 25 + sands * 10 + ents * 15 + tasks * 20

        if score >= 200:
            HIGH[proc] = score
        elif score >= 50:
            MEDIUM[proc] = score
        else:
            LOW[proc] = score

    with open(md_path, "w") as md:

        # ============================================================
        #                    报告标题
        # ============================================================
        md.write("# iOS 进程检测报告（process_analyzer）\n\n")
        md.write("本报告根据 sysdiagnose / OSLog 自动识别进程活动，并对签名、沙盒、权限、task_for_pid 等行为进行风险评估。\n\n")
        md.write("---\n\n")

        # ============================================================
        #                  1. 风险分类统计
        # ============================================================
        md.write("## 1. 风险分类统计\n\n")

        md.write(f"- 高危进程（HIGH，评分 ≥ 200）：**{len(HIGH)}** 个\n")
        md.write(f"- 中危进程（MEDIUM，50 ≤ 评分 < 200）：**{len(MEDIUM)}** 个\n")
        md.write(f"- 低危进程（LOW，评分 < 50）：**{len(LOW)}** 个\n\n")

        md.write("### 1.1 高危进程列表\n")
        if HIGH:
            for p, s in sorted(HIGH.items(), key=lambda x: x[1], reverse=True):
                md.write(f"- `{p}`（评分：{s}）\n")
        else:
            md.write("- （无）\n")
        md.write("\n")

        md.write("### 1.2 中危进程列表\n")
        if MEDIUM:
            for p, s in sorted(MEDIUM.items(), key=lambda x: x[1], reverse=True):
                md.write(f"- `{p}`（评分：{s}）\n")
        else:
            md.write("- （无）\n")
        md.write("\n")

        md.write("### 1.3 低危进程列表\n")
        if LOW:
            for p, s in sorted(LOW.items(), key=lambda x: x[1], reverse=True):
                md.write(f"- `{p}`（评分：{s}）\n")
        else:
            md.write("- （无）\n")
        md.write("\n---\n\n")

        # ============================================================
        #                  2. 进程统计总表
        # ============================================================
        md.write("## 2. 进程统计总表\n\n")
        md.write("| 进程名 | 日志行数 | Signature | Sandbox | Entitlement | TFP | 风险分 |\n")
        md.write("|--------|----------|-----------|---------|-------------|-----|--------|\n")

        for proc in sorted(proc_logs.keys()):
            logs = proc_logs[proc]
            sigs = len(proc_sig_events.get(proc, []))
            sands = len(proc_sandbox_events.get(proc, []))
            ents = len(proc_entitlement_events.get(proc, []))
            tasks = len(proc_task_events.get(proc, []))
            score = sigs * 25 + sands * 10 + ents * 15 + tasks * 20
            md.write(f"| `{proc}` | {len(logs)} | {sigs} | {sands} | {ents} | {tasks} | {score} |\n")

        md.write("\n---\n\n")

        # ============================================================
        #                  3. 单进程详细分析
        # ============================================================
        md.write("## 3. 单进程详细分析\n\n")

        for proc in sorted(proc_logs.keys()):
            logs = proc_logs[proc]
            sigs = proc_sig_events.get(proc, [])
            sands = proc_sandbox_events.get(proc, [])
            ents = proc_entitlement_events.get(proc, [])
            tasks = proc_task_events.get(proc, [])

            # 路径
            path_list = list(proc_path_map.get(proc, []))
            sample_path = path_list[0] if path_list else "（日志中未找到路径）"

            # 风险评分
            score = len(sigs) * 25 + len(sands) * 10 + len(ents) * 15 + len(tasks) * 20
            if score >= 200:
                level = "⚠️ HIGH"
            elif score >= 50:
                level = "🟡 MEDIUM"
            else:
                level = "🟢 LOW"

            md.write(f"### {proc}\n\n")
            md.write(f"- **风险等级：{level}（{score}）**\n")
            md.write(f"- **示例路径：** `{sample_path}`\n\n")

            md.write("#### 3.x.1 事件数量概览\n")
            md.write(f"- Signature 事件：{len(sigs)}\n")
            md.write(f"- Sandbox 事件：{len(sands)}\n")
            md.write(f"- Entitlement 事件：{len(ents)}\n")
            md.write(f"- task_for_pid 事件：{len(tasks)}\n")
            md.write(f"- 总日志行数：{len(logs)}\n\n")

            # ===== 在每个进程小节中分别展示各类事件日志 =====

            md.write("#### 3.x.2 Signature 相关日志（最多 5 条）\n")
            if sigs:
                for ln in sigs[:5]:
                    md.write(f"> {ln}\n")
            else:
                md.write("> （无 Signature 相关事件）\n")
            md.write("\n")

            md.write("#### 3.x.3 Sandbox 相关日志（最多 5 条）\n")
            if sands:
                for ln in sands[:5]:
                    md.write(f"> {ln}\n")
            else:
                md.write("> （无 Sandbox 相关事件）\n")
            md.write("\n")

            md.write("#### 3.x.4 Entitlement 相关日志（最多 5 条）\n")
            if ents:
                for ln in ents[:5]:
                    md.write(f"> {ln}\n")
            else:
                md.write("> （无 Entitlement 相关事件）\n")
            md.write("\n")

            md.write("#### 3.x.5 task_for_pid（TFP）相关日志（最多 5 条）\n")
            if tasks:
                for ln in tasks[:5]:
                    md.write(f"> {ln}\n")
            else:
                md.write("> （无 task_for_pid 相关事件）\n")
            md.write("\n")

            md.write("#### 3.x.6 综合示例日志（最多 5 条，原始）\n")
            for ln in logs[:5]:
                md.write(f"> {ln}\n")
            md.write("\n---\n")

        print(f"[+] process_report.md 已生成：{md_path}")


# -----------------------------------------------------
# main
# -----------------------------------------------------
if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--src", required=True, help="sysdiagnose/OSLog 所在目录")
    parser.add_argument("--fs", required=False, help="filesystem.json 路径")
    parser.add_argument("--out", required=True, help="输出目录")
    args = parser.parse_args()

    logs = collect_logs(args.src)
    filesystem = load_filesystem(args.fs) if args.fs else None


    analyze_processes(logs, filesystem, args.out)

    print("[*] 进程检测完成。")
