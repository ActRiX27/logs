import argparse
import fnmatch
import json
import os
import shutil
import subprocess
from datetime import datetime
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Sequence

from datalogic.ios.backup import analyze_profiles, ios_backup_cert_check, ios_backup_full_check
from datalogic.ios.sysdiag import generate_sysdiag_report, process_analyzer
from datalogic.security import jb_detector

"""基于提权备份目录的统一安全检测入口。

- --src: 必须指向真实备份目录，用于执行完整安全检测。
- --tree: 可选，仅用于调试路径规则，不参与风险判定。

脚本会扫描真实目录结构，匹配越狱/篡改/取证痕迹，串联仓库现有检测模块与 MVT，
输出统一的 JSON / Markdown 报告，并支持加载自定义 IOC（iocs/）。
"""


SUSPICIOUS_PATH_PATTERNS: Dict[str, Sequence[str]] = {
    "越狱/Hook": [
        "*usr/libexec/substrate*",
        "*usr/libexec/substitute*",
        "*usr/libexec/ellekit*",
        "*usr/lib/TweakInject*",
        "*private/var/db/stash*",
        "*Library/MobileSubstrate*",
    ],
    "权限数据库": [
        "*Library/TCC/TCC.db*",
        "*private/var/mobile/Library/TCC/TCC.db*",
    ],
    "行为数据库": [
        "*Knowledge/knowledgeC.db*",
        "*CoreDuet/KnowledgeC*",
    ],
    "MDM / 描述文件": [
        "*ConfigurationProfiles*",
        "*ProvisioningProfiles*",
        "*UserConfigurationProfiles*",
    ],
    "企业签名 / 取证": [
        "*embedded.mobileprovision*",
        "*Signature*",
        "*TrustStore.sqlite*",
        "*Lockdown*",
    ],
    "系统分区异常": [
        "*System/Library/Caches*",
        "*System/Library/PrivateFrameworks*",
        "*iOSSupport*",
    ],
    "数据取证残留": [
        "*Analytics*",
        "*LogArchive*",
        "*mobile/Library/Logs*",
        "*mobile/Containers/Data/Application/*/Library/Caches*",
    ],
}

CATEGORY_SEVERITY = {
    "越狱/Hook": "high",
    "企业签名 / 取证": "high",
    "系统分区异常": "high",
    "MDM / 描述文件": "medium",
    "数据取证残留": "medium",
    "权限数据库": "medium",
    "行为数据库": "medium",
}


def log_info(message: str) -> None:
    ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    print(f"[{ts}] {message}")


def scan_directory(path: Path) -> List[str]:
    """递归扫描目录并返回完整路径列表（绝对路径）。"""

    if not path.exists():
        raise FileNotFoundError(f"路径不存在: {path}")

    log_info(f"开始扫描目录：{path}")
    collected: List[str] = []
    for current, dirs, files in os.walk(path):
        dirs.sort()
        files.sort()
        for name in dirs + files:
            full_path = Path(current) / name
            collected.append(str(full_path))
            if len(collected) % 5000 == 0:
                log_info(f"已枚举路径 {len(collected)} 条……")

    log_info(f"目录扫描完成，共 {len(collected)} 条路径")
    return collected


def parse_tree_lines(lines: Iterable[str]) -> List[str]:
    paths: List[str] = []
    stack: List[str] = []
    for raw in lines:
        line = raw.rstrip("\n")
        if not line.strip():
            continue
        if not any(mark in line for mark in ("└", "├", "──")):
            stack = [line.strip()]
            continue

        if "── " in line:
            prefix, name = line.split("── ", 1)
        else:
            parts = line.rsplit(" ", 1)
            prefix, name = (parts if len(parts) == 2 else ("", line.strip()))

        indent = prefix.count("    ") + prefix.count("│   ")
        stack = stack[: indent + 1]
        stack[indent:] = [name]
        candidate = "/".join(stack).strip()
        if candidate:
            paths.append(candidate)
    return paths


def load_tree_file(tree_path: Path) -> List[str]:
    with open(tree_path, "r", encoding="utf-8") as f:
        return parse_tree_lines(f.readlines())


def match_patterns(paths: List[str]) -> List[Dict[str, object]]:
    """根据模式匹配返回命中列表，同时保留原始大小写路径。"""

    results: List[Dict[str, object]] = []
    paired = [(p, p.lower()) for p in paths]

    for category, patterns in SUSPICIOUS_PATH_PATTERNS.items():
        hits: List[str] = []
        for pattern in patterns:
            lower_pattern = pattern.lower()
            for original, lowered in paired:
                if fnmatch.fnmatch(lowered, lower_pattern):
                    hits.append(original)

        unique_hits = sorted(set(hits))
        results.append(
            {
                "category": category,
                "severity": CATEGORY_SEVERITY.get(category, "low"),
                "patterns": list(patterns),
                "hits": unique_hits,
                "hit_count": len(unique_hits),
            }
        )
    return results


def summarize_risk(detections: List[Dict[str, object]]) -> str:
    level = "low"
    for det in detections:
        if det.get("hit_count"):
            severity = det.get("severity")
            if severity == "high":
                return "high"
            if severity == "medium" and level != "high":
                level = "medium"
    return level


def run_module_safely(fn, *args, **kwargs) -> Dict[str, object]:  # type: ignore[no-any-unimported]
    try:
        result = fn(*args, **kwargs)
        return {"status": "ok", "result": result}
    except Exception as exc:  # noqa: BLE001
        return {"status": "error", "error": str(exc)}


def run_backup_modules(src: Path, out_root: Path) -> List[Dict[str, object]]:
    outputs: List[Dict[str, object]] = []
    outputs.append(
        {
            "name": "analyze_profiles",
            **run_module_safely(analyze_profiles.run, str(src), str(out_root / "analyze_profiles")),
            "output_dir": str(out_root / "analyze_profiles"),
        }
    )
    outputs.append(
        {
            "name": "ios_backup_cert_check",
            **run_module_safely(ios_backup_cert_check.run, str(src), str(out_root / "cert_check")),
            "output_dir": str(out_root / "cert_check"),
        }
    )
    outputs.append(
        {
            "name": "ios_backup_full_check",
            **run_module_safely(ios_backup_full_check.run, str(src), str(out_root / "full_check")),
            "output_dir": str(out_root / "full_check"),
        }
    )
    return outputs


def detect_dataset_types(paths: List[str]) -> Dict[str, bool]:
    """识别备份、sysdiagnose 与日志特征，补充边界信号。"""

    lowered_paths = [p.lower() for p in paths]
    is_backup = any(
        "manifest.db" in p
        or "manifest.mbdb" in p
        or "status.plist" in p
        or p.endswith("/info.plist")
        for p in lowered_paths
    )
    is_sysdiag = any(
        "sysdiagnose" in p
        or "system_logs" in p
        or ".tracev3" in p
        or "/oslog" in p
        or p.endswith(".tar")
        or "filesystem" in p
        for p in lowered_paths
    )
    has_profiles = any(
        "configurationprofiles" in p or "provisioningprofiles" in p or "userconfigurationprofiles" in p
        for p in lowered_paths
    )
    has_oslog = any("oslog" in p or "logarchive" in p or ".tracev3" in p for p in lowered_paths)
    return {
        "is_backup": is_backup,
        "is_sysdiag": is_sysdiag,
        "has_profiles": has_profiles,
        "has_oslog": has_oslog,
    }


def run_backup_modules_if_detected(dataset: Dict[str, bool], src: Path, out_root: Path) -> List[Dict[str, object]]:
    if not dataset.get("is_backup"):
        return [
            {
                "name": "ios_backup_modules",
                "status": "skipped",
                "reason": "未检测到 Manifest.db/Status.plist，不符合备份结构",
            }
        ]
    return run_backup_modules(src, out_root)


def run_jb_detector_if_ready(src: Path, out_root: Path) -> Dict[str, object]:
    required = [
        src / "device_info.json",
        src / "filesystem.json",
        src / "system_baseline.json",
        src / "oslog_full.txt",
    ]
    log_dir = src / "output" / "logs"
    ready = all(p.exists() for p in required)
    if not ready:
        return {
            "name": "jb_detector",
            "status": "skipped",
            "reason": "缺少必要的 device_info/filesystem/baseline/oslog 文件",
        }

    report_dir = out_root / "jailbreak"
    report_dir.mkdir(parents=True, exist_ok=True)
    report_path = report_dir / "jailbreak_report.md"
    log_dir_path = log_dir if log_dir.exists() else report_dir / "logs"
    result = run_module_safely(
        jb_detector.run,
        device_info_path=str(required[0]),
        filesystem_path=str(required[1]),
        baseline_path=str(required[2]),
        log_path=str(required[3]),
        log_dir=str(log_dir_path),
        report_path=str(report_path),
    )
    result.update({"name": "jb_detector", "output_dir": str(report_dir), "report_path": str(report_path)})
    return result


def run_sysdiag_modules_if_ready(src: Path, paths: List[str], out_root: Path) -> List[Dict[str, object]]:
    outputs: List[Dict[str, object]] = []
    has_sysdiag = any("sysdiagnose" in p.lower() for p in paths)
    has_logarchive = any("logarchive" in p.lower() for p in paths)
    filesystem_json = src / "filesystem.json"

    if has_sysdiag:
        sysdiag_out = out_root / "sysdiag_report"
        outputs.append(
            {
                "name": "generate_sysdiag_report",
                **run_module_safely(generate_sysdiag_report.run, str(src), str(sysdiag_out)),
                "output_dir": str(sysdiag_out),
            }
        )

    if has_logarchive:
        process_out = out_root / "sysdiag_process"
        outputs.append(
            {
                "name": "process_analyzer",
                **run_module_safely(
                    process_analyzer.run,
                    str(src),
                    str(filesystem_json) if filesystem_json.exists() else None,
                    str(process_out),
                ),
                "output_dir": str(process_out),
            }
        )

    return outputs


def run_subprocess_logged(command: Sequence[str], log_path: Path) -> Dict[str, object]:
    log_path.parent.mkdir(parents=True, exist_ok=True)
    log_info(f"运行外部命令：{' '.join(command)}，日志输出 -> {log_path}")
    try:
        proc = subprocess.run(
            list(command),
            check=False,
            text=True,
            capture_output=True,
        )
        log_path.write_text((proc.stdout or "") + "\n" + (proc.stderr or ""), encoding="utf-8")
        status = "ok" if proc.returncode == 0 else "error"
        log_info(f"命令完成（status={status}, returncode={proc.returncode}）")
        return {
            "status": status,
            "returncode": proc.returncode,
            "log_path": str(log_path),
        }
    except FileNotFoundError as exc:  # noqa: PERF203
        return {"status": "error", "error": f"命令不存在: {exc}", "log_path": str(log_path)}
    except Exception as exc:  # noqa: BLE001
        return {"status": "error", "error": str(exc), "log_path": str(log_path)}


def collect_mvt_ioc_findings(json_dir: Path) -> List[Dict[str, object]]:
    findings: List[Dict[str, object]] = []
    if not json_dir.exists():
        return findings

    interesting_keys = {"detections", "results", "matches", "iocs", "indicators"}
    for json_file in sorted(json_dir.rglob("*.json")):
        try:
            data = json.loads(json_file.read_text(encoding="utf-8"))
        except Exception:  # noqa: BLE001, PERF203
            continue

        summary: List[str] = []
        if isinstance(data, dict):
            for key in interesting_keys:
                if key in data and data[key]:
                    value = data[key]
                    if isinstance(value, list) and value:
                        sample = value[0]
                        if isinstance(sample, dict):
                            summary.append(f"{key}: {sample.get('type') or sample.get('id') or 'match'}")
                        else:
                            summary.append(f"{key}: {str(sample)[:80]}")
                    else:
                        summary.append(f"{key}: {type(value).__name__}")
        if summary:
            findings.append(
                {
                    "source_file": str(json_file),
                    "summary": summary,
                }
            )

    return findings


def run_mvt_if_needed(
    dataset: Dict[str, bool],
    src: Path,
    out_root: Path,
    iocs_dir: Path,
    backup_password: Optional[str] = None,
) -> (List[Dict[str, object]], List[Dict[str, object]]):
    outputs: List[Dict[str, object]] = []
    findings: List[Dict[str, object]] = []

    if not (dataset.get("is_backup") or dataset.get("is_sysdiag")):
        return outputs, findings

    if shutil.which("mvt-ios") is None:
        return [
            {
                "name": "mvt-ios",
                "status": "skipped",
                "reason": "未检测到 mvt-ios，可通过 pip install mvt 安装",
            }
        ], findings

    mvt_root = out_root / "mvt_output"
    json_dir = mvt_root / "json"
    files_dir = mvt_root / "files"
    logs_dir = mvt_root / "logs"
    json_dir.mkdir(parents=True, exist_ok=True)
    files_dir.mkdir(parents=True, exist_ok=True)
    logs_dir.mkdir(parents=True, exist_ok=True)

    backup_target = src
    if dataset.get("is_backup") and backup_password:
        decrypt_log = logs_dir / "decrypt-backup.log"
        decrypt_result = run_subprocess_logged(
            [
                "mvt-ios",
                "decrypt-backup",
                "--destination",
                str(files_dir / "decrypted_backup"),
                "--password",
                backup_password,
                str(src),
            ],
            decrypt_log,
        )
        decrypt_result.update({"name": "mvt-ios decrypt-backup", "output_dir": str(files_dir / "decrypted_backup")})
        outputs.append(decrypt_result)
        if decrypt_result.get("status") == "ok":
            backup_target = files_dir / "decrypted_backup"

    if dataset.get("is_backup"):
        cb_log = logs_dir / "check-backup.log"
        cb_result = run_subprocess_logged(
            ["mvt-ios", "check-backup", "--output", str(json_dir), str(backup_target)],
            cb_log,
        )
        cb_result.update({"name": "mvt-ios check-backup", "output_dir": str(json_dir)})
        outputs.append(cb_result)
    else:
        outputs.append({"name": "mvt-ios check-backup", "status": "skipped", "reason": "未检测到备份结构"})

    if dataset.get("is_backup") or dataset.get("is_sysdiag"):
        ci_log = logs_dir / "check-iocs.log"
        ioc_target = backup_target if dataset.get("is_backup") else src
        ci_result = run_subprocess_logged(
            ["mvt-ios", "check-iocs", "--iocs", str(iocs_dir), str(ioc_target)],
            ci_log,
        )
        ci_result.update({"name": "mvt-ios check-iocs", "output_dir": str(json_dir), "target": str(ioc_target)})
        outputs.append(ci_result)
        if ci_result.get("status") == "ok":
            findings = collect_mvt_ioc_findings(json_dir)

    return outputs, findings


def build_markdown(report: Dict[str, object]) -> str:
    lines = ["# 统一安全检测报告", ""]
    lines.append(f"生成时间：{report['generated_at']}")
    lines.append(f"检测目录：{report.get('source', 'N/A')}")
    lines.append(f"风险等级：{report.get('risk_level', 'unknown').upper()}")
    lines.append("")

    dataset = report.get("dataset", {})
    lines.append("## 数据集识别")
    lines.append(f"- iOS 备份: {dataset.get('is_backup')}（Manifest.db/Status.plist 检测）")
    lines.append(f"- sysdiagnose: {dataset.get('is_sysdiag')}（tracev3/Filesystem/oslog 检测）")
    lines.append(f"- 配置/描述文件残留: {dataset.get('has_profiles')}")
    lines.append(f"- OSLog/LogArchive: {dataset.get('has_oslog')}")
    lines.append("")

    lines.append("## 路径匹配风险分析")
    for det in report.get("detections", []):  # type: ignore[index]
        lines.append(f"### {det['category']} ({det['severity']})")
        if det.get("hits"):
            for hit in det["hits"]:
                lines.append(f"- {hit}")
        else:
            lines.append("- 未命中")
        lines.append("")

    lines.append("## 越权/越狱/取证可能性判断")
    lines.append(report.get("risk_explanation", "未提供"))
    lines.append("")

    detail = report.get("risk_detail", {})  # type: ignore[index]
    lines.append("## 风险细节")
    if detail.get("categories_with_hits"):
        lines.append("- 路径命中分布：")
        for category, count in detail["categories_with_hits"].items():  # type: ignore[index]
            lines.append(f"  - {category}: {count} 条")
    else:
        lines.append("- 未命中路径规则")
    lines.append(f"- MVT IOC 条目：{detail.get('mvt_findings', 0)}")
    lines.append("")

    mvt_section: List[Dict[str, object]] = report.get("mvt_ioc_findings", [])  # type: ignore[index]
    lines.append("## MVT IOC 聚合")
    if not mvt_section:
        lines.append("- 未检测到 IOC 或未运行 MVT")
    else:
        for finding in mvt_section:
            lines.append(f"- {finding['source_file']}")
            for summary in finding.get("summary", []):
                lines.append(f"  - {summary}")
    lines.append("")

    lines.append("## 子检测模块聚合结果")
    modules: List[Dict[str, object]] = report.get("module_runs", [])  # type: ignore[index]
    if not modules:
        lines.append("- 未调用子模块")
    else:
        for mod in modules:
            status = mod.get("status")
            line = f"- {mod.get('name')}: {status}"
            if mod.get("output_dir"):
                line += f" (输出目录: {mod['output_dir']})"
            if mod.get("log_path"):
                line += f"，日志: {mod['log_path']}"
            if mod.get("error"):
                line += f"，错误: {mod['error']}"
            if mod.get("reason"):
                line += f"，原因: {mod['reason']}"
            lines.append(line)
    lines.append("")

    if report.get("tree_inference"):
        lines.append("## tree.txt 规则调试 (不参与风险判定)")
        for det in report["tree_inference"]:  # type: ignore[index]
            lines.append(f"- {det['category']}: {det['hit_count']} 条命中")
        lines.append("")

    return "\n".join(lines)


def build_report(
    src: Path,
    detections: List[Dict[str, object]],
    module_runs: List[Dict[str, object]],
    dataset: Dict[str, bool],
    mvt_findings: List[Dict[str, object]],
    tree_inference: Optional[List[Dict[str, object]]],
) -> Dict[str, object]:
    risk_level = summarize_risk(detections)
    if mvt_findings:
        risk_level = "high"
    explanation = {
        "high": "命中越狱/系统分区/签名或 IOC 高危路径，存在越权或取证高风险。",
        "medium": "检测到敏感数据库、日志或管控残留，可能存在越权风险。",
        "low": "未发现高危命中，可能仅存在常规应用或缓存残留。",
    }

    risk_detail = {
        "categories_with_hits": {det["category"]: det["hit_count"] for det in detections if det.get("hit_count")},
        "mvt_findings": len(mvt_findings),
    }

    return {
        "generated_at": datetime.utcnow().isoformat() + "Z",
        "source": str(src),
        "risk_level": risk_level,
        "risk_explanation": explanation.get(risk_level, "未定义"),
        "risk_detail": risk_detail,
        "detections": detections,
        "dataset": dataset,
        "mvt_ioc_findings": mvt_findings,
        "module_runs": module_runs,
        "tree_inference": tree_inference,
    }


def run_tree_only(tree_path: Path) -> None:
    if not tree_path.exists():
        raise FileNotFoundError(f"tree.txt 不存在：{tree_path}")
    log_info(f"以 tree.txt 规则调试模式运行：{tree_path}")
    paths = load_tree_file(tree_path)
    detections = match_patterns(paths)
    print("[tree 调试模式] 以下命中仅用于规则调试，不代表实际风险：")
    for det in detections:
        if det["hit_count"]:
            print(f"- {det['category']}: {det['hit_count']} 命中")
            for hit in det["hits"]:
                print(f"    • {hit}")
    print("调试完成。")


def run_detection(src: Path, tree_path: Optional[Path], out_root: Path, backup_password: Optional[str]) -> Dict[str, object]:
    if not src:
        raise ValueError("必须提供 --src 指向真实备份目录")
    if not src.exists():
        raise FileNotFoundError(f"src 路径不存在：{src}")

    out_root.mkdir(parents=True, exist_ok=True)
    script_root = Path(__file__).resolve().parent
    iocs_dir = script_root / "iocs"
    if not iocs_dir.exists():
        iocs_dir = Path.cwd() / "iocs"
    iocs_dir.mkdir(parents=True, exist_ok=True)

    log_info(f"开始运行统一检测，数据源：{src}，输出目录：{out_root}")
    fs_paths = scan_directory(src)
    log_info("目录扫描完成，开始识别数据集类型与风险模式……")
    dataset = detect_dataset_types(fs_paths)
    detections = match_patterns(fs_paths)

    module_runs: List[Dict[str, object]] = []
    log_info("调用备份相关模块……")
    module_runs.extend(run_backup_modules_if_detected(dataset, src, out_root))
    log_info("调用越狱检测模块……")
    module_runs.append(run_jb_detector_if_ready(src, out_root))
    log_info("调用 sysdiagnose/OSLog 相关模块……")
    module_runs.extend(run_sysdiag_modules_if_ready(src, fs_paths, out_root))
    log_info("调用 MVT 模块……")
    mvt_outputs, mvt_findings = run_mvt_if_needed(dataset, src, out_root, iocs_dir, backup_password)
    module_runs.extend(mvt_outputs)

    tree_inference: Optional[List[Dict[str, object]]] = None
    if tree_path:
        log_info("加载 tree.txt 进行规则调试（不影响风险判定）……")
        tree_inference = match_patterns(load_tree_file(tree_path))

    log_info("汇总报告并写入输出目录……")
    report = build_report(src, detections, module_runs, dataset, mvt_findings, tree_inference)

    report_json_path = out_root / "unified_report.json"
    report_md_path = out_root / "unified_report.md"
    report_json_path.write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")
    report_md_path.write_text(build_markdown(report), encoding="utf-8")

    print(f"统一报告已生成：{report_json_path} / {report_md_path}")
    print(f"模块输出目录：{out_root}")
    if tree_path:
        print("已加载 tree.txt 进行规则调试（不影响最终判定）")
    return report


def main() -> None:
    parser = argparse.ArgumentParser(description="基于提权备份目录的全量检测")
    parser.add_argument("--src", type=Path, help="真实备份目录 (必需)")
    parser.add_argument("--tree", type=Path, help="tree.txt，用于规则调试，不参与判定", required=False)
    parser.add_argument("--out", type=Path, help="输出目录 (默认 unified_output)", default=Path("unified_output"))
    parser.add_argument("--backup-password", dest="backup_password", help="如备份加密，可提供密码给 mvt decrypt-backup", default=None)
    args = parser.parse_args()

    if args.src:
        run_detection(args.src, args.tree, args.out, args.backup_password)
    elif args.tree:
        run_tree_only(args.tree)
    else:
        parser.error("必须至少提供 --src 或 --tree")


if __name__ == "__main__":
    main()
