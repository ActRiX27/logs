from pathlib import Path
from typing import Optional

import click

from datalogic.ios.backup import (
    analyze_profiles,
    ios_backup_cert_check,
    ios_backup_full_check,
    parse_ios_backup,
    restore_ios_backup,
)
from datalogic.ios.sysdiag import extract_device_info, generate_sysdiag_report, process_analyzer
from datalogic.security import jb_detector


@click.group()
def cli():
    """datalogic: Unified iOS backup, sysdiagnose and security analysis toolkit."""


@cli.group()
def ios():
    """iOS tooling commands."""


@ios.group()
def backup():
    """Backup analysis helpers."""


@backup.command("analyze-profiles")
@click.option("--input", "input_path", required=True, type=click.Path(exists=True, file_okay=False, path_type=Path), help="restored_tree 根目录")
@click.option("--out", "out_path", required=False, type=click.Path(file_okay=False, path_type=Path), help="输出目录")
def backup_analyze_profiles(input_path: Path, out_path: Optional[Path]):
    """Analyze configuration profiles within an iOS backup."""
    analyze_profiles.run(str(input_path), str(out_path) if out_path else None)


@backup.command("cert-check")
@click.option("--input", "input_path", required=True, type=click.Path(exists=True, file_okay=False, path_type=Path), help="restored_tree 根目录")
@click.option("--out", "out_path", required=False, type=click.Path(file_okay=False, path_type=Path), help="输出目录")
def backup_cert_check(input_path: Path, out_path: Optional[Path]):
    """Inspect profile certificates and enterprise signatures in backups."""
    ios_backup_cert_check.run(str(input_path), str(out_path) if out_path else None)


@backup.command("full-check")
@click.option("--input", "input_path", required=True, type=click.Path(exists=True, file_okay=False, path_type=Path), help="restored_tree 根目录")
@click.option("--out", "out_path", required=False, type=click.Path(file_okay=False, path_type=Path), help="输出目录")
def backup_full_check(input_path: Path, out_path: Optional[Path]):
    """Run the full backup security inspection pipeline."""
    ios_backup_full_check.run(str(input_path), str(out_path) if out_path else None)


@backup.command("restore")
@click.option("--input", "input_path", required=True, type=click.Path(exists=True, file_okay=False, path_type=Path), help="解密后的备份目录")
@click.option("--output", "output_path", required=True, type=click.Path(file_okay=False, path_type=Path), help="输出还原目录")
def backup_restore(input_path: Path, output_path: Path):
    """Restore Manifest.db contents into a readable directory structure."""
    restore_ios_backup.run(str(input_path), str(output_path))


@backup.command("parse")
@click.option("--backup", "backup_path", required=True, type=click.Path(exists=True, file_okay=False, path_type=Path), help="已解密的 iOS 备份目录")
@click.option("--out", "out_path", required=True, type=click.Path(file_okay=False, path_type=Path), help="分析输出目录")
def backup_parse(backup_path: Path, out_path: Path):
    """Invoke the full iOS backup forensic parser (shell-based)."""
    parse_ios_backup.run(str(backup_path), str(out_path))


@ios.group()
def sysdiag():
    """sysdiagnose helpers."""


@sysdiag.command("report")
@click.option("--src", "src_path", required=True, type=click.Path(exists=True, file_okay=False, path_type=Path), help="sysdiagnose 解压后的根目录")
@click.option("--out", "out_path", required=True, type=click.Path(file_okay=False, path_type=Path), help="报告输出目录")
def sysdiag_report(src_path: Path, out_path: Path):
    """Generate comprehensive sysdiagnose reports (JSON + Markdown)."""
    generate_sysdiag_report.run(str(src_path), str(out_path))


@sysdiag.command("process")
@click.option("--src", "src_path", required=True, type=click.Path(exists=True, file_okay=False, path_type=Path), help="sysdiagnose/OSLog 所在目录")
@click.option("--fs", "fs_path", required=False, type=click.Path(exists=True, dir_okay=False, path_type=Path), help="filesystem.json 路径")
@click.option("--out", "out_path", required=True, type=click.Path(file_okay=False, path_type=Path), help="输出目录")
def sysdiag_process(src_path: Path, fs_path: Optional[Path], out_path: Path):
    """Analyze process-related OSLog entries."""
    process_analyzer.run(str(src_path), str(fs_path) if fs_path else None, str(out_path))


@sysdiag.command("extract-info")
@click.option("--src", "src_path", required=True, type=click.Path(exists=True, dir_okay=False, path_type=Path), help="ios_sysdiagnose_report.md 路径")
def sysdiag_extract_info(src_path: Path):
    """Extract device metadata from sysdiagnose markdown report."""
    extract_device_info.run(str(src_path))


@cli.group()
def security():
    """Security checks."""


@security.command("jbd")
@click.option("--src", "src_dir", required=True, type=click.Path(exists=True, file_okay=False, path_type=Path), help="包含 device_info.json 等文件的目录")
def security_jbd(src_dir: Path):
    """Run jailbreak detection using extracted artifacts."""
    base = src_dir
    report_path = base / "jailbreak_report.md"
    jb_detector.run(
        device_info_path=base / "device_info.json",
        filesystem_path=base / "filesystem.json",
        baseline_path=base / "system_baseline.json",
        log_path=base / "oslog_full.txt",
        log_dir=base / "output/logs",
        report_path=report_path,
    )
    click.echo(f"Report generated at {report_path}")


def main():
    cli()


if __name__ == "__main__":
    main()
