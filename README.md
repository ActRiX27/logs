# datalogic

统一的 iOS 备份、sysdiagnose 与安全检测命令行工具链。项目将原有脚本打包成可安装的 `datalogic` CLI，覆盖备份配置扫描、证书检测、系统日志分析与越狱检测等场景。

## 安装

```bash
pip install .
```

安装后可直接使用 `datalogic` 命令。

> 说明：仓库不直接提交 wheel / tar.gz 等二进制发布产物，若需本地生成发行包，请运行 `python scripts/build_artifacts.py`，脚本会使用 `python -m build` 在
> `dist/` 目录下生成可供发布的 wheel 与源码压缩包。

## 安装与使用指南

### 环境准备
- Python 3.8+
- `pip install mvt`
- `pip install -r requirements.txt`
- 可选：`brew install libimobiledevice`（macOS 可使用 libimobiledevice 读取设备信息）

### 安装 MVT（Mobile Verification Toolkit）
- macOS：`brew install mvt`
- 或跨平台：`pip3 install mvt`

### 统一检测脚本示例
```bash
python3 detect_from_tree.py --src /path/to/backup --out ./out
```

- 自动识别目录类型（iOS 备份 / 提权备份 / sysdiagnose），匹配越狱/Hook、权限数据库、MDM/描述文件、企业签名与取证痕迹。
- 自动串联 MVT（check-backup / decrypt-backup / check-iocs）与仓库内置脚本：`ios_backup_full_check.py`、`analyze_profiles.py`、`ios_backup_cert_check.py`、`jb_detector.py`、`process_analyzer`、`sysdiagnose`。
- 生成统一报告 `out/unified_report.json`、`out/unified_report.md`，并输出 MVT 产物到 `out/mvt_output/{json,files,logs}`。

### 自定义 IOC 规则
- 在仓库根目录放置 `iocs/`，支持三类文件：
  - `iocs/domains.json`
  - `iocs/paths.json`
  - `iocs/behavior.json`
- 示例 JSON 结构：
  ```json
  {
    "domains": ["malicious.example.com"],
    "paths": ["/private/var/mobile/Library/ConfigurationProfiles/ClientTruth.plist"],
    "behaviors": ["unexpected_background_location_usage"]
  }
  ```
- 运行时脚本会自动将 `iocs/` 传递给 `mvt-ios check-iocs --iocs iocs/`，并把 IOC 命中并入统一报告。

### 输出格式
- `out/unified_report.json` / `out/unified_report.md`：风险等级（High / Medium / Low）、越权分析、越狱/取证可能性、高敏路径命中、各子模块结果、MVT IOC 聚合，并附带命中路径分布与 IOC 条目计数的风险细节。
- `mvt_output/json`：`mvt-ios check-backup`、`check-iocs` 产出的 JSON。
- `mvt_output/files`：若执行解密/提取的文件输出目录。
- `mvt_output/logs`：所有 MVT 命令的日志输出。

## 命令概览

```text
datalogic
└─ ios
   ├─ backup
   │  ├─ analyze-profiles   # 描述文件/全局偏好/应用限制检测
   │  ├─ cert-check         # 备份证书与企业签名检测
   │  ├─ full-check         # 备份全量安全检测
   │  ├─ restore            # 使用 Manifest.db 还原备份目录结构
   │  └─ parse              # 调用 shell 版全功能取证解析
   └─ sysdiag
      ├─ report             # 生成 sysdiagnose 综合报告 (JSON + Markdown)
      ├─ process            # OSLog 进程行为分析
      └─ extract-info       # 从 sysdiagnose 报告提取设备信息
└─ security
   └─ jbd                   # 越狱/插件/系统新增文件检测
```

## 备份相关命令

- 描述文件/偏好检测
  ```bash
  datalogic ios backup analyze-profiles --input /path/to/restored_tree --out ./output
  ```
- 证书与企业签名检测
  ```bash
  datalogic ios backup cert-check --input /path/to/restored_tree --out ./output
  ```
- 全量安全检测（合并配置、证书、应用扫描）
  ```bash
  datalogic ios backup full-check --input /path/to/restored_tree --out ./output
  ```
- 备份目录还原
  ```bash
  datalogic ios backup restore --input /path/to/decrypted_backup --output ./restored_tree
  ```
- 调用 shell 版全功能取证解析（依赖 zsh、mvt-ios、jq、sqlite3、plutil 等）
  ```bash
  datalogic ios backup parse --backup /path/to/decrypted_backup --out ./backup_output_full
  ```

## sysdiagnose 相关命令

- 生成综合报告（JSON + Markdown）
  ```bash
  datalogic ios sysdiag report --src /path/to/sysdiagnose --out ./sysdiag_report
  ```
- 进程行为分析（可选提供 filesystem.json）
  ```bash
  datalogic ios sysdiag process --src /path/to/oslog_dir --fs /path/to/filesystem.json --out ./process_report
  ```
- 从 Markdown 报告中提取设备信息
  ```bash
  datalogic ios sysdiag extract-info --src ./ios_sysdiagnose_report.md
  ```

## 安全检测命令

- 越狱/插件检测
  ```bash
  datalogic security jbd --src ./artifacts
  ```
  `--src` 目录需包含 `device_info.json`、`filesystem.json`、`system_baseline.json`、`oslog_full.txt` 以及 `output/logs/` 等文件，报告默认输出为该目录下的 `jailbreak_report.md`。

## 基于提权备份目录的全量检测

`detect_from_tree.py` 面向 iOS 17.x 提权后的完整备份目录，实现真实文件扫描 + 风控规则匹配 + 现有检测模块编排的统一入口。tree.txt 仅用于规则调试，不会参与安全判定。

- 深度检测真实备份目录（推荐）
```bash
python detect_from_tree.py --src /path/to/restored_tree --out ./out --backup-password <若备份加密可选>
```
  - 递归扫描真实目录（等效 `tree -a`），匹配越狱/Hook、权限数据库、行为数据库、MDM/描述文件、企业签名/取证、系统分区异常、数据取证残留等路径模式。
  - 自动调用 `ios_backup_full_check`、`ios_backup_cert_check`、`analyze_profiles`、`jb_detector`，并在检测到 sysdiagnose/OSLog 产物时联动 `generate_sysdiag_report`、`process_analyzer`，同时在存在备份或 sysdiagnose 结构时整合 `mvt-ios decrypt-backup` / `check-backup` / `check-iocs`（使用仓库根目录的 `iocs/` 规则）。
  - 统一输出：`out/unified_report.json`、`out/unified_report.md`，聚合路径匹配风险、越狱特征、证书风险、描述文件/MDM 检测、敏感数据库命中、MVT IOC 命中与综合判定；子模块结果默认存放于 `./out/`（未指定时使用 `./unified_output/`）。

- 规则调试模式（仅解析 tree.txt，查看模式命中，不生成安全报告）
  ```bash
  python detect_from_tree.py --tree ./tree.txt
  ```
  仅用于验证目录结构与路径模式，无任何风险输出。

## 模块与输出说明

- `ios.backup`：负责备份配置、证书、全量检测与目录还原，输出 JSON/Markdown 报告及还原目录。
- `ios.sysdiag`：针对 sysdiagnose 生成结构化与 Markdown 报告，支持日志进程分析与设备信息抽取。
- `security`：基于备份/日志产物进行越狱、插件和系统分区新增文件检测，输出 `jailbreak_report.md`。

所有报告与导出文件路径可通过命令行参数控制；未指定的输出目录默认使用当前工作目录或脚本内部的默认文件名。
