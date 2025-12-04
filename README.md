# datalogic

统一的 iOS 备份、sysdiagnose 与安全检测命令行工具链。项目将原有脚本打包成可安装的 `datalogic` CLI，覆盖备份配置扫描、证书检测、系统日志分析与越狱检测等场景。

## 安装

```bash
pip install .
```

安装后可直接使用 `datalogic` 命令。

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

## 模块与输出说明

- `ios.backup`：负责备份配置、证书、全量检测与目录还原，输出 JSON/Markdown 报告及还原目录。
- `ios.sysdiag`：针对 sysdiagnose 生成结构化与 Markdown 报告，支持日志进程分析与设备信息抽取。
- `security`：基于备份/日志产物进行越狱、插件和系统分区新增文件检测，输出 `jailbreak_report.md`。

所有报告与导出文件路径可通过命令行参数控制；未指定的输出目录默认使用当前工作目录或脚本内部的默认文件名。
