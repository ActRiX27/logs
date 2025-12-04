# Changelog

## v0.2.0
- 发布首个正式发行包，支持 `pip install datalogic` 安装。
- 新增 `detect_from_tree.py` 统一检测入口，自动扫描提权备份、iOS Backup、Sysdiagnose，聚合多模块检测结果并输出 JSON/Markdown 报告。
- 深度整合 MVT（`mvt-ios check-backup/check-iocs/decrypt-backup`），支持在 `iocs/` 下自定义域名、路径、行为类 IOC 并纳入统一报告。
- 增强风险细节展示，包含路径命中分布、IOC 计数与风险等级说明。
- 提供 `scripts/build_artifacts.py` 用于在本地生成发行用的 wheel 与源码包，避免直接拉取二进制产物。

## v0.1.0
- 初始化发布，提供基础的包结构与 CLI 入口。
