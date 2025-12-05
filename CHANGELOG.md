# Changelog

<<<<<<< HEAD
=======
## v0.2.5
- 新增 `drafts/` 目录集中存放草案与设计稿，避免在根 README 中混入草稿内容。
- README 补充草案指引索引，指向草案目录的使用约定。
- 版本号更新至 0.2.5，保持包与文档版本一致。

## v0.2.4
- 将“示例与调试资源”说明独立到 `demo_data/README.md`，根 README 仅保留索引，便于集中维护示例说明。
- 更新版本号至 0.2.4，保持包与文档版本一致。

## v0.2.3
- 新增 `demo_data/` 目录，用于存放提权备份的示例 tree.txt、调试脚本等脱敏样例，并内置示例路径树供模式编写参考。
- README 增补示例/调试资源说明，明确示例数据不会影响正式检测流程。

## v0.2.2
- 自动识别输入目录类型：已还原备份、包含 Manifest 的解密备份（可自动还原到 `--out/restored_tree`）、以及含 /var 或 System 的提权备份。
- 备份全量检测新增提权路径兜底搜索与全局文件名搜索，提升描述文件、全局偏好、应用限制的发现率并减少“未找到”误报。
- 文档补充输入格式示例，明确如何提供提权备份目录与解密备份目录。
## v0.2.1
- 引入共享的 JSON 安全转换工具（支持 bytes/base64、日期、Path、集合等），统一备份检测模块的序列化行为。
- 更新备份检测脚本以复用通用转换逻辑，减少重复代码并提升可维护性。

>>>>>>> codex/add-unified-detection-script-detect_from_tree.py-51ys18
## v0.2.0
- 发布首个正式发行包，支持 `pip install datalogic` 安装。
- 新增 `detect_from_tree.py` 统一检测入口，自动扫描提权备份、iOS Backup、Sysdiagnose，聚合多模块检测结果并输出 JSON/Markdown 报告。
- 深度整合 MVT（`mvt-ios check-backup/check-iocs/decrypt-backup`），支持在 `iocs/` 下自定义域名、路径、行为类 IOC 并纳入统一报告。
- 增强风险细节展示，包含路径命中分布、IOC 计数与风险等级说明。
- 提供 `scripts/build_artifacts.py` 用于在本地生成发行用的 wheel 与源码包，避免直接拉取二进制产物。
<<<<<<< HEAD
=======
- 新增 `scripts/fetch_release_assets.py`，支持通过 GitHub Releases 自动下载指定 tag 的 wheel 与 tar.gz，用于无法直接提交或同步二进制文件的场景。
>>>>>>> codex/add-unified-detection-script-detect_from_tree.py-51ys18

## v0.1.0
- 初始化发布，提供基础的包结构与 CLI 入口。
