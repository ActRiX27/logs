#!/bin/zsh
# =========================================================
# iOS sysdiagnose 自动报告 v12（v8.12 基线 + v11.1 增强）
# 仅基于 mvt-ios check-fs 能见范围；不包含备份专属数据（浏览史/描述文件/证书等）。
# 用法：zsh ./generate_sysdiag_report_v12.sh --src ./unpacked --out ./output_auto [--fast]
# 依赖：mvt-ios, jq, plutil(macOS自带), 可选 pandoc
# =========================================================

set -Eeuo pipefail
export LC_ALL=C
trap 'echo "❌ 出错于第 $LINENO 行: $BASH_COMMAND" >&2' ERR

# --------- 工具函数 ----------
normalize_pt() {
  # 仅保留 iPhoneN,N / iPadN,N / iPodN,N（剥离“路径:命中”等噪声）
  print -- "$1" | grep -aoE 'iPhone[0-9]+,[0-9]+|iPad[0-9]+,[0-9]+|iPod[0-9]+,[0-9]+' | head -n1 || true
}

# --------- 参数 ----------
SRC_DIR=""
OUT_DIR=""
FAST_MODE="0"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --src) SRC_DIR="$2"; shift 2 ;;
    --out) OUT_DIR="$2"; shift 2 ;;
    --fast) FAST_MODE="1"; shift 1 ;;
    *) echo "未知参数: $1" >&2; exit 1 ;;
  esac
done

[[ -n "$SRC_DIR" && -n "$OUT_DIR" ]] || { echo "用法：$0 --src <unpacked_dir> --out <output_dir> [--fast]"; exit 1; }
[[ -d "$SRC_DIR" ]] || { echo "❌ 源目录不存在：$SRC_DIR" >&2; exit 1; }

mkdir -p "$OUT_DIR" "$OUT_DIR/oslog_enriched"
FILESYSTEM="$OUT_DIR/filesystem.json"
INFO="$OUT_DIR/info.json"
TIMELINE="$OUT_DIR/timeline.csv"
COMMAND="$OUT_DIR/command.log"
REPORT_MD="$OUT_DIR/ios_sysdiagnose_report.md"
REPORT_DOCX="$OUT_DIR/ios_sysdiagnose_report.docx"
OSLOG_OUT="$OUT_DIR/oslog_enriched"

echo "📁 输入目录: $SRC_DIR"
echo "📂 输出目录: $OUT_DIR"

# --------- 依赖检查 ----------
for dep in jq plutil; do
  command -v "$dep" >/dev/null 2>&1 || { echo "❌ 需要依赖缺失：$dep" >&2; exit 1; }
done
command -v mvt-ios >/dev/null 2>&1 || { echo "❌ 未找到 mvt-ios" >&2; exit 1; }

# --------- 若无 MVT 输出则执行 ----------
if [[ ! -f "$FILESYSTEM" || ! -f "$INFO" || ! -f "$TIMELINE" || ! -f "$COMMAND" ]]; then
  echo "⏳ 未检测到 MVT 输出，开始分析 sysdiagnose..."
  mvt-ios check-fs "$SRC_DIR" -o "$OUT_DIR"

  # 等待写盘稳定（避免“刚跑完就读不到”的情况）
  for f in "$FILESYSTEM" "$INFO" "$TIMELINE" "$COMMAND"; do
    for i in {1..15}; do [[ -f "$f" ]] && break; sleep 1; done
    [[ -f "$f" ]] || { echo "❌ 缺少输出文件：$f" >&2; exit 1; }
  done
else
  echo "✅ 检测到现有 MVT 输出，跳过分析阶段"
fi

echo "⏳ 正在解析（仅保留 sysdiagnose 可见范围；OSLog 富集可选）..."

# --------- 基础信息（info.json） ----------
DEVICE_NAME="$(jq -r '.device_name // "Unknown Device"' "$INFO" 2>/dev/null || echo "Unknown Device")"
SCAN_TIME="$(jq -r '.scan_time // "Unknown Time"' "$INFO" 2>/dev/null || echo "Unknown Time")"
MVT_VERSION="$(jq -r '.mvt_version // "Unknown"' "$INFO" 2>/dev/null || echo "Unknown")"
TOTAL_FILES="$(jq 'length' "$FILESYSTEM" 2>/dev/null || echo "0")"

# --------- iOS 版本 / Build（SystemVersion.plist 权威） ----------
IOS_VERSION=""; OS_BUILD=""
SV="$(find "$SRC_DIR" -type f -path '*/SystemVersion/SystemVersion.plist' -print -quit 2>/dev/null || true)"
if [[ -n "$SV" ]]; then
  IOS_VERSION="$(plutil -extract ProductVersion raw -o - "$SV" 2>/dev/null || echo "")"
  OS_BUILD="$(plutil -extract ProductBuildVersion raw -o - "$SV" 2>/dev/null || echo "")"
  [[ -z "$OS_BUILD" ]] && OS_BUILD="$(plutil -convert json -o - "$SV" 2>/dev/null | jq -r '.ProductBuildVersion // .BuildVersion // .OSBuildVersion // .OSBuild // empty' | head -n1)"
fi

# --------- 机型识别（ProductType 优先；HWModel 次之） ----------
PRODUCT_TYPE=""; HW_MODEL=""; MARKETING_NAME="Unknown"

# A. 先找含 ProductType 的 plist（文本/二进制都可由 plutil 转）
PT_PLIST="$(grep -RIl --binary-files=text '"ProductType"' "$SRC_DIR" 2>/dev/null | head -n1 || true)"
if [[ -n "$PT_PLIST" ]]; then
  pt_raw="$(plutil -convert json -o - "$PT_PLIST" 2>/dev/null | jq -r '.ProductType // .Product // empty' | head -n1)"
  PRODUCT_TYPE="$(normalize_pt "$pt_raw")"
fi

# B. 取不到就全局扫（注意 -h 去文件名前缀，-o 只输出命中）
if [[ -z "$PRODUCT_TYPE" ]]; then
  PRODUCT_TYPE="$(grep -RahoE 'iPhone[0-9]+,[0-9]+|iPad[0-9]+,[0-9]+|iPod[0-9]+,[0-9]+' "$SRC_DIR" 2>/dev/null | head -n1 || true)"
fi

# C. OSLog 兜底（慢；仅在有 logarchive 且未启用 --fast 时启用）
LOGARCH="$(find "$SRC_DIR" -type d -name 'system_logs.logarchive' -print -quit 2>/dev/null || true)"
if [[ -z "$PRODUCT_TYPE" && -n "$LOGARCH" && "$FAST_MODE" = "0" ]]; then
  echo "⏳ 通过 OSLog 深度扫描机型标识（可能较慢）..."
  local_hit="$(log show --archive "$LOGARCH" --predicate 'eventMessage CONTAINS[c] "iPhone" OR composedMessage CONTAINS[c] "iPhone"' --info 2>/dev/null \
               | grep -aoE 'iPhone[0-9]+,[0-9]+' \
               | head -n1 || true)"
  [[ -n "$local_hit" ]] && PRODUCT_TYPE="$local_hit"
fi

# D. HWModel（可展示；不参与营销名映射）
if [[ -z "$HW_MODEL" ]]; then
  HW_PLIST="$(grep -RIl --binary-files=text -E '"HardwareModel"|"HWModel"|"HWModelStr"' "$SRC_DIR" 2>/dev/null | head -n1 || true)"
  if [[ -n "$HW_PLIST" ]]; then
    HW_MODEL="$(plutil -convert json -o - "$HW_PLIST" 2>/dev/null | jq -r '.HardwareModel // .HWModel // .HWModelStr // empty' | head -n1)"
  fi
fi

# --------- 标识符 -> 营销名映射 ----------
typeset -A PT_MAP
PT_MAP=(
  "iPhone17,1" "iPhone 16 Pro"
  "iPhone17,2" "iPhone 16 Pro Max"
  "iPhone16,1" "iPhone 15 Pro"
  "iPhone16,2" "iPhone 15 Pro Max"
  "iPhone15,4" "iPhone 15"
  "iPhone15,5" "iPhone 15 Plus"
  "iPhone15,2" "iPhone 14 Pro"
  "iPhone15,3" "iPhone 14 Pro Max"
  "iPhone14,7" "iPhone 14"
  "iPhone14,8" "iPhone 14 Plus"
  "iPhone14,2" "iPhone 13 Pro"
  "iPhone14,3" "iPhone 13 Pro Max"
  "iPhone14,4" "iPhone 13 mini"
  "iPhone14,5" "iPhone 13"
  "iPhone13,1" "iPhone 12 mini"
  "iPhone13,2" "iPhone 12"
  "iPhone13,3" "iPhone 12 Pro"
  "iPhone13,4" "iPhone 12 Pro Max"
)
if [[ -n "${PRODUCT_TYPE:-}" && -n "${PT_MAP[$PRODUCT_TYPE]:-}" ]]; then
  MARKETING_NAME="${PT_MAP[$PRODUCT_TYPE]}"
elif [[ -n "${PRODUCT_TYPE:-}" ]]; then
  MARKETING_NAME="$PRODUCT_TYPE"
elif [[ -n "${HW_MODEL:-}" ]]; then
  MARKETING_NAME="$HW_MODEL"
else
  MARKETING_NAME="Unknown"
fi

# --------- 设备名 / 扫描时间 兜底 ----------
if [[ "$DEVICE_NAME" == "Unknown Device" || "$DEVICE_NAME" == "Unknown" || -z "$DEVICE_NAME" ]]; then
  if [[ "$MARKETING_NAME" != "Unknown" ]]; then
    DEVICE_NAME="$MARKETING_NAME"
  elif [[ -n "${PRODUCT_TYPE:-}" ]]; then
    DEVICE_NAME="$PRODUCT_TYPE"
  elif [[ -n "${HW_MODEL:-}" ]]; then
    DEVICE_NAME="$HW_MODEL"
  else
    DEVICE_NAME="iPhone"
  fi
fi

if [[ "$SCAN_TIME" == "Unknown Time" || -z "$SCAN_TIME" ]]; then
  SYSROOT="$(find "$SRC_DIR" -maxdepth 1 -type d -name 'sysdiagnose_*_iPhone-OS_*' -print -quit 2>/dev/null || true)"
  if [[ -z "$SYSROOT" && -n "$LOGARCH" ]]; then SYSROOT="$(dirname "$LOGARCH")"; fi
  if [[ -n "$SYSROOT" ]]; then
    BASE="$(basename "$SYSROOT")"
    # sysdiagnose_2025.11.13_10-21-43+0800_iPhone-OS_iPhone_22G100 -> 2025-11-13 10:21:43 +0800
    TS="$(echo "$BASE" | sed -nE 's/^sysdiagnose_([0-9]{4})\.([0-9]{2})\.([0-9]{2})_([0-9]{2})-([0-9]{2})-([0-9]{2})\+([0-9]{4}).*/\1-\2-\3 \4:\5:\6 +\7/p')"
    [[ -n "$TS" ]] && SCAN_TIME="$TS"
  fi
fi

# --------- command.log 统计 ----------
MODULE_RUNS="$(grep -E "Running module " "$COMMAND" || true)"
NO_DETECTIONS="$(grep -c "produced no detections" "$COMMAND" || echo 0)"
NO_DATA="$(grep -c "no data to extract" "$COMMAND" || echo 0)"
IOC_TOTAL="$(grep -Eo 'Loaded a total of [0-9]+ unique indicators' "$COMMAND" | awk '{print $5}' | tail -n1)"
IOC_TOTAL="${IOC_TOTAL:-0}"
IOC_PACKS="$(grep -cE '^.*Parsing STIX2 indicators file' "$COMMAND" || echo 0)"
if grep -qE "IOC match|MATCHED" "$COMMAND" 2>/dev/null; then
  IOC_HITS="$(grep -E "IOC match|MATCHED" "$COMMAND" | tail -n 50)"
  IOC_RESULT="DETECTED"
else
  IOC_HITS=""; IOC_RESULT="NONE"
fi

# --------- filesystem.json 统计（仅 sysdiagnose 能见部分） ----------
TOP_DIRS="$(
  jq -r '.[].path' "$FILESYSTEM" \
  | awk -F'/' '{if (NF>=2) print "/"$2; else print "/"}' \
  | sort | uniq -c | sort -nr | head -n 10 \
  | awk '{printf("- %s: %s 项\n", $2, $1)}'
)"
TOP_EXT="$(
  jq -r '.[].path' "$FILESYSTEM" \
  | awk -F'.' 'NF>1 {print tolower($NF)}' \
  | sort | uniq -c | sort -nr | head -n 10 \
  | awk '{printf("- .%s: %s 项\n", $2, $1)}'
)"
JAILBREAK_PATHS="$(
  { jq -r '.[].path' "$FILESYSTEM" \
    | grep -E '(^|/)(MobileSubstrate|Substrate|Cydia|apt|dpkg|/usr/libexec/ssh|/bin/bash)($|/)' \
    || true; } \
  | sort -u
)"
JAILBREAK_COUNT="$(echo "$JAILBREAK_PATHS" | sed '/^$/d' | wc -l | tr -d ' ')"
DEV_PATHS="$(
  { jq -r '.[].path' "$FILESYSTEM" \
    | grep -E '(^|/)(frida|lldb|instruments|Developer|XCTest|dyld_shared_cache)($|/|\\.)' \
    || true; } \
  | sort -u
)"
DEV_COUNT="$(echo "$DEV_PATHS" | sed '/^$/d' | wc -l | tr -d ' ')"
TOP_CHANGED_DIRS="$(
  awk -F',' 'NR>1 {
    p=$2; gsub(/^"|"$/, "", p);
    if (length(p)>0){
      n=split(p, a, "/");
      if(n>=3){print "/"a[2]"/"a[3]}
      else if(n>=2){print "/"a[2]}
      else {print "/"}
    }
  }' "$TIMELINE" \
  | sort | uniq -c | sort -nr | head -n 10 \
  | awk '{printf("- %s: %s 次变更\n", $2, $1)}'
)"
RECENT_CHANGES="$(
  tail -n +2 "$TIMELINE" \
  | awk -F',' '{t=$1; p=$2; gsub(/^"|"$/, "", t); gsub(/^"|"$/, "", p); if(length(t)>0 && length(p)>0) print t" -> "p}' \
  | tail -n 20 | sed 's/^/- /'
)"

# --------- OSLog 富集（可选；不影响“仅 sysdiagnose 能见”原则） ----------
TRUSTD_TSV=""; VPN_SUMMARY=""; PROFILE_SUMMARY=""; PROC_LIST=""; TOP_DOMAINS=""
if [[ -n "$LOGARCH" && "$FAST_MODE" = "0" ]]; then
  echo "🔎 OSLog 富集提取（trustd/VPN/MDM/进程候选）..."
  log show --archive "$LOGARCH" --predicate 'subsystem == "com.apple.trustd"' --info 2>/dev/null \
    | egrep -i 'ssl|tls|certificate|pin|trust|revocation|ocsp|crl|expired|untrusted' \
    > "$OSLOG_OUT/trustd_tls_errors.log" || true
  awk -F' : ' '{print $1"|" $2}' "$OSLOG_OUT/trustd_tls_errors.log" 2>/dev/null | sed 's/  *//g' \
    > "$OSLOG_OUT/trustd_tls_errors.tsv" || true
  TRUSTD_TSV="$(tail -n 20 "$OSLOG_OUT/trustd_tls_errors.tsv" 2>/dev/null || true)"
  grep -aoE '[A-Za-z0-9.-]+\.[A-Za-z]{2,}' "$OSLOG_OUT/trustd_tls_errors.log" 2>/dev/null \
    | tr '[:upper:]' '[:lower:]' | sort | uniq -c | sort -nr | head -n 15 \
    > "$OSLOG_OUT/trustd_top_domains.txt" || true
  TOP_DOMAINS="$(cat "$OSLOG_OUT/trustd_top_domains.txt" 2>/dev/null || true)"

  log show --archive "$LOGARCH" --predicate '(subsystem CONTAINS "com.apple.NetworkExtension") OR (process CONTAINS "neagent") OR (process CONTAINS "configd")' --info 2>/dev/null \
    > "$OSLOG_OUT/vpn_neactivity.log" || true
  egrep -i 'tunnel|connect|disconnect|proxy|dns|profile|installed|removed|configuration' "$OSLOG_OUT/vpn_neactivity.log" 2>/dev/null \
    > "$OSLOG_OUT/vpn_summary.txt" || true
  VPN_SUMMARY="$(tail -n 30 "$OSLOG_OUT/vpn_summary.txt" 2>/dev/null || true)"

  log show --archive "$LOGARCH" --predicate '(process CONTAINS "profiled") OR (subsystem CONTAINS "com.apple.managedconfiguration") OR (process CONTAINS "mdmd")' --info 2>/dev/null \
    > "$OSLOG_OUT/profile_mdm.log" || true
  egrep -i 'install|remove|mdm|payload|profile|configuration|enterprise|supervised' "$OSLOG_OUT/profile_mdm.log" 2>/dev/null \
    > "$OSLOG_OUT/profile_mdm_summary.txt" || true
  PROFILE_SUMMARY="$(tail -n 30 "$OSLOG_OUT/profile_mdm_summary.txt" 2>/dev/null || true)"

  log show --archive "$LOGARCH" --predicate '(process CONTAINS "runningboardd") OR (process CONTAINS "launchd") OR (eventMessage CONTAINS "assertion")' --info 2>/dev/null \
    > "$OSLOG_OUT/process_runningboardd.log" || true
  grep -aoE '[A-Za-z0-9._-]+(\.app)?' "$OSLOG_OUT/process_runningboardd.log" 2>/dev/null \
    | sort -u > "$OSLOG_OUT/process_candidates.txt" || true
  PROC_LIST="$(head -n 40 "$OSLOG_OUT/process_candidates.txt" 2>/dev/null || true)"
else
  echo "⚙️ 已启用 --fast 或未找到 logarchive，跳过 OSLog 富集。"
fi

# --------- 生成报告 ----------
echo "📝 正在生成报告..."
{
  echo "# 📱 iOS sysdiagnose 安全分析报告（v12，check-fs 基线 + 可选 OSLog）"
  echo
  echo "**生成时间：** $(date '+%Y-%m-%d %H:%M:%S')"
  echo "**检测设备：** ${MARKETING_NAME}"
  echo "**设备型号（ProductType）：** ${PRODUCT_TYPE:-Unknown}"
  echo "**iOS 版本：** ${IOS_VERSION:-Unknown}    **Build：** ${OS_BUILD:-Unknown}"
  echo "**扫描时间：** ${SCAN_TIME}"
  echo "**MVT 版本：** ${MVT_VERSION}"
  echo
  echo "## 0. 声明"
  echo "- 本报告**仅**基于 sysdiagnose 与 \`mvt-ios check-fs\` 可见的文件与日志。"
  echo "- **不包含**：浏览器历史/Favicons、描述文件/MDM、证书信任、应用清单、进程清单等（这些需 \`check-backup\`）。"
  echo "- 若未启用 \`--fast\` 且存在 OSLog 归档，会附带 **可选** 富集节选（不改变取证边界）。"
  echo
  echo "## 1. 任务与模块执行概览"
  echo "- 加载 IOC：$IOC_TOTAL 条（来自 $IOC_PACKS 个情报集）"
  echo "- 模块“无命中”次数：$NO_DETECTIONS"
  echo "- 模块“无数据可提取”次数：$NO_DATA"
  echo "- 已运行模块："
  [[ -n "$MODULE_RUNS" ]] && echo "$MODULE_RUNS" | sed 's/^/- /' || echo "- （command.log 未记录 Running module 行）"
  echo
  echo "## 2. 文件系统视角（filesystem.json）"
  echo "- 条目总数：$TOTAL_FILES"
  echo "### 2.1 Top 目录（前 10）"; [[ -n "$TOP_DIRS" ]] && echo "$TOP_DIRS" || echo "- 无"
  echo
  echo "### 2.2 Top 扩展名（前 10）"; [[ -n "$TOP_EXT" ]] && echo "$TOP_EXT" || echo "- 无"
  echo
  echo "### 2.3 越狱迹象（路径规则匹配，最多列 50 条）"
  echo "- 计数：$JAILBREAK_COUNT"
  if [[ "$JAILBREAK_COUNT" -gt 0 ]]; then
    echo '```'; echo "$JAILBREAK_PATHS" | head -n 50; echo '```'
    echo "> 注：仅基于路径关键字（MobileSubstrate/Cydia/apt/dpkg/ssh/bash），需人工复核。"
  else
    echo "- 未发现越狱路径特征。"
  fi
  echo
  echo "### 2.4 开发/调试迹象（路径规则匹配，最多列 50 条）"
  echo "- 计数：$DEV_COUNT"
  if (( DEV_COUNT > 0 )); then
    echo '```'; echo "$DEV_PATHS" | head -n 50; echo '```'
    echo "> 注：仅路径特征（frida/lldb/Developer/XCTest/dyld_shared_cache 等），并不等同实际调试行为。"
  else
    echo "- 未发现明显的开发/调试路径特征。"
  fi
  echo
  echo "## 3. 时间线（timeline.csv）"
  echo "### 3.1 变更最活跃目录（前 10）"; [[ -n "$TOP_CHANGED_DIRS" ]] && echo "$TOP_CHANGED_DIRS" || echo "- 无可聚合事件"
  echo
  echo "### 3.2 最近 20 条变更"; [[ -n "$RECENT_CHANGES" ]] && echo "$RECENT_CHANGES" || echo "- 无"
  echo
  echo "## 4. OSLog 富集（可选）"
  if [[ "$FAST_MODE" = "1" || -z "$LOGARCH" ]]; then
    echo "- 已跳过 OSLog 富集（--fast 或缺少 logarchive）。"
  else
    echo "### 4.1 trustd/TLS 异常（节选）"; [[ -n "$TRUSTD_TSV" ]] && echo '```'; [[ -n "$TRUSTD_TSV" ]] && echo "$TRUSTD_TSV" && echo '```' || echo "- 无"
    echo
    echo "### 4.2 trustd Top 域名（前 15）"; [[ -n "$TOP_DOMAINS" ]] && echo '```'; [[ -n "$TOP_DOMAINS" ]] && echo "$TOP_DOMAINS" && echo '```' || echo "- 无"
    echo
    echo "### 4.3 VPN / NetworkExtension 事件（节选）"; [[ -n "$VPN_SUMMARY" ]] && echo '```'; [[ -n "$VPN_SUMMARY" ]] && echo "$VPN_SUMMARY" && echo '```' || echo "- 无"
    echo
    echo "### 4.4 描述文件 / MDM（节选）"; [[ -n "$PROFILE_SUMMARY" ]] && echo '```'; [[ -n "$PROFILE_SUMMARY" ]] && echo "$PROFILE_SUMMARY" && echo '```' || echo "- 无"
    echo
    echo "### 4.5 进程活跃候选（Top 40）"; [[ -n "$PROC_LIST" ]] && echo '```'; [[ -n "$PROC_LIST" ]] && echo "$PROC_LIST" && echo '```' || echo "- 无"
  fi
  echo
  echo "## 5. IOC 情报匹配（基于 command.log）"
  if [[ "$IOC_RESULT" == "DETECTED" ]]; then
    echo "### 5.1 命中详情（最近 50 行）"; echo '```'; echo "$IOC_HITS"; echo '```'
  else
    echo "- 未检测到 IOC 命中。"
  fi
  echo
  echo "## 6. 结论与建议（仅基于 sysdiagnose 可见数据）"
  echo "- 若需验证浏览记录/描述文件/证书/应用/进程等，请改用 **加密 iTunes 备份 + mvt-ios check-backup**。"
  echo "- 上述路径/关键字特征建议人工复核，避免误报。"
  echo "- 采集更贴近事件发生时点的 sysdiagnose，并开启“分析与改进”，可提升 OSLog 侧证据密度。"
  echo
  echo "**报告生成时间：** $(date '+%Y-%m-%d %H:%M:%S')"
} > "$REPORT_MD"

# --------- 转 DOCX ----------
if command -v pandoc >/dev/null 2>&1; then
  echo "📄 正在转换为 Word 文档..."
  pandoc "$REPORT_MD" -o "$REPORT_DOCX"
  echo "✅ Word 报告已生成：$REPORT_DOCX"
else
  echo "⚠️ 未检测到 pandoc，仅生成 Markdown：$REPORT_MD"
fi

echo "📦 所有输出文件已保存于：$OUT_DIR"
