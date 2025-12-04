#!/bin/zsh
# =========================================================
# iOS Backup 全功能取证解析器
# - 输入：已解密的 iOS 备份目录（含 Manifest.db / Info.plist / hashed 子目录）
# - 输出：backup_analysis/ 下的 mvt 结果 + backup_report_full.md/.docx
# - 目标：
#   * 配置 / 描述文件 / TCC
#   * 证书 / keychain-backup.plist 导出
#   * 浏览器历史 / 数据使用
#   * 短信 / 短信附件 / 通话记录 / 通讯录
#   * 应用清单 / 进程名候选 / 越狱关键字
#   * IOC 命中情况 + 可疑文件导出
#
# 用法示例：
#   zsh ./parse_ios_backup.sh \
#       --backup "/path/to/decrypted_backup" \
#       --out "./backup_output_full"
#
# 依赖：mvt-ios, jq, sqlite3, plutil(macOS自带), 可选 pandoc
# =========================================================

set -euo pipefail
trap 'echo "❌ 出错于第 $LINENO 行"; exit 1' ERR
export LC_ALL=C

# ---------------- 参数解析 ----------------
BACKUP_DIR=""
OUT_DIR=""

while [[ $# -gt 0 ]]; do
  case "$1" in
    --backup)
      BACKUP_DIR="$2"; shift 2;;
    --out)
      OUT_DIR="$2"; shift 2;;
    *)
      echo "未知参数: $1"; exit 1;;
  esac
done

if [[ -z "$BACKUP_DIR" || -z "$OUT_DIR" ]]; then
  echo "用法: $0 --backup <decrypted_backup_dir> --out <output_dir>"
  exit 1
fi

[[ -d "$BACKUP_DIR" ]] || { echo "❌ 备份目录不存在: $BACKUP_DIR"; exit 1; }

# ---------------- 依赖检查 ----------------
for dep in jq sqlite3 plutil; do
  command -v "$dep" >/dev/null 2>&1 || { echo "❌ 依赖缺失: $dep"; exit 1; }
done
command -v mvt-ios >/dev/null 2>&1 || { echo "❌ 未找到 mvt-ios"; exit 1; }

mkdir -p "$OUT_DIR"
ANALYSIS_DIR="$OUT_DIR/backup_analysis"
mkdir -p "$ANALYSIS_DIR"
ARTIFACT_DIR="$OUT_DIR/artifacts"
mkdir -p "$ARTIFACT_DIR"

echo "📁 备份目录:       $BACKUP_DIR"
echo "📂 分析输出目录:   $OUT_DIR"
echo "📂 MVT 输出目录:   $ANALYSIS_DIR"

# ---------------- 若无 MVT 输出则运行 check-backup ----------------
if [[ ! -f "$ANALYSIS_DIR/info.json" ]]; then
  echo "⏳ 未检测到 MVT backup 输出，开始执行 mvt-ios check-backup..."
  mvt-ios check-backup -o "$ANALYSIS_DIR" "$BACKUP_DIR"
  echo "⏳ 写盘同步..."
  sleep 2; sync || true
else
  echo "✅ 检测到现有 MVT backup 输出，跳过 mvt-ios 分析阶段"
fi

# ---------------- 关键路径 / 文件 ----------------
MVT_INFO="$ANALYSIS_DIR/info.json"
MVT_TIMELINE="$ANALYSIS_DIR/timeline.csv"
MVT_COMMAND="$ANALYSIS_DIR/command.log"
MVT_MANIFEST_JSON="$ANALYSIS_DIR/manifest.json"  # mvt 的 manifest 模块
BACKUP_INFO_JSON="$ANALYSIS_DIR/backup_info.json"  # mvt 的 backup_info 模块（如存在）

BACKUP_INFO_PLIST="$BACKUP_DIR/Info.plist"
BACKUP_STATUS_PLIST="$BACKUP_DIR/Status.plist"
BACKUP_MANIFEST_DB="$BACKUP_DIR/Manifest.db"
BACKUP_APPS_PLIST="$BACKUP_DIR/Applications.plist"

for f in "$MVT_INFO" "$MVT_COMMAND"; do
  [[ -f "$f" ]] || { echo "❌ 缺少必要文件: $f"; exit 1; }
done

# ---------------- 一些小工具函数 ----------------

# 按 iTunes 规则，根据 fileID 找到物理路径
# 例如 51a4... -> <BACKUP_DIR>/51/51a4...
resolve_file_by_fileid() {
  local fid="$1"
  local dir="${fid:0:2}"
  local path="$BACKUP_DIR/$dir/$fid"
  if [[ -f "$path" ]]; then
    echo "$path"
  else
    echo ""
  fi
}

# 从 Manifest.db 用 domain+relativePath 找 hashed 路径，并复制到 artifacts 子目录
export_artifact() {
  local domain="$1"
  local relpath="$2"
  local subdir="$3"

  [[ -f "$BACKUP_MANIFEST_DB" ]] || return 0

  local sql="SELECT fileID FROM Files WHERE domain = ? AND relativePath = ? LIMIT 1"
  local fid
  fid="$(sqlite3 "$BACKUP_MANIFEST_DB" "$sql" "$domain" "$relpath" || true)"
  if [[ -z "$fid" ]]; then
    return 0
  fi

  local src
  src="$(resolve_file_by_fileid "$fid")"
  [[ -f "$src" ]] || return 0

  local dst_dir="$ARTIFACT_DIR/$subdir"
  mkdir -p "$dst_dir"
  local dst="$dst_dir/$(basename "$relpath")"
  cp -p "$src" "$dst"
  echo "$dst"
}

# 从 JSON 中取某个 key（标量），没有就给默认值
jq_get_or_default() {
  local key="$1"
  local file="$2"
  local def="$3"
  jq -r ".$key // \"$def\"" "$file" 2>/dev/null || echo "$def"
}

# ---------------- 1. 设备 / 备份基础信息 ----------------

DEVICE_NAME="Unknown Device"
PRODUCT_TYPE="Unknown"
IOS_VERSION="Unknown"
IOS_BUILD="Unknown"
BACKUP_DATE="Unknown Time"
BACKUP_ENCRYPTED="Unknown"
COMPUTER_NAME="Unknown"

if [[ -f "$BACKUP_INFO_JSON" ]]; then
  DEVICE_NAME=$(jq_get_or_default "device_name" "$BACKUP_INFO_JSON" "$DEVICE_NAME")
  PRODUCT_TYPE=$(jq_get_or_default "product_type" "$BACKUP_INFO_JSON" "$PRODUCT_TYPE")
  IOS_VERSION=$(jq_get_or_default "product_version" "$BACKUP_INFO_JSON" "$IOS_VERSION")
  IOS_BUILD=$(jq_get_or_default "build_version" "$BACKUP_INFO_JSON" "$IOS_BUILD")
  BACKUP_DATE=$(jq_get_or_default "backup_date" "$BACKUP_INFO_JSON" "$BACKUP_DATE")
  BACKUP_ENCRYPTED=$(jq_get_or_default "is_encrypted" "$BACKUP_INFO_JSON" "$BACKUP_ENCRYPTED")
  COMPUTER_NAME=$(jq_get_or_default "computer_name" "$BACKUP_INFO_JSON" "$COMPUTER_NAME")
fi

# 兜底：从 Info.plist / Status.plist 中再扒一层
if [[ -f "$BACKUP_INFO_PLIST" ]]; then
  [[ "$DEVICE_NAME" == "Unknown Device" ]] && \
    DEVICE_NAME="$(plutil -extract Device Name raw -o - "$BACKUP_INFO_PLIST" 2>/dev/null || echo "$DEVICE_NAME")"
  [[ "$PRODUCT_TYPE" == "Unknown" ]] && \
    PRODUCT_TYPE="$(plutil -extract Product Type raw -o - "$BACKUP_INFO_PLIST" 2>/dev/null || echo "$PRODUCT_TYPE")"
  [[ "$IOS_VERSION" == "Unknown" ]] && \
    IOS_VERSION="$(plutil -extract Product Version raw -o - "$BACKUP_INFO_PLIST" 2>/dev/null || echo "$IOS_VERSION")"
fi

if [[ -f "$BACKUP_STATUS_PLIST" ]]; then
  [[ "$BACKUP_ENCRYPTED" == "Unknown" ]] && \
    BACKUP_ENCRYPTED="$(plutil -extract IsEncrypted raw -o - "$BACKUP_STATUS_PLIST" 2>/dev/null || echo "$BACKUP_ENCRYPTED")"
fi

MVT_VERSION=$(jq_get_or_default "mvt_version" "$MVT_INFO" "Unknown")

# ---------------- 2. MVT 运行情况（IOC / 模块） ----------------

MODULE_RUNS=$(grep -E "Running module " "$MVT_COMMAND" || true)
NO_DETECTIONS=$(grep -c "produced no detections" "$MVT_COMMAND" || echo 0)
NO_DATA=$(grep -c "no data to extract" "$MVT_COMMAND" || echo 0)
IOC_TOTAL=$(grep -Eo 'Loaded a total of [0-9]+ unique indicators' "$MVT_COMMAND" | awk '{print $5}' | tail -n1)
IOC_TOTAL=${IOC_TOTAL:-0}
IOC_PACKS=$(grep -cE '^.*Parsing STIX2 indicators file' "$MVT_COMMAND" || echo 0)

if grep -qE "IOC match|MATCHED" "$MVT_COMMAND" 2>/dev/null; then
  IOC_HITS=$(grep -E "IOC match|MATCHED" "$MVT_COMMAND" | tail -n 80)
  IOC_RESULT="DETECTED"
else
  IOC_HITS=""
  IOC_RESULT="NONE"
fi

# ---------------- 3. 配置 / TCC / 描述文件（基于 JSON） ----------------

GLOBAL_PREF_JSON="$ANALYSIS_DIR/global_preferences.json"
TCC_JSON="$ANALYSIS_DIR/tcc.json"

TCC_TOTAL=0
TCC_SENSITIVE=0
TCC_TOP_APPS=""
if [[ -f "$TCC_JSON" ]]; then
  TCC_TOTAL=$(jq 'length' "$TCC_JSON" 2>/dev/null || echo 0)
  # 摄像头/麦克风/定位/通讯录等敏感权限
  TCC_SENSITIVE=$(jq '[.[] | select(.service | test("kTCCService(Camera|Microphone|Photos|Contacts|Location|Bluetooth|Motion)"))] | length' "$TCC_JSON" 2>/dev/null || echo 0)
  TCC_TOP_APPS=$(
    jq -r '.[] | .client? // .identifier? // empty' "$TCC_JSON" \
    | sort | uniq -c | sort -nr | head -n 10 \
    | awk '{printf("- %s: %s 项权限记录\n",$2,$1)}'
  )
fi

# 这里先做一个简单的“可疑配置点”统计，你后面可以按需扩展规则
CFG_FLAGS=""
if [[ -f "$GLOBAL_PREF_JSON" ]]; then
  # 示例：统计是否关闭 Analytics / 是否有 MDM 提示等
  CFG_FLAGS=$(
    jq -r '
      to_entries[]
      | select(.key | test("Analytics|MDM|Profile|Configuration"; "i"))
      | "- " + .key + ": " + ( .value|tostring )
    ' "$GLOBAL_PREF_JSON" 2>/dev/null || true
  )
fi

# ---------------- 4. 浏览 / 网络使用 ----------------

SAFARI_JSON=""
WEBKIT_STATS_JSON=""
DATAUSAGE_JSON=""

# Safari 历史
if [[ -f "$ANALYSIS_DIR/safari_history.json" ]]; then
    SAFARI_JSON="$ANALYSIS_DIR/safari_history.json"
fi

# WebKit 资源访问统计
if [[ -f "$ANALYSIS_DIR/webkit_resource_load_statistics.json" ]]; then
    WEBKIT_STATS_JSON="$ANALYSIS_DIR/webkit_resource_load_statistics.json"
fi

# 流量/数据使用情况 (datausage.json)
if [[ -f "$ANALYSIS_DIR/datausage.json" ]]; then
    DATAUSAGE_JSON="$ANALYSIS_DIR/datausage.json"
fi

SAFARI_TOP_DOMAINS=""
if [[ -f "$SAFARI_JSON" ]]; then
  SAFARI_TOP_DOMAINS=$(
    jq -r '
      .. | objects | .url? // .URL? // empty
    ' "$SAFARI_JSON" 2>/dev/null \
    | sed -E 's#^[a-zA-Z]+://##' | cut -d'/' -f1 \
    | sed '/^$/d' \
    | sort | uniq -c | sort -nr | head -n 15 \
    | awk '{printf("- %s: %s 次访问\n",$2,$1)}'
  )
fi

WEBKIT_TOP_THIRD=""
if [[ -f "$WEBKIT_STATS_JSON" ]]; then
  WEBKIT_TOP_THIRD=$(
    jq -r '
      .. | objects
      | select(has("registrable_domain") and has("total_subresource_requests"))
      | .registrable_domain + " " + (.total_subresource_requests|tostring)
    ' "$WEBKIT_STATS_JSON" 2>/dev/null \
    | awk '{print $1" "$2}' \
    | sort -k2nr | head -n 15 \
    | awk '{printf("- %s: %s 次子资源请求\n",$1,$2)}'
  )
fi

# ---------------- 5. 通讯录 / 短信 / 通话 ----------------

CONTACTS_JSON="$ANALYSIS_DIR/contacts.json"
SMS_JSON="$ANALYSIS_DIR/sms.json"
CALLS_JSON="$ANALYSIS_DIR/calls.json"

CONTACTS_COUNT=0
SMS_COUNT=0
CALLS_COUNT=0

if [[ -f "$CONTACTS_JSON" ]]; then
  CONTACTS_COUNT=$(jq 'length' "$CONTACTS_JSON" 2>/dev/null || echo 0)
fi
if [[ -f "$SMS_JSON" ]]; then
  SMS_COUNT=$(jq 'length' "$SMS_JSON" 2>/dev/null || echo 0)
fi
if [[ -f "$CALLS_JSON" ]]; then
  CALLS_COUNT=$(jq 'length' "$CALLS_JSON" 2>/dev/null || echo 0)
fi

# 简单列出最近几条通话记录（号码 + 方向）
RECENT_CALLS=""
if [[ -f "$CALLS_JSON" ]]; then
  RECENT_CALLS=$(
    jq -r '
      .[] | select(.date? != null)
      | [.date, (.address? // .number? // "Unknown"), (.type? // "")]
      | @tsv
    ' "$CALLS_JSON" 2>/dev/null \
    | sort | tail -n 20 \
    | awk -F'\t' '{printf("- %s -> %s (%s)\n",$1,$2,$3)}'
  )
fi

# ---------------- 6. 应用清单 / 进程候选 / 越狱关键字 ----------------

APPS_TOTAL=0
APPS_USER=0
APPS_ENTERPRISE=0
APPS_LIST_TOP=""

# 6.1 优先用 MVT 的 manifest.json（如果有）
if [[ -f "$MVT_MANIFEST_JSON" ]]; then
  APPS_TOTAL=$(jq 'length' "$MVT_MANIFEST_JSON" 2>/dev/null || echo 0)
  APPS_LIST_TOP=$(
    jq -r '
      .[]
      | [.bundle_id? // .bundleID? // "Unknown",
         .name? // .display_name? // "Unknown",
         .version? // "Unknown"]
      | @tsv
    ' "$MVT_MANIFEST_JSON" 2>/dev/null \
    | head -n 30 \
    | awk -F'\t' '{printf("- %s (%s) 版本: %s\n",$2,$1,$3)}'
  )
else
  # 退回到 Applications.plist
  if [[ -f "$BACKUP_APPS_PLIST" ]]; then
    # 转成 JSON 再搞
    APPS_JSON_TMP="$OUT_DIR/_apps_tmp.json"
    plutil -convert json -o "$APPS_JSON_TMP" "$BACKUP_APPS_PLIST" 2>/dev/null || true
    if [[ -f "$APPS_JSON_TMP" ]]; then
      APPS_TOTAL=$(jq 'length' "$APPS_JSON_TMP" 2>/dev/null || echo 0)
      APPS_USER=$(
        jq '[.[] | select(.ApplicationType=="User")] | length' "$APPS_JSON_TMP" 2>/dev/null || echo 0
      )
      APPS_ENTERPRISE=$(
        jq '[.[] | select(.ApplicationType=="System") ] | length' "$APPS_JSON_TMP" 2>/dev/null || echo 0
      )
      APPS_LIST_TOP=$(
        jq -r '
          .[]
          | [.CFBundleIdentifier? // "Unknown",
             .CFBundleDisplayName? // .CFBundleName? // "Unknown",
             .ApplicationType? // "Unknown"]
          | @tsv
        ' "$APPS_JSON_TMP" 2>/dev/null \
        | head -n 30 \
        | awk -F'\t' '{printf("- %s (%s) 类型: %s\n",$2,$1,$3)}'
      )
    fi
  fi
fi

# 6.2 “进程候选”：从 Analytics 中抽可执行名（只是候选，真实进程靠 sysdiagnose）
PROC_CANDIDATES=""
ANALYTICS_JSON="$ANALYSIS_DIR/os_analytics_ad_daily.json"
if [[ -f "$ANALYTICS_JSON" ]]; then
  PROC_CANDIDATES=$(
    jq -r '
      .. | objects | .process? // .proc_name? // .bundle_id? // empty
    ' "$ANALYTICS_JSON" 2>/dev/null \
    | sed '/^$/d' \
    | sort | uniq -c | sort -nr | head -n 20 \
    | awk '{printf("- %s: %s 条记录\n",$2,$1)}'
  )
fi

# 6.3 越狱关键字（备份视角）
JAILBREAK_HINTS=$(
  grep -RIn --binary-files=text -E 'Cydia|Substrate|Sileo|checkra1n|palera1n|chimera|Electra' \
    "$BACKUP_DIR" 2>/dev/null | head -n 50 || true
)

# ---------------- 7. Keychain / 证书相关（基于 Manifest.db + 你已有的 Keychain@iOS 导出） ----------------

KEYCHAIN_PLIST_EXPORTED=""
if [[ -f "$BACKUP_MANIFEST_DB" ]]; then
  KEYCHAIN_PLIST_EXPORTED=$(export_artifact "KeychainDomain" "keychain-backup.plist" "keychain" || echo "")
fi

KEYCHAIN_SUMMARY=""
if [[ -f "$OUT_DIR/Keychain@iOS.json" ]]; then
  KEYCHAIN_SUMMARY=$(
    jq -r '
      .[]?
      | [.Label? // "Unknown", .Account? // .Service? // "Unknown", .Class? // "Unknown"]
      | @tsv
    ' "$OUT_DIR/Keychain@iOS.json" 2>/dev/null \
    | head -n 30 \
    | awk -F'\t' '{printf("- %s / %s  (%s)\n",$1,$2,$3)}'
  )
fi

# ---------------- 8. 生成报告 ----------------

REPORT_MD="$OUT_DIR/backup_report_full.md"
REPORT_DOCX="$OUT_DIR/backup_report_full.docx"

echo "📝 正在生成 backup 报告: $REPORT_MD"

{
  echo "# 📦 iOS 加密备份取证分析报告（Backup 全功能版）"
  echo
  echo "**生成时间：** $(date '+%Y-%m-%d %H:%M:%S')"
  echo "**检测设备：** $DEVICE_NAME"
  echo "**设备型号（ProductType）：** $PRODUCT_TYPE"
  echo "**iOS 版本：** $IOS_VERSION    **Build：** $IOS_BUILD"
  echo "**备份时间：** $BACKUP_DATE"
  echo "**备份加密：** $BACKUP_ENCRYPTED"
  echo "**备份电脑：** $COMPUTER_NAME"
  echo "**MVT 版本：** $MVT_VERSION"
  echo
  echo "## 0. 声明"
  echo "- 本报告基于 **iTunes 加密备份 + mvt-ios check-backup** 解析结果。"
  echo "- 只覆盖备份包含的数据（用户容器/数据库等），**不包含** sysdiagnose 专属的系统日志与守护进程信息。"
  echo "- 建议与 sysdiagnose 报告（v11）结合阅读。"
  echo
  echo "## 1. MVT 任务与 IOC 概况"
  echo "- 加载 IOC：$IOC_TOTAL 条（来自 $IOC_PACKS 个情报集）"
  echo "- 模块“无命中”次数：$NO_DETECTIONS"
  echo "- 模块“无数据可提取”次数：$NO_DATA"
  echo "- 已运行模块："
  if [[ -n "$MODULE_RUNS" ]]; then
    echo "$MODULE_RUNS" | sed 's/^/- /'
  else
    echo "- （command.log 未记录 Running module 行）"
  fi
  echo
  echo "### 1.1 IOC 匹配情况"
  if [[ "$IOC_RESULT" == "DETECTED" ]]; then
    echo "- 存在 IOC 命中，最近 80 条记录："
    echo '```'
    echo "$IOC_HITS"
    echo '```'
  else
    echo "- 未检测到 IOC 命中。"
    echo "> 说明：IOC 命中高度依赖情报集与样本交集，未命中不等于“绝对安全”。"
  fi
  echo
  echo "## 2. 配置项 / TCC / 描述文件视角"
  echo "- TCC 条目总数：$TCC_TOTAL"
  echo "- 涉及敏感权限（摄像头/麦克风/定位等）的条目数：$TCC_SENSITIVE"
  echo "### 2.1 TCC 权限集中在的 App"
  if [[ -n "$TCC_TOP_APPS" ]]; then
    echo "$TCC_TOP_APPS"
  else
    echo "- 未获取到 TCC 详细数据（可能模块未输出 tcc.json）。"
  fi
  echo
  echo "### 2.2 可疑配置键（来自 global_preferences.json）"
  if [[ -n "$CFG_FLAGS" ]]; then
    echo "$CFG_FLAGS"
  else
    echo "- 暂未发现明显与 Analytics/MDM/Profile 相关的配置记录，或模块未输出。"
  fi
  echo
  echo "## 3. 浏览器与网络行为"
  echo "### 3.1 Safari 历史中最常访问域名"
  if [[ -n "$SAFARI_TOP_DOMAINS" ]]; then
    echo "$SAFARI_TOP_DOMAINS"
  else
    echo "- 未发现可解析的 Safari 历史数据。"
  fi
  echo
  echo "### 3.2 WebKit 资源加载统计（近似第三方域名活跃度）"
  if [[ -n "$WEBKIT_TOP_THIRD" ]]; then
    echo "$WEBKIT_TOP_THIRD"
  else
    echo "- 未发现 WebKit 资源统计数据。"
  fi
  echo
  echo "## 4. 通讯录 / 短信 / 通话"
  echo "- 通讯录联系人数量：$CONTACTS_COUNT"
  echo "- 短信会话条目数：$SMS_COUNT"
  echo "- 通话记录条目数：$CALLS_COUNT"
  echo
  echo "### 4.1 最近 20 条通话记录（时间 -> 号码）"
  if [[ -n "$RECENT_CALLS" ]]; then
    echo "$RECENT_CALLS"
  else
    echo "- 无通话记录或模块未输出 calls.json。"
  fi
  echo
  echo "## 5. 应用清单与进程候选"
  echo "- 备份中观测到的应用条目：$APPS_TOTAL"
  if [[ "$APPS_USER" != "0" || "$APPS_ENTERPRISE" != "0" ]]; then
    echo "- 其中 User 类型：$APPS_USER, System 类型：$APPS_ENTERPRISE"
  fi
  echo
  echo "### 5.1 应用概览（最多列出 30 个）"
  if [[ -n "$APPS_LIST_TOP" ]]; then
    echo "$APPS_LIST_TOP"
  else
    echo "- 未能解析应用清单（Applications.plist 或 manifest.json 结构需根据实际调整）。"
  fi
  echo
  echo "### 5.2 进程候选（来自 Analytics 日志，仅供参考）"
  if [[ -n "$PROC_CANDIDATES" ]]; then
    echo "$PROC_CANDIDATES"
    echo
    echo "> 说明：这些名称来自 Analytics / Crash 日志，不一定代表当前仍在运行的进程。"
  else
    echo "- 未从 Analytics 中解析到可用的进程名信息。"
  fi
  echo
  echo "### 5.3 越狱关键字（备份文件内检索结果，最多 50 条）"
  if [[ -n "$JAILBREAK_HINTS" ]]; then
    echo '```'
    echo "$JAILBREAK_HINTS"
    echo '```'
    echo "> 说明：关键字命中仅代表出现相关字符串，需结合 sysdiagnose 报告确认越狱状态。"
  else
    echo "- 未在备份文件中检索到典型越狱关键字。"
  fi
  echo
  echo "## 6. Keychain / 证书相关"
  echo "- Manifest.db 中 KeychainDomain/keychain-backup.plist 导出路径："
  if [[ -n "$KEYCHAIN_PLIST_EXPORTED" ]]; then
    echo "  - $KEYCHAIN_PLIST_EXPORTED"
  else
    echo "  - 未在 Manifest.db 中找到 keychain-backup.plist 对应记录，或源文件缺失。"
  fi
  echo
  echo "### 6.1 Keychain 条目概览（如存在 Keychain@iOS.json）"
  if [[ -n "$KEYCHAIN_SUMMARY" ]]; then
    echo "$KEYCHAIN_SUMMARY"
    echo
    echo "> 说明：Keychain 解析依赖额外工具，你当前提供的 Keychain@iOS.json 已用作简单汇总。"
  else
    echo "- 未提供 Keychain@iOS.json，或结构需按实际导出格式调整 jq 表达式。"
  fi
  echo
  echo "## 7. 能力矩阵对应关系（仅备份侧）"
  echo "- (3) 配置项 / 描述文件：依赖 global_preferences.json / tcc.json / backup_info.json；本报告中已给出敏感权限和可疑配置键。"
  echo "- (4) 证书 / Keychain：通过 Manifest.db 定位 keychain-backup.plist，并对 Keychain 导出文件做摘要。"
  echo "- (5) 进程信息：通过 Analytics 中的进程名候选做近似，真正完整进程列表仍需 sysdiagnose 支持。"
  echo "- (6) 应用清单：通过 Applications.plist/mvt manifest.json 解析应用名 / Bundle ID / 类型。"
  echo "- (7) 越狱插件：通过备份内关键字进行弱检测，强检测依赖 sysdiagnose filesystem 对比（v11 已实现）。"
  echo "- (8) 系统分区新增文件：主要由 sysdiagnose 侧负责，备份仅能展示用户域异常路径。"
  echo "- (9) 报告导出：当前脚本导出 Markdown + 可选 Word 报告，并支持 artifacts 目录导出可疑文件。"
  echo "- (10) 自定义规则 / IOC：IOC 由 mvt 提供，自定义规则可通过你额外维护的 grep / jq 脚本挂接在本工具链之上。"
  echo
  echo "## 8. 结论与后续分析建议"
  echo "- 将本备份报告与同设备的 sysdiagnose 报告（v11）合并，可以覆盖设备配置、日志、进程、系统分区、用户数据等多个维度。"
  echo "- 若需进一步验证特定威胁，可针对本报告中导出的 artifacts（如 keychain-backup.plist、可疑 App 沙盒）使用专门工具做深度逆向与流量重放。"
  echo
  echo "**报告生成时间：** $(date '+%Y-%m-%d %H:%M:%S')"
} > "$REPORT_MD"

# ---------------- 转 DOCX ----------------
if command -v pandoc >/dev/null 2>&1; then
  echo "📄 正在转换为 Word 文档..."
  pandoc "$REPORT_MD" -o "$REPORT_DOCX"
  echo "✅ Word 报告已生成：$REPORT_DOCX"
else
  echo "⚠️ 未检测到 pandoc，仅生成 Markdown：$REPORT_MD"
fi

echo "📦 所有输出文件已保存于：$OUT_DIR"
