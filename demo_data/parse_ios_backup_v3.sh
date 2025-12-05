#!/bin/zsh
# ======================================================================
# iOS Backup 自动分析脚本 v3.1
# - 自动读取密码（支持 Password.txt）
# - 解密 + check-backup
# - 生成 markdown/word 报告
# - 输出目录结构清晰
# ======================================================================

set -euo pipefail
export LC_ALL=C
trap 'echo "❌ Error at line $LINENO"; exit 1' ERR

# ---------------- 参数 ----------------
if [[ $# -lt 2 ]]; then
  echo "用法: $0 <BACKUP_DIR> <OUT_DIR>"
  exit 1
fi

BACKUP_DIR="$1"
OUT_DIR="$2"

[[ -d "$BACKUP_DIR" ]] || { echo "❌ 备份目录不存在: $BACKUP_DIR"; exit 1; }
mkdir -p "$OUT_DIR"

echo "📂 备份目录: $BACKUP_DIR"
echo "📁 输出目录: $OUT_DIR"
echo ""

# ---------------- 自动读取密码（新增） ----------------
BACKUP_PASS=""
PASS_FILE="$BACKUP_DIR/Password.txt"

if [[ -f "$PASS_FILE" ]]; then
  echo "🔍 检测到 Password.txt，尝试读取密码..."
  BACKUP_PASS="$(cat "$PASS_FILE" | head -n1 | tr -d '\r\n')"

  if [[ -n "$BACKUP_PASS" ]]; then
    echo "🔐 成功从 Password.txt 获取备份密码"
  else
    echo "⚠️ Password.txt 内容为空，将继续询问密码"
    BACKUP_PASS=""
  fi
fi

# ---------------- 若未从 Password.txt 获取密码，则询问 ----------------
if [[ -z "$BACKUP_PASS" ]]; then
  printf "🔐 若为加密备份，请输入密码（留空则跳过）: "
  stty -echo
  read BACKUP_PASS
  stty echo
  echo ""
fi

# ---------------- Decrypt or Direct Check ----------------
DECRYPT_DIR="$OUT_DIR/decrypted_backup"

if [[ -n "$BACKUP_PASS" ]]; then
  echo "🔓 使用密码解密备份..."
  mkdir -p "$DECRYPT_DIR"

  mvt-ios decrypt-backup \
      -p "$BACKUP_PASS" \
      -d "$DECRYPT_DIR" \
      "$BACKUP_DIR"

  echo "🔍 开始运行 check-backup（基于解密后的数据）..."
  mvt-ios check-backup "$DECRYPT_DIR" -o "$OUT_DIR"

else
  echo "ℹ️ 未提供密码 → 直接使用 mvt-ios check-backup"
  mvt-ios check-backup "$BACKUP_DIR" -o "$OUT_DIR"
fi

echo "⏳ 写盘同步..."
sleep 2
sync || true

# ---------------- 基础文件 ----------------
INFO_JSON="$OUT_DIR/info.json"
COMMAND_LOG="$OUT_DIR/command.log"
BACKUP_INFO="$OUT_DIR/backup_info.json"
REPORT_MD="$OUT_DIR/backup_report.md"
REPORT_DOCX="$OUT_DIR/backup_report.docx"

# ---------------- 生成 summary 报告 ----------------
echo "📝 正在生成分析报告..."

{
  echo "# 📱 iOS 加密备份安全分析报告"
  echo
  echo "**生成时间：** $(date '+%Y-%m-%d %H:%M:%S')"
  echo "**备份目录：** $BACKUP_DIR"
  echo

  echo "## 1. 基础信息"
  if [[ -f "$BACKUP_INFO" ]]; then
    DEVICE_NAME=$(jq -r '.DeviceName // "Unknown"' "$BACKUP_INFO")
    IOS_VERSION=$(jq -r '.ProductVersion // "Unknown"' "$BACKUP_INFO")
    BUILD=$(jq -r '.BuildVersion // "Unknown"' "$BACKUP_INFO")
    SERIAL=$(jq -r '.SerialNumber // "Unknown"' "$BACKUP_INFO")

    echo "- 设备名称：$DEVICE_NAME"
    echo "- iOS 版本：$IOS_VERSION"
    echo "- Build 号：$BUILD"
    echo "- 序列号：$SERIAL"
  else
    echo "- 未找到 backup_info.json"
  fi
  echo

  echo "## 2. 解析任务与 IOC 结果"
  echo
  if [[ -f "$COMMAND_LOG" ]]; then
    echo '````'
    tail -n 200 "$COMMAND_LOG"
    echo '````'
  else
    echo "- 未找到 command.log"
  fi
  echo

  echo "## 3. 应用列表（来自 Manifest 与 MVT）"
  if [[ -f "$OUT_DIR"/*apps.json ]]; then
    APP_FILE=$(ls "$OUT_DIR"/*apps.json | head -n1)
    echo "- 应用数量：$(jq length "$APP_FILE")"
  else
    echo "- 无应用信息"
  fi
  echo

  echo "## 4. 描述文件 / 配置项"
  if [[ -f "$OUT_DIR"/*profiles.json ]]; then
    PROFILE_FILE=$(ls "$OUT_DIR"/*profiles.json | head -n1)
    echo "- 描述文件数量：$(jq length "$PROFILE_FILE")"
  else
    echo "- 无描述文件数据"
  fi
  echo

  echo "## 5. 证书信息"
  if [[ -f "$OUT_DIR"/*keychain.json ]]; then
    CERT_FILE=$(ls "$OUT_DIR"/*keychain.json | head -n1)
    echo "- 证书数量：$(jq length "$CERT_FILE")"
  else
    echo "- 无证书数据"
  fi
  echo

  echo "## 6. 浏览器历史 / Safari 数据"
  SAFARI_HISTORY="$OUT_DIR/safari_history.json"
  if [[ -f "$SAFARI_HISTORY" ]]; then
    echo "- Safari 历史条目数：$(jq length "$SAFARI_HISTORY")"
  else
    echo "- 无 Safari 历史记录"
  fi
  echo

  echo "## 7. 结论"
  echo "- 如需 IOC 命中分析，可使用 output 中的 timeline_detected.csv"
  echo "- 若需与 sysdiagnose 联合分析，可和 v11 脚本结合使用"
  echo

} > "$REPORT_MD"

# ---------------- Word 文档输出 ----------------
if command -v pandoc >/dev/null 2>&1; then
  pandoc "$REPORT_MD" -o "$REPORT_DOCX"
  echo "📄 Word 报告已生成：$REPORT_DOCX"
else
  echo "⚠️ pandoc 不存在，仅生成 Markdown 文件：$REPORT_MD"
fi

echo "🎉 分析完成！所有文件已输出到：$OUT_DIR"
