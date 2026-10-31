#!/bin/bash
# ═══════════════════════════════════════════════════════════════
# H3C BIOS 密码爆破 — 全字符集分阶段测试脚本
#
# 用法:
#   ./run_brute.sh              # 从第1阶段开始, 依次跑到结束或命中
#   ./run_brute.sh 5            # 只跑第5阶段
#   ./run_brute.sh 3 8          # 跑第3~8阶段
#   ./run_brute.sh list         # 列出所有阶段
#   ./run_brute.sh status       # 查看是否已命中
#
# 多服务器协同: 给每台分配不同阶段范围, 例如:
#   服务器A: ./run_brute.sh 1 7
#   服务器B: ./run_brute.sh 8 14
#   服务器C: ./run_brute.sh 15 20
#
# 命中后自动停止, 密码写入 passd.txt
# ═══════════════════════════════════════════════════════════════

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$SCRIPT_DIR"

BINARY="./go-brute"
PASSD="passd.txt"
LOG="brute.log"

# ─── 字符集定义 ───────────────────────────────────────────────
DIGITS="0123456789"
LOWER="abcdefghijklmnopqrstuvwxyz"
UPPER="ABCDEFGHIJKLMNOPQRSTUVWXYZ"
LOWER_DIGIT="${LOWER}${DIGITS}"
UPPER_DIGIT="${UPPER}${DIGITS}"
ALNUM="${LOWER}${UPPER}${DIGITS}"
# 常见键盘特殊字符
SPECIAL_COMMON='!@#$%^&*()-_=+'
ALNUM_SPECIAL="${ALNUM}${SPECIAL_COMMON}"
# 扩展特殊字符 (含方括号、花括号、分号等)
SPECIAL_FULL='!@#$%^&*()-_=+[]{}|;:,.<>?/~'
PRINTABLE="${ALNUM}${SPECIAL_FULL}"
# 纯特殊字符 (不含字母数字)
SPECIAL_ONLY='!@#$%^&*()-_=+'

# ─── 阶段定义 ─────────────────────────────────────────────────
# 格式: "编号|描述|字符集|最小长度|最大长度|编码"
# 编码: both = UTF-16LE + Latin-1 都试; utf16le = 只试UTF-16LE
PHASES=(
  # ── 快速阶段: 最常见的密码模式 ──
  "1|字典(内置常见密码)|-|-|-|dict"
  "2|纯数字3-10|${DIGITS}|3|10|both"
  "3|小写字母3-8|${LOWER}|3|8|both"
  "4|大写字母3-8|${UPPER}|3|8|both"
  "5|小写+数字3-7|${LOWER_DIGIT}|3|7|both"
  "6|大写+数字3-7|${UPPER_DIGIT}|3|7|both"
  "7|大小写+数字3-6|${ALNUM}|3|6|both"
  "8|字母数字+常见特殊3-5|${ALNUM_SPECIAL}|3|5|both"

  # ── 扩展阶段: 更长密码 ──
  "9|纯数字11-12|${DIGITS}|11|12|both"
  "10|小写字母9|${LOWER}|9|9|both"
  "11|大写字母9|${UPPER}|9|9|both"
  "12|小写+数字8|${LOWER_DIGIT}|8|8|both"
  "13|大写+数字8|${UPPER_DIGIT}|8|8|both"
  "14|大小写+数字7|${ALNUM}|7|7|both"
  "15|字母数字+常见特殊6|${ALNUM_SPECIAL}|6|6|both"

  # ── 深度扩展阶段 ──
  "16|纯数字13-14|${DIGITS}|13|14|both"
  "17|小写字母10|${LOWER}|10|10|both"
  "18|大写字母10|${UPPER}|10|10|both"
  "19|小写+数字9|${LOWER_DIGIT}|9|9|both"
  "20|大小写+数字8|${ALNUM}|8|8|both"
  "21|字母数字+常见特殊7|${ALNUM_SPECIAL}|7|7|both"
  "22|全可打印字符3-6|${PRINTABLE}|3|6|both"

  # ── 极限阶段 (非常耗时) ──
  "23|纯数字15-16|${DIGITS}|15|16|both"
  "24|小写字母11|${LOWER}|11|11|both"
  "25|小写+数字10|${LOWER_DIGIT}|10|10|both"
  "26|大小写+数字9|${ALNUM}|9|9|both"
  "27|字母数字+常见特殊8|${ALNUM_SPECIAL}|8|8|both"
  "28|全可打印字符7|${PRINTABLE}|7|7|both"

  # ── 超长/纯特殊字符 ──
  "29|纯特殊字符3-8|${SPECIAL_ONLY}|3|8|both"
  "30|小写字母12|${LOWER}|12|12|both"
  "31|小写+数字11-12|${LOWER_DIGIT}|11|12|both"
  "32|大小写+数字10|${ALNUM}|10|10|both"
  "33|全可打印字符8|${PRINTABLE}|8|8|both"
)

# ─── 辅助函数 ─────────────────────────────────────────────────

check_hit() {
    if [ -f "$PASSD" ]; then
        echo ""
        echo "══════════════════════════════════════════════════"
        echo "  ★★★ 密码已找到! ★★★"
        echo "══════════════════════════════════════════════════"
        echo "  密码: $(cat "$PASSD")"
        echo "  文件: $(pwd)/$PASSD"
        echo "══════════════════════════════════════════════════"
        return 0
    fi
    return 1
}

run_phase() {
    local phase_str="$1"
    IFS='|' read -r num desc charset minlen maxlen enc <<< "$phase_str"

    echo ""
    echo "──────────────────────────────────────────────────────"
    echo "  阶段 ${num}: ${desc}"
    echo "  时间: $(date '+%Y-%m-%d %H:%M:%S')"
    echo "──────────────────────────────────────────────────────"

    if [ "$enc" = "dict" ]; then
        "$BINARY" -dict 2>&1 | tee -a "$LOG"
    else
        echo "  字符集(${#charset}字符) 长度${minlen}-${maxlen} 编码=${enc}" | tee -a "$LOG"
        "$BINARY" -charset "$charset" -min "$minlen" -max "$maxlen" -enc "$enc" 2>&1 | tee -a "$LOG"
    fi

    return 0
}

list_phases() {
    echo "══════════════════════════════════════════════════════════════"
    echo "  全部爆破阶段列表"
    echo "══════════════════════════════════════════════════════════════"
    printf "%-5s %-40s %-8s %-10s %s\n" "编号" "描述" "长度" "字符数" "编码"
    echo "──────────────────────────────────────────────────────────────"
    for phase in "${PHASES[@]}"; do
        IFS='|' read -r num desc charset minlen maxlen enc <<< "$phase"
        if [ "$enc" = "dict" ]; then
            printf "%-5s %-40s %-8s %-10s %s\n" "$num" "$desc" "-" "-" "dict"
        else
            local cslen=${#charset}
            printf "%-5s %-40s %-8s %-10s %s\n" "$num" "$desc" "${minlen}-${maxlen}" "$cslen" "$enc"
        fi
    done
    echo "══════════════════════════════════════════════════════════════"
    echo ""
    echo "用法:"
    echo "  ./run_brute.sh            # 跑全部阶段"
    echo "  ./run_brute.sh 5          # 只跑第5阶段"
    echo "  ./run_brute.sh 3 8        # 跑第3~8阶段"
    echo "  ./run_brute.sh list       # 列出阶段"
    echo "  ./run_brute.sh status     # 查看命中状态"
    echo ""
    echo "多服务器分配示例:"
    echo "  服务器A: ./run_brute.sh 1 10"
    echo "  服务器B: ./run_brute.sh 11 20"
    echo "  服务器C: ./run_brute.sh 21 30"
}

show_status() {
    if check_hit; then
        return 0
    fi
    echo "尚未命中。"
    if [ -f "$LOG" ]; then
        echo ""
        echo "最近日志:"
        tail -5 "$LOG"
    fi
}

# ─── 主逻辑 ───────────────────────────────────────────────────

# 确保二进制存在
if [ ! -x "$BINARY" ]; then
    echo "错误: 找不到可执行文件 $BINARY"
    echo "请先编译: go build -o go-brute ."
    exit 1
fi

# 处理命令行参数
case "${1:-all}" in
    list)
        list_phases
        exit 0
        ;;
    status)
        show_status
        exit 0
        ;;
    all|"")
        FROM=1
        TO=${#PHASES[@]}
        ;;
    *)
        if [[ "$1" =~ ^[0-9]+$ ]]; then
            FROM=$1
            if [ -n "${2:-}" ] && [[ "$2" =~ ^[0-9]+$ ]]; then
                TO=$2
            else
                TO=$1
            fi
        else
            echo "错误: 无效参数 '$1'"
            echo "用法: $0 [阶段号|起始 终止|list|status]"
            exit 1
        fi
        ;;
esac

# 启动
echo "══════════════════════════════════════════════════════════════"
echo "  H3C BIOS 密码爆破 — 全阶段测试"
echo "  阶段范围: ${FROM} ~ ${TO}"
echo "  开始时间: $(date '+%Y-%m-%d %H:%M:%S')"
echo "  工作目录: $(pwd)"
echo "  日志文件: $(pwd)/$LOG"
echo "══════════════════════════════════════════════════════════════"

# 如果日志已存在, 追加分隔线
if [ -f "$LOG" ]; then
    echo "" >> "$LOG"
    echo "══════════════════════════════════════════════════" >> "$LOG"
    echo "  新一轮爆破 $(date '+%Y-%m-%d %H:%M:%S') 阶段${FROM}-${TO}" >> "$LOG"
    echo "══════════════════════════════════════════════════" >> "$LOG"
else
    echo "H3C BIOS 密码爆破日志 — $(date '+%Y-%m-%d %H:%M:%S')" > "$LOG"
fi

# 依次执行阶段
TOTAL_START=$(date +%s)

for phase in "${PHASES[@]}"; do
    IFS='|' read -r num desc charset minlen maxlen enc <<< "$phase"

    # 跳过不在范围内的阶段
    if [ "$num" -lt "$FROM" ] || [ "$num" -gt "$TO" ]; then
        continue
    fi

    # 每个阶段开始前检查是否已命中
    if check_hit; then
        exit 0
    fi

    # 记录阶段开始
    PHASE_START=$(date +%s)
    echo "" | tee -a "$LOG"
    echo "[阶段${num}] ${desc} — $(date '+%H:%M:%S')" | tee -a "$LOG"

    # 执行阶段
    if [ "$enc" = "dict" ]; then
        "$BINARY" -dict 2>&1 | tee -a "$LOG"
    else
        echo "  字符集(${#charset}字符) 长度${minlen}-${maxlen} 编码=${enc}" | tee -a "$LOG"
        "$BINARY" -charset "$charset" -min "$minlen" -max "$maxlen" -enc "$enc" 2>&1 | tee -a "$LOG"
    fi

    # 检查命中
    if check_hit; then
        PHASE_END=$(date +%s)
        TOTAL_END=$(date +%s)
        echo "本阶段用时: $((PHASE_END - PHASE_START))s" | tee -a "$LOG"
        echo "总用时: $((TOTAL_END - TOTAL_START))s" | tee -a "$LOG"
        exit 0
    fi

    PHASE_END=$(date +%s)
    echo "[阶段${num}] 完成, 用时 $((PHASE_END - PHASE_START))s, 未命中" | tee -a "$LOG"
done

# 全部跑完未命中
TOTAL_END=$(date +%s)
echo ""
echo "══════════════════════════════════════════════════════════════"
echo "  阶段 ${FROM}~${TO} 全部完成, 未命中。"
echo "  总用时: $((TOTAL_END - TOTAL_START))s"
echo "  结束时间: $(date '+%Y-%m-%d %H:%M:%S')"
echo "══════════════════════════════════════════════════════════════"
echo ""
echo "建议:"
echo "  1. 尝试更长密码 (当前最大到12位字母)"
echo "  2. 使用 GPU + hashcat 加速"
echo "  3. 检查密码是否包含中文或其他Unicode字符"
echo "  4. 考虑固件级绕过 (清除CMOS/刷写SPI芯片)"
