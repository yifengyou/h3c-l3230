package main

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"flag"
	"fmt"
	"math"
	"os"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// ─── 目标哈希 ───────────────────────────────────────────────

// targetHex 是从固件 AMITSESetup 变量中提取的 Administrator 密码 SHA-256 哈希。
const targetHex = "e089d77a47c87ec220637f23258723ebafd3a21cb5b61082852c2e00ab6d1da0"

// ─── 算法说明 ───────────────────────────────────────────────

// 算法 (经 447A1B58 模块反汇编逐指令确认):
//   1. 密码以指定编码(UTF-16LE 或 Latin-1/ASCII)转为字节
//   2. 用 0x00 填充到 40 字节 (0x28)
//   3. 对 40 字节做单次 SHA-256
//   4. 取 32 字节摘要与目标比对
//   无 salt、无迭代、无 HMAC —— 纯单次 SHA-256
//
// 密码长度: 3 ~ 20 字符 (UTF-16 字节 6~40, Latin-1 字节 3~20)

// ─── 配置 ───────────────────────────────────────────────────

const bufLen = 40 // AMITSE 密码缓冲区固定 40 字节

// Config 持有爆破任务的所有可配置参数。
type Config struct {
	Charset  string // 候选字符集
	MinLen   int    // 最小密码长度
	MaxLen   int    // 最大密码长度
	Encoding string // "utf16le" 或 "latin1" 或 "both"
	Workers  int    // 并行 worker 数 (goroutine)
	Chunk    uint64 // 每个 task chunk 的候选数
}

// defaultConfig 返回合理默认值。
func defaultConfig() Config {
	return Config{
		Charset:  "0123456789",
		MinLen:   3,
		MaxLen:   10,
		Encoding: "both",
		Workers:  runtime.NumCPU(),
		Chunk:    200_000,
	}
}

// ─── 编码表 ─────────────────────────────────────────────────

// encUnit 是单个字符在某种编码下的字节序列。
// UTF-16LE: 2 字节; Latin-1: 1 字节。
type encUnit []byte

// buildTable 为字符集中每个字符预计算编码后的字节单元。
func buildTable(charset, encoding string) []encUnit {
	table := make([]encUnit, len(charset))
	for i, c := range charset {
		switch encoding {
		case "utf16le":
			b := make([]byte, 2)
			binary.LittleEndian.PutUint16(b, uint16(c))
			table[i] = encUnit(b)
		case "latin1":
			// Latin-1 仅支持 U+0000~U+00FF; 超出范围的字符用 0x3F('?')替代
			if c > 0xFF {
				table[i] = encUnit{0x3F}
			} else {
				table[i] = encUnit{byte(c)}
			}
		default:
			panic("unknown encoding: " + encoding)
		}
	}
	return table
}

// unitSize 返回每个编码单元的字节数。
func unitSize(encoding string) int {
	if encoding == "utf16le" {
		return 2
	}
	return 1
}

// ─── 候选生成 + 哈希 ────────────────────────────────────────

// hashCandidate 将一个候选密码(以字符索引数组表示)编码、填充、哈希，返回摘要。
func hashCandidate(table []encUnit, idx []int, unitSz int) [32]byte {
	var buf [bufLen]byte
	pos := 0
	for _, i := range idx {
		u := table[i]
		copy(buf[pos:], u)
		pos += len(u)
	}
	// pos 之后已经是零 (Go 数组零值), 无需显式填充
	return sha256.Sum256(buf[:])
}

// indexToPassword 将字符索引数组还原为密码字符串。
func indexToPassword(charset string, idx []int) string {
	var sb strings.Builder
	sb.Grow(len(idx))
	for _, i := range idx {
		sb.WriteRune([]rune(charset)[i])
	}
	return sb.String()
}

// ─── 任务分片 ───────────────────────────────────────────────

// Task 描述一个工作区间: 对长度 L 的字符空间, 处理 [Start, End) 范围。
type Task struct {
	L     int
	Start uint64
	End   uint64
}

// generateTasks 为所有长度生成 task 列表, 每个 task 包含至多 chunk 个候选。
func generateTasks(cfg Config) []Task {
	n := len(cfg.Charset)
	var tasks []Task
	for L := cfg.MinLen; L <= cfg.MaxLen; L++ {
		total := powU64(uint64(n), uint64(L))
		for s := uint64(0); s < total; s += cfg.Chunk {
			e := s + cfg.Chunk
			if e > total {
				e = total
			}
			tasks = append(tasks, Task{L: L, Start: s, End: e})
		}
	}
	return tasks
}

// powU64 计算 base^exp, 溢出时返回 math.MaxUint64。
func powU64(base, exp uint64) uint64 {
	if exp == 0 {
		return 1
	}
	result := uint64(1)
	for i := uint64(0); i < exp; i++ {
		if result > math.MaxUint64/base {
			return math.MaxUint64
		}
		result *= base
	}
	return result
}

// ─── Worker ────────────────────────────────────────────────

// runTask 处理一个 Task: 在 [Start, End) 范围内枚举所有候选, 哈希并比对。
// 命中时通过 found channel 返回结果。
func runTask(task Task, charset, encoding string, table []encUnit, unitSz int, target [32]byte,
	found chan<- Result, hitFlag *int32, counter *uint64) {

	if atomic.LoadInt32(hitFlag) == 1 {
		return
	}

	n := len(table)
	idx := make([]int, task.L)

	// 将 Start 转为 n 进制索引数组
	x := task.Start
	for i := task.L - 1; i >= 0; i-- {
		idx[i] = int(x % uint64(n))
		x /= uint64(n)
	}

	var localCount uint64
	for c := task.Start; c < task.End; c++ {
		if localCount&0x3FFFF == 0 && atomic.LoadInt32(hitFlag) == 1 {
			return
		}
		digest := hashCandidate(table, idx, unitSz)
		if digest == target {
			pw := indexToPassword(charset, idx)
			atomic.StoreInt32(hitFlag, 1)
			found <- Result{Password: pw, Encoding: encoding}
			atomic.AddUint64(counter, localCount+1)
			return
		}
		localCount++

		// n 进制递增
		k := task.L - 1
		for k >= 0 {
			idx[k]++
			if idx[k] < n {
				break
			}
			idx[k] = 0
			k--
		}
	}
	atomic.AddUint64(counter, localCount)
}

// Result 持有命中结果。
type Result struct {
	Password string
	Encoding string
}

// ─── 主爆破流程 ─────────────────────────────────────────────

// Brute 执行完整爆破流程, 使用给定编码。命中返回 Result, 否则返回空。
func Brute(cfg Config, encoding string, target [32]byte) *Result {
	table := buildTable(cfg.Charset, encoding)
	unitSz := unitSize(encoding)
	tasks := generateTasks(cfg)

	totalCandidates := uint64(0)
	for _, t := range tasks {
		totalCandidates += t.End - t.Start
	}

	fmt.Printf("[%s] 字符集=%q(%d) 长度%d-%d 总候选=%s 线程=%d\n",
		encoding, cfg.Charset, len(cfg.Charset), cfg.MinLen, cfg.MaxLen,
		formatNum(totalCandidates), cfg.Workers)

	var hitFlag int32
	var counter uint64
	found := make(chan Result, 1)

	// 进度报告 goroutine
	done := make(chan struct{})
	go func() {
		ticker := time.NewTicker(5 * time.Second)
		defer ticker.Stop()
		start := time.Now()
		for {
			select {
			case <-ticker.C:
				if atomic.LoadInt32(&hitFlag) == 1 {
					return
				}
				done2 := atomic.LoadUint64(&counter)
				elapsed := time.Since(start).Seconds()
				rate := float64(done2) / elapsed
				pct := float64(done2) / float64(totalCandidates) * 100
				eta := ""
				if rate > 0 {
					etaSec := float64(totalCandidates-done2) / rate
					eta = fmt.Sprintf("ETA %s", formatDuration(etaSec))
				}
				fmt.Printf("  [%s] %.2f%% | %s | %s h/s | %s\n",
					encoding, pct, formatNum(done2), formatNum(uint64(rate)), eta)
			case <-done:
				return
			}
		}
	}()

	// 并发执行 tasks
	var wg sync.WaitGroup
	sem := make(chan struct{}, cfg.Workers)
	for _, task := range tasks {
		if atomic.LoadInt32(&hitFlag) == 1 {
			break
		}
		wg.Add(1)
		sem <- struct{}{}
		go func(t Task) {
			defer wg.Done()
			defer func() { <-sem }()
			runTask(t, cfg.Charset, encoding, table, unitSz, target, found, &hitFlag, &counter)
		}(task)
	}

	// 等待完成或命中
	go func() {
		wg.Wait()
		close(found)
	}()

	var result *Result
	for r := range found {
		result = &r
		break
	}
	close(done)
	wg.Wait()

	elapsed := time.Since(time.Now()) // placeholder; actual elapsed tracked by caller
	_ = elapsed
	fmt.Printf("[%s] 完成\n", encoding)
	return result
}

// ─── 字典攻击 ───────────────────────────────────────────────

// dictionaryCandidates 返回内置的常见密码字典。
func dictionaryCandidates() []string {
	return []string{
		// H3C / 新华三 / 机型
		"h3c", "H3C", "H3c", "NewH3C", "NEWH3C", "newh3c", "h3ctech", "H3CTech",
		"h3cgroup", "h3c123", "H3C123", "h3c@123", "h3c@h3c", "h3c1234", "h3c12345",
		"h3c123456", "h3c12345678", "h3cadmin", "H3CADMIN", "H3CAdmin", "h3cbios",
		"H3CBIOS", "h3csetup", "h3cpassword", "H3Cpassword", "h3c@2023", "h3c@2024",
		"n5105", "N5105", "n5100", "N5100", "n5095", "N5095", "h3cn5105", "H3CN5105",
		"H3cN5105", "n5105h3c", "N5105H3C", "book", "Book", "BOOK", "h3cbook",
		"H3CBook", "h3cbookpro", "magicbook", "MagicBook", "Magicbook",
		"h3cmagicbook", "H3CMagicBook", "probook", "ProBook", "ultrabook", "UltraBook",
		"notebook", "Notebook", "tsinghua", "Tsinghua", "TSINGHUA", "tsinghuaunis",
		"TsinghuaUnis", "unis", "UNIS", "Unis", "unisplendour", "Unisplendour",
		"tongfang", "Tongfang", "TONGFANG", "TongFang", "h3c!@#", "H3C!@#",
		"h3c!@#$", "H3C!@#$", "h3c123!", "H3C123!", "h3c2023", "H3C2023",
		// 常见默认密码
		"admin", "Admin", "ADMIN", "administrator", "Administrator", "password",
		"Password", "PASSWORD", "passw0rd", "P@ssw0rd", "123456", "12345678",
		"123456789", "1234567890", "000000", "111111", "888888", "666666", "999999",
		"123123", "112233", "123321", "654321", "0000", "1111", "8888", "abc123",
		"ABC123", "qwerty", "Qwerty", "QWERTY", "bios", "BIOS", "Bios", "setup",
		"Setup", "SETUP", "cmos", "CMOS", "clear", "Clear", "super", "Super",
		"phoenix", "Phoenix", "PHOENIX", "insyde", "Insyde", "ami", "AMI", "Ami",
		"apto", "aptio", "Aptio", "lenovo", "Lenovo", "LENOVO", "thinkpad",
		"ThinkPad", "haier", "Haier", "HAIER", "boe", "BOE", "Boe", "intel",
		"Intel", "INTEL", "celeron", "Celeron", "jasper", "Jasper", "jasperlake",
		"JasperLake", "jsl", "JSL", "mrd", "MRD",
		// 年份
		"2020", "2021", "2022", "2023", "2024", "2025", "2026", "admin2023",
		"Admin2023",
		// SMBIOS 序列号/UUID 派生
		"219801A5NG5238BKX056", "219801a5ng5238bkx056", "219801A5NG5238BKX0",
		"NG5238BKX056", "219801A5", "219801", "BKX056", "NG5238", "A5NG5238",
		"119005663083002", "11900566308300", "119005663",
		"eb8fab80-34cf-11ee-8479-bcc03a387400", "eb8fab8034cf11ee8479bcc03a387400",
		"EB8FAB8034CF11EE8479BCC03A387400", "eb8fab80", "34cf11ee", "8479bcc0",
		"3a387400",
	}
}

// tryDictionary 用内置字典尝试, 两种编码都试。命中返回结果。
func tryDictionary(target [32]byte) *Result {
	cands := dictionaryCandidates()
	fmt.Printf("[字典] %d 候选\n", len(cands))
	for _, pw := range cands {
		for _, enc := range []string{"utf16le", "latin1"} {
			// 把字符串当字符集, 每个"字符"就是密码本身的一个 char
			// 但这里 pw 是完整密码, 不是单字符; 直接编码整个字符串
			if r := hashFullString(pw, enc, target); r != nil {
				return r
			}
		}
	}
	fmt.Println("[字典] 未命中")
	return nil
}

// hashFullString 对完整密码字符串做编码+填充+SHA-256, 命中返回 Result。
func hashFullString(pw, encoding string, target [32]byte) *Result {
	var encoded []byte
	switch encoding {
	case "utf16le":
		for _, r := range pw {
			b := make([]byte, 2)
			binary.LittleEndian.PutUint16(b, uint16(r))
			encoded = append(encoded, b...)
		}
	case "latin1":
		for _, r := range pw {
			if r > 0xFF {
				encoded = append(encoded, 0x3F)
			} else {
				encoded = append(encoded, byte(r))
			}
		}
	}
	if len(encoded) < 6 || len(encoded) > 40 {
		return nil
	}
	var buf [bufLen]byte
	copy(buf[:], encoded)
	digest := sha256.Sum256(buf[:])
	if digest == target {
		return &Result{Password: pw, Encoding: encoding}
	}
	return nil
}

// ─── 辅助函数 ───────────────────────────────────────────────

// formatNum 将大数字格式化为带千分位的字符串。
func formatNum(n uint64) string {
	s := fmt.Sprintf("%d", n)
	if len(s) <= 3 {
		return s
	}
	var sb strings.Builder
	pre := len(s) % 3
	if pre > 0 {
		sb.WriteString(s[:pre])
		if len(s) > pre {
			sb.WriteByte(',')
		}
	}
	for i := pre; i < len(s); i += 3 {
		sb.WriteString(s[i : i+3])
		if i+3 < len(s) {
			sb.WriteByte(',')
		}
	}
	return sb.String()
}

// formatDuration 将秒数格式化为人类可读的时间。
func formatDuration(sec float64) string {
	if sec < 60 {
		return fmt.Sprintf("%.0fs", sec)
	}
	if sec < 3600 {
		return fmt.Sprintf("%.1fm", sec/60)
	}
	return fmt.Sprintf("%.1fh", sec/3600)
}

// ─── main ──────────────────────────────────────────────────

func main() {
	cfg := defaultConfig()
	var targetHash string
	var dictOnly bool

	flag.StringVar(&cfg.Charset, "charset", cfg.Charset, "候选字符集")
	flag.IntVar(&cfg.MinLen, "min", cfg.MinLen, "最小密码长度")
	flag.IntVar(&cfg.MaxLen, "max", cfg.MaxLen, "最大密码长度")
	flag.StringVar(&cfg.Encoding, "enc", cfg.Encoding, "编码: utf16le|latin1|both")
	flag.IntVar(&cfg.Workers, "threads", cfg.Workers, "并行线程数")
	flag.StringVar(&targetHash, "hash", targetHex, "目标 SHA-256 哈希 (hex)")
	flag.BoolVar(&dictOnly, "dict", false, "仅跑字典")
	flag.Parse()

	// 解析目标哈希
	targetBytes, err := hex.DecodeString(targetHash)
	if err != nil || len(targetBytes) != 32 {
		fmt.Fprintf(os.Stderr, "错误: 无效的哈希 '%s'\n", targetHash)
		os.Exit(1)
	}
	var target [32]byte
	copy(target[:], targetBytes)

	fmt.Println("╔══════════════════════════════════════════════════════════╗")
	fmt.Println("║        H3C BIOS 密码爆破器 (Go 版)                       ║")
	fmt.Println("╚══════════════════════════════════════════════════════════╝")
	fmt.Printf("目标哈希: %s\n", targetHash)
	fmt.Printf("算法: SHA-256( (编码(密码) + 0x00)[:40] )\n")
	fmt.Printf("CPU 核心: %d  线程: %d\n", runtime.NumCPU(), cfg.Workers)
	fmt.Println(strings.Repeat("═", 60))

	startTime := time.Now()

	// Phase 1: 字典
	if r := tryDictionary(target); r != nil {
		printResult(r, startTime, targetHash)
		return
	}

	if dictOnly {
		fmt.Println("\n字典模式结束, 未命中。")
		return
	}

	// Phase 2+: 暴力
	encodings := []string{cfg.Encoding}
	if cfg.Encoding == "both" {
		encodings = []string{"utf16le", "latin1"}
	}

	for _, enc := range encodings {
		if r := Brute(cfg, enc, target); r != nil {
			printResult(r, startTime, targetHash)
			return
		}
	}

	fmt.Printf("\n所有阶段未命中。用时: %s\n", formatDuration(time.Since(startTime).Seconds()))
}

// printResult 打印命中结果并写入 passd.txt。
func printResult(r *Result, startTime time.Time, targetHash string) {
	elapsed := time.Since(startTime)
	fmt.Println()
	fmt.Println(strings.Repeat("═", 60))
	fmt.Printf("★ 命中! BIOS 管理员密码 = %q\n", r.Password)
	fmt.Printf("  编码: %s\n", r.Encoding)
	fmt.Printf("  用时: %s\n", formatDuration(elapsed.Seconds()))

	// 复核
	var encoded []byte
	switch r.Encoding {
	case "utf16le":
		for _, c := range r.Password {
			b := make([]byte, 2)
			binary.LittleEndian.PutUint16(b, uint16(c))
			encoded = append(encoded, b...)
		}
	case "latin1":
		for _, c := range r.Password {
			if c > 0xFF {
				encoded = append(encoded, 0x3F)
			} else {
				encoded = append(encoded, byte(c))
			}
		}
	}
	var buf [bufLen]byte
	copy(buf[:], encoded)
	digest := sha256.Sum256(buf[:])
	fmt.Printf("  复核 SHA-256: %s\n", hex.EncodeToString(digest[:]))
	fmt.Printf("  目标        : %s\n", targetHash)
	fmt.Printf("  匹配: %v\n", hex.EncodeToString(digest[:]) == targetHash)

	// 写入 passd.txt
	if err := os.WriteFile("passd.txt", []byte(r.Password+"\n"), 0644); err != nil {
		fmt.Fprintf(os.Stderr, "  写文件失败: %v\n", err)
		os.Exit(1)
	}
	fmt.Println("  已写入 passd.txt")
}
