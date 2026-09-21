package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"
)

const (
	AUTH_TOKEN        = "20f01e4ae93f95d41cfdca0f180dec4c52430125" // 与网页端一致
	ALLOWED_CLIENT_IP = "192.168.68.2"                             // 允许的PC1 IP
	TASK_TIMEOUT      = 3 * time.Hour
	LOG_FILE          = "render_server.log"
	QUEUE_SIZE        = 50 // 最大排队任务数
)

// 工具路径：启动时由 checkEnvironment() 解析，支持 exe同目录 / tools子目录 / PATH
var (
	NVENCC_PATH = "NVEncC64.exe"
	FFMPEG_PATH = "ffmpeg.exe"
)

type Job struct {
	Filename string `json:"filename"`
	Codec    string `json:"codec"`
	Bitrate  int    `json:"bitrate"`
	Seek     string `json:"seek"`
	SeekTo   string `json:"seekto"`
	Local    bool   `json:"local"` // 本机快剪模式：filename 为完整路径，输出写到同目录
	ClientIP string `json:"-"`
}

var (
	jobQueue       = make(chan Job, QUEUE_SIZE)
	validName      = regexp.MustCompile(`^[\p{Han}A-Za-z0-9 _\.\-]+$`)
	validLocalPath = regexp.MustCompile(`^[A-Za-z]:\\(?:[\p{Han}A-Za-z0-9 _\.\-\(\)\[\]]+\\)*[\p{Han}A-Za-z0-9 _\.\-\(\)\[\]]+$`)
	allowedMap     = map[string]bool{"av1": true, "svt-av1": true}
)

func init() {
	f, err := os.OpenFile(LOG_FILE, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	if err != nil {
		panic(err)
	}
	log.SetOutput(io.MultiWriter(os.Stdout, f))
	log.SetFlags(log.LstdFlags | log.Lmicroseconds)
}

// ================== 工具函数 ==================
func clientIP(r *http.Request) string {
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		ips := strings.Split(xff, ",")
		return strings.TrimSpace(ips[0])
	}
	host, _, _ := net.SplitHostPort(r.RemoteAddr)
	return host
}

func safeJoinInput(filename string) string {
	return filepath.Join("C:\\Videos", filename)
}
func safeJoinOutput(filename string) string {
	return filepath.Join(`\\Desktop-mealea9\c\Users\Admin\Videos\Media Encoder 9Slim渲染机输出`, filename)
}

func parseSeek(s string) (int, error) {
	if s == "" {
		return 0, nil
	}
	parts := strings.Split(s, ":")
	if len(parts) != 2 {
		return 0, errors.New("seek format must be M:S")
	}
	m, err := strconv.Atoi(parts[0])
	if err != nil || m < 0 {
		return 0, err
	}
	sec, err := strconv.Atoi(parts[1])
	if err != nil || sec < 0 || sec >= 60 {
		return 0, err
	}
	return m*60 + sec, nil
}

func validateJob(j *Job) error {
	if j.Filename == "" {
		return errors.New("filename empty")
	}
	if j.Local {
		if !validLocalPath.MatchString(j.Filename) {
			return errors.New("invalid local path: must be absolute Windows path (e.g. C:\\Videos\\clip.mp4)")
		}
	} else {
		if !validName.MatchString(j.Filename) {
			return errors.New("invalid filename")
		}
	}
	if !allowedMap[strings.ToLower(j.Codec)] {
		return fmt.Errorf("unsupported codec: %s", j.Codec)
	}
	if j.Bitrate <= 0 || j.Bitrate > 200000 {
		return fmt.Errorf("bitrate out of range: %d", j.Bitrate)
	}
	return nil
}

// resolveJobPaths 根据模式返回输入/输出绝对路径
func resolveJobPaths(job Job) (input, output string, err error) {
	if job.Local {
		input = job.Filename
		if _, statErr := os.Stat(input); statErr != nil {
			err = fmt.Errorf("input file not found: %s", input)
			return
		}
		dir := filepath.Dir(input)
		base := filepath.Base(input)
		ext := filepath.Ext(base)
		stem := base[:len(base)-len(ext)]
		output = filepath.Join(dir, fmt.Sprintf("%s_%s_%dk.mp4", stem, strings.ToLower(job.Codec), job.Bitrate))
		return
	}
	input = safeJoinInput(job.Filename)
	output = safeJoinOutput(job.Filename)
	return
}

// ================== 执行函数 ==================
func runNVEnc(job Job, input, output string) error {
	tmpOutput := output + ".tmp.mp4"

	args := []string{
		"-c", "av1", "--level", "6.1", "--preset", "quality", "--profile", "high",
		"-i", input, "-o", tmpOutput,
		"--vbr", fmt.Sprint(job.Bitrate),
		"--output-buf", "128",
		"--multipass", "2pass-full",
		"--lookahead", "32",
		"--bref-mode", "each",
		"--aq", "--aq-temporal",
		"--mv-precision", "Q-pel",
		"--cuda-schedule", "sync",
		"--thread-throttling", "output=on,perfmonitor=on",
		"--audio-codec", "1?aac:aac_coder=twoloop",
		"--audio-bitrate", "192",
	}
	if job.Seek != "" {
		args = append(args, "--seek", job.Seek)
	}
	if job.SeekTo != "" {
		args = append(args, "--seekto", job.SeekTo)
	}

	ctx, cancel := context.WithTimeout(context.Background(), TASK_TIMEOUT)
	defer cancel()
	cmd := exec.CommandContext(ctx, NVENCC_PATH, args...)
	log.Println("Running NVEnc:", cmd.String())
	if out, err := cmd.CombinedOutput(); err != nil {
		log.Printf("NVEnc error: %v\n%s", err, string(out))
		return err
	}

	// 网页优化：将 moov atom 移到文件头部（faststart）
	log.Println("Applying web optimization (faststart)...")
	remux := exec.CommandContext(ctx, FFMPEG_PATH,
		"-y", "-i", tmpOutput,
		"-c", "copy",
		"-movflags", "+faststart",
		output,
	)
	if out, err := remux.CombinedOutput(); err != nil {
		log.Printf("Faststart remux error: %v\n%s", err, string(out))
		os.Remove(tmpOutput)
		return err
	}
	os.Remove(tmpOutput)
	log.Printf("NVEnc AV1 done for %s", job.Filename)
	return nil
}

func runFFmpeg(job Job, input, output string) error {
	br := fmt.Sprintf("%dk", job.Bitrate)
	logfile := "ffmpeg2pass.log"

	os.Remove(logfile)
	ctx, cancel := context.WithTimeout(context.Background(), TASK_TIMEOUT)
	defer cancel()

	// seek / seekto
	var seekArgs []string
	if job.Seek != "" {
		start, _ := parseSeek(job.Seek)
		if start > 0 {
			seekArgs = append(seekArgs, "-ss", fmt.Sprintf("%d", start))
		}
	}
	if job.SeekTo != "" {
		end, _ := parseSeek(job.SeekTo)
		if end > 0 {
			seekArgs = append(seekArgs, "-to", fmt.Sprintf("%d", end))
		}
	}

	pass1Args := append([]string{"-y"}, seekArgs...)
	pass1Args = append(pass1Args,
		"-i", input,
		"-pix_fmt", "yuv420p10le",
		"-c:v", "libsvtav1",
		"-preset", "8",
		"-b:v", br,
		"-pass", "1",
		"-an", "-f", "null", "NUL",
	)
	pass1 := exec.CommandContext(ctx, FFMPEG_PATH, pass1Args...)
	pass1.Env = append(os.Environ(), "SVT_LOGFILE="+logfile)
	log.Println("FFmpeg Pass 1:", pass1.String())
	if out, err := pass1.CombinedOutput(); err != nil {
		log.Printf("FFmpeg Pass1 failed: %v\n%s", err, out)
		return err
	}

	pass2Args := append([]string{"-y"}, seekArgs...)
	pass2Args = append(pass2Args,
		"-i", input,
		"-pix_fmt", "yuv420p10le",
		"-c:v", "libsvtav1",
		"-preset", "5",
		"-b:v", br,
		"-pass", "2",
		"-c:a", "aac", "-b:a", "192k",
		"-movflags", "+faststart",
		output,
	)
	pass2 := exec.CommandContext(ctx, FFMPEG_PATH, pass2Args...)
	pass2.Env = append(os.Environ(), "SVT_LOGFILE="+logfile)
	log.Println("FFmpeg Pass 2:", pass2.String())
	if out, err := pass2.CombinedOutput(); err != nil {
		log.Printf("FFmpeg Pass2 failed: %v\n%s", err, out)
		return err
	}
	os.Remove(logfile)
	log.Printf("SVT-AV1 done for %s", job.Filename)
	return nil
}

// ================== 队列 Worker ==================
func worker() {
	for job := range jobQueue {
		log.Printf("Dequeued job [%s] from %s codec=%s bitrate=%d local=%v", job.Filename, job.ClientIP, job.Codec, job.Bitrate, job.Local)
		input, output, err := resolveJobPaths(job)
		if err != nil {
			log.Printf("Job path error: %s error=%v", job.Filename, err)
			continue
		}
		log.Printf("  input : %s", input)
		log.Printf("  output: %s", output)
		start := time.Now()
		switch strings.ToLower(job.Codec) {
		case "svt-av1":
			err = runFFmpeg(job, input, output)
		case "av1":
			err = runNVEnc(job, input, output)
		default:
			err = fmt.Errorf("unknown codec: %s", job.Codec)
		}
		if err != nil {
			log.Printf("Job failed: %s error=%v", job.Filename, err)
		} else {
			log.Printf("Job finished: %s elapsed=%s", job.Filename, time.Since(start))
		}
	}
}

// ================== HTTP Handler ==================
func jobHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Access-Control-Allow-Methods", "POST, OPTIONS")
	w.Header().Set("Access-Control-Allow-Headers", "Content-Type, X-Auth-Token")
	if r.Method == http.MethodOptions {
		w.WriteHeader(http.StatusNoContent)
		return
	}

	client := clientIP(r)
	if r.Header.Get("X-Auth-Token") != AUTH_TOKEN {
		http.Error(w, "unauthorized", 401)
		log.Printf("auth fail %s", client)
		return
	}
	// 预过滤：只允许已知渲染客户端 或 本机回环地址
	isLocalhost := client == "127.0.0.1" || client == "::1"
	isAllowed := client == ALLOWED_CLIENT_IP
	if !isLocalhost && !isAllowed {
		http.Error(w, "forbidden", 403)
		log.Printf("forbidden client %s", client)
		return
	}

	body, err := io.ReadAll(io.LimitReader(r.Body, 16*1024))
	if err != nil {
		http.Error(w, "read error", 400)
		return
	}
	var job Job
	if err := json.Unmarshal(body, &job); err != nil {
		http.Error(w, "bad json", 400)
		return
	}
	if err := validateJob(&job); err != nil {
		http.Error(w, err.Error(), 400)
		return
	}
	// 二次校验：本机模式只允许本机发起，双机模式只允许已授权客户端
	if job.Local && !isLocalhost {
		http.Error(w, "local mode requires localhost connection", 403)
		log.Printf("local mode rejected from %s", client)
		return
	}
	if !job.Local && !isAllowed {
		http.Error(w, "forbidden", 403)
		log.Printf("remote job rejected from non-allowed client %s", client)
		return
	}

	job.ClientIP = client
	select {
	case jobQueue <- job:
		log.Printf("Queued job [%s] from %s", job.Filename, client)
		w.Write([]byte("queued"))
	default:
		http.Error(w, "queue full", 503)
		log.Printf("Queue full, reject job from %s", client)
	}
}

// ================== 环境检查 ==================
// resolveExe 在 searchDirs 和系统 PATH 中查找可执行文件，返回绝对路径；未找到返回 ""
func resolveExe(name string, searchDirs []string) string {
	for _, dir := range searchDirs {
		p := filepath.Join(dir, name)
		if _, err := os.Stat(p); err == nil {
			if abs, err := filepath.Abs(p); err == nil {
				return abs
			}
			return p
		}
	}
	if p, err := exec.LookPath(name); err == nil {
		return p
	}
	return ""
}

// checkEnvironment 在启动时确认 NVEncC64.exe 和 ffmpeg.exe 可用，并更新路径变量
func checkEnvironment() {
	exeDir := "."
	if exePath, err := os.Executable(); err == nil {
		exeDir = filepath.Dir(exePath)
	}
	toolsDir := filepath.Join(exeDir, "tools")
	searchDirs := []string{exeDir, toolsDir, "."}

	log.Println("[ENV] 检查运行环境...")

	p := resolveExe("NVEncC64.exe", searchDirs)
	if p == "" {
		log.Fatal("[ENV] 错误：未找到 NVEncC64.exe（已搜索 exe目录、tools子目录、PATH）。请运行 setup.bat 安装依赖。")
	}
	NVENCC_PATH = p
	log.Printf("[ENV] NVEncC64 : %s", NVENCC_PATH)

	p = resolveExe("ffmpeg.exe", searchDirs)
	if p == "" {
		log.Fatal("[ENV] 错误：未找到 ffmpeg.exe（已搜索 exe目录、tools子目录、PATH）。请运行 setup.bat 安装依赖。")
	}
	FFMPEG_PATH = p
	log.Printf("[ENV] ffmpeg   : %s", FFMPEG_PATH)

	log.Println("[ENV] 环境检查通过。")
}

// ================== Main ==================
func main() {
	checkEnvironment()
	go worker()
	http.HandleFunc("/job", jobHandler)
	log.Println("Render server with queue listening on :8088")
	log.Fatal(http.ListenAndServe(":8088", nil))
}
