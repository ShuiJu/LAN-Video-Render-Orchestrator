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
	AUTH_TOKEN        = "114514"       // 与网页端一致
	ALLOWED_CLIENT_IP = "192.168.1.xx" // 允许的PC1 IP
	NVENCC_PATH       = "NVEncC64.exe"
	FFMPEG_PATH       = "ffmpeg.exe"
	TASK_TIMEOUT      = 3 * time.Hour
	LOG_FILE          = "render_server.log"
	QUEUE_SIZE        = 10 // 最大排队任务数
)

type Job struct {
	Filename string `json:"filename"`
	Codec    string `json:"codec"`
	Bitrate  int    `json:"bitrate"`
	Seek     string `json:"seek"`
	SeekTo   string `json:"seekto"`
	ClientIP string `json:"-"`
}

var (
	jobQueue   = make(chan Job, QUEUE_SIZE)
	validName  = regexp.MustCompile(`^[\p{Han}A-Za-z0-9 _\.\-]+$`)
	allowedMap = map[string]bool{"av1": true, "hevc": true, "h265": true, "svt-av1": true}
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
	return filepath.Join(`\\Desktop-mealea9\c\Users\ShuiJu\Videos\Media Encoder 9Slim渲染机输出`, filename)
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
	if !validName.MatchString(j.Filename) {
		return errors.New("invalid filename")
	}
	if !allowedMap[strings.ToLower(j.Codec)] {
		return fmt.Errorf("unsupported codec: %s", j.Codec)
	}
	if j.Bitrate <= 0 || j.Bitrate > 200000 {
		return fmt.Errorf("bitrate out of range: %d", j.Bitrate)
	}
	return nil
}

// ================== 执行函数 ==================
func runNVEnc(job Job) error {
	input := safeJoinInput(job.Filename)
	output := safeJoinOutput(job.Filename)
	codec := strings.ToLower(job.Codec)
	if codec == "h265" {
		codec = "hevc"
	}

	base := []string{
		"-i", input, "-o", output,
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
		base = append(base, "--seek", job.Seek)
	}
	if job.SeekTo != "" {
		base = append(base, "--seekto", job.SeekTo)
	}

	var args []string
	if codec == "av1" {
		args = append([]string{"-c", "av1", "--level", "6.1", "--preset", "quality", "--profile", "high"}, base...)
	} else {
		args = append([]string{"-c", "hevc", "--level", "6", "--preset", "quality", "--tier", "high", "--avsync", "forcecfr"}, base...)
	}

	ctx, cancel := context.WithTimeout(context.Background(), TASK_TIMEOUT)
	defer cancel()
	cmd := exec.CommandContext(ctx, NVENCC_PATH, args...)
	log.Println("Running NVEnc:", cmd.String())
	out, err := cmd.CombinedOutput()
	if err != nil {
		log.Printf("NVEnc error: %v\n%s", err, string(out))
		return err
	}
	log.Printf("NVEnc done for %s", job.Filename)
	return nil
}

func runFFmpeg(job Job) error {
	input := safeJoinInput(job.Filename)
	output := safeJoinOutput(job.Filename)
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
		log.Printf("Dequeued job [%s] from %s codec=%s bitrate=%d", job.Filename, job.ClientIP, job.Codec, job.Bitrate)
		start := time.Now()
		var err error
		switch strings.ToLower(job.Codec) {
		case "svt-av1":
			err = runFFmpeg(job)
		default:
			err = runNVEnc(job)
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
	if client != ALLOWED_CLIENT_IP {
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

// ================== Main ==================
func main() {
	go worker()
	http.HandleFunc("/job", jobHandler)
	log.Println("Render server with queue listening on :8088")
	log.Fatal(http.ListenAndServe(":8088", nil))
}
