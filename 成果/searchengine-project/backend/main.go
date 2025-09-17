package main

import (
	"encoding/json"
	"fmt"
	"log"
	"math/rand"
	"net/http"
	"regexp"
	"strings"
	"sync"
	"time"
)

type SendCaptchaRequest struct {
	Phone string `json:"phone"`
}

type VerifyCaptchaRequest struct {
	Phone string `json:"phone"`
	Code  string `json:"code"`
}

type CaptchaInfo struct {
	Code     string    `json:"code"`
	ExpireAt time.Time `json:"expire_at"`
}

var (
	captchaStore = make(map[string]CaptchaInfo)
	mu           sync.RWMutex
	phoneRegex   = regexp.MustCompile(`^1[3-9]\d{9}$`)
)

func sendCaptchaHandler(w http.ResponseWriter, r *http.Request) {
	setCORSHeaders(w)
	if r.Method == http.MethodOptions {
		w.WriteHeader(http.StatusOK)
		return
	}
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req SendCaptchaRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}
	defer r.Body.Close()

	req.Phone = strings.TrimSpace(req.Phone)
	if !phoneRegex.MatchString(req.Phone) {
		http.Error(w, "Invalid phone number", http.StatusBadRequest)
		return
	}

	mu.RLock()
	info, exists := captchaStore[req.Phone]
	mu.RUnlock()

	// 检查是否在冷却期（1分钟内重复发送）
	if exists && info.ExpireAt.After(time.Now().Add(-1*time.Minute)) {
		http.Error(w, "Too many requests, please try again later", http.StatusTooManyRequests)
		return
	}

	// 生成6位随机验证码
	code := rand.Intn(900000) + 100000
	codeStr := fmt.Sprintf("%d", code)
	expireAt := time.Now().Add(5 * time.Minute)

	// 存储验证码（线程安全）
	mu.Lock()
	captchaStore[req.Phone] = CaptchaInfo{
		Code:     codeStr,
		ExpireAt: expireAt,
	}
	mu.Unlock()

	// 调试信息（打印发送的验证码）
	log.Printf("发送验证码：%s（手机号：%s，过期时间：%s）", codeStr, req.Phone, expireAt.Format("2006-01-02 15:04:05"))

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"code": 0,
		"msg":  "Captcha sent successfully",
	})
}

func verifyCaptchaHandler(w http.ResponseWriter, r *http.Request) {
	setCORSHeaders(w)
	if r.Method == http.MethodOptions {
		w.WriteHeader(http.StatusOK)
		return
	}
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req VerifyCaptchaRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}
	defer r.Body.Close()

	req.Phone = strings.TrimSpace(req.Phone)
	req.Code = strings.TrimSpace(req.Code)

	if !phoneRegex.MatchString(req.Phone) {
		http.Error(w, "Invalid phone number", http.StatusBadRequest)
		return
	}

	if len(req.Code) != 6 {
		http.Error(w, "Captcha must be 6 digits", http.StatusBadRequest)
		return
	}

	// 线程安全读取
	mu.RLock()
	info, exists := captchaStore[req.Phone]
	mu.RUnlock()

	if !exists {
		http.Error(w, "Captcha not found", http.StatusBadRequest)
		return
	}

	if time.Now().After(info.ExpireAt) {
		// 清理过期验证码
		mu.Lock()
		delete(captchaStore, req.Phone)
		mu.Unlock()
		http.Error(w, "Captcha expired", http.StatusBadRequest)
		return
	}

	if info.Code != req.Code {
		http.Error(w, "Invalid captcha", http.StatusBadRequest)
		return
	}

	// 验证成功，清除验证码
	mu.Lock()
	delete(captchaStore, req.Phone)
	mu.Unlock()

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"code": 0,
		"msg":  "Captcha verified successfully",
	})
}

func setCORSHeaders(w http.ResponseWriter) {
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Access-Control-Allow-Methods", "POST, OPTIONS")
	w.Header().Set("Access-Control-Allow-Headers", "Content-Type")
}

func main() {
	rand.Seed(time.Now().UnixNano())
	http.HandleFunc("/api/send-captcha", sendCaptchaHandler)
	http.HandleFunc("/api/verify-captcha", verifyCaptchaHandler)
	log.Println("Server starting on :8080...")
	if err := http.ListenAndServe(":8080", nil); err != nil {
		log.Fatalf("Server failed to start: %v", err)
	}
}
