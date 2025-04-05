package main

import (
	"encoding/json"
	"fmt"
	"io"
	"math/rand"
	"os"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
	"unsafe"

	"github.com/valyala/fasthttp"
	"github.com/valyala/fasthttp/fasthttpproxy"
	"golang.org/x/sys/windows"
)

type ErrorData struct {
	Email struct {
		ErrorCode int    `json:"error_code"`
		ErrorBody string `json:"error_body"`
	} `json:"email"`
}

type CheckResult struct {
	Email    string
	Status   string
	Response []byte
}

type Stats struct {
	processed int64
	linked    int64
	unlinked  int64
	startTime time.Time
}

func (s *Stats) increment(status string) {
	atomic.AddInt64(&s.processed, 1)
	switch {
	case strings.Contains(status, "[LINKED]"):
		atomic.AddInt64(&s.linked, 1)
	case strings.Contains(status, "[UNLINKED]"):
		atomic.AddInt64(&s.unlinked, 1)
	}
}

func (s *Stats) getCPM() float64 {
	duration := time.Since(s.startTime)
	minutes := duration.Minutes()
	if minutes > 0 {
		return float64(atomic.LoadInt64(&s.processed)) / minutes
	}
	return 0
}

func generateRegInstance() string {
	const charset = "0123456789"
	result := make([]byte, 16)
	for i := range result {
		result[i] = charset[rand.Intn(len(charset))]
	}
	return string(result)
}

func formatProxy(proxy string) string {
	parts := strings.Split(proxy, ":")
	if len(parts) == 2 {
		return fmt.Sprintf("http://%s", proxy)
	}
	return proxy
}
func checkEmailWithProxy(email, proxy string) (string, []byte) {
	client := &fasthttp.Client{
		MaxConnsPerHost:     10000,
		ReadTimeout:         30 * time.Second,
		WriteTimeout:        30 * time.Second,
		MaxIdleConnDuration: 30 * time.Second,
		MaxConnDuration:     30 * time.Second,
		MaxConnWaitTimeout:  30 * time.Second,
		Dial: (&fasthttp.TCPDialer{
			Concurrency:      4000,
			DNSCacheDuration: time.Hour,
		}).Dial,
	}

	if proxy != "" {
		formattedProxy := formatProxy(proxy)
		client.Dial = fasthttpproxy.FasthttpHTTPDialer(formattedProxy)
	}

	req := fasthttp.AcquireRequest()
	resp := fasthttp.AcquireResponse()
	defer fasthttp.ReleaseRequest(req)
	defer fasthttp.ReleaseResponse(resp)

	req.SetRequestURI("https://graph.facebook.com/app/validate_registration_data")
	req.Header.SetMethod("POST")
	req.Header.SetContentType("application/json")

	payload := map[string]string{
		"email":                    email,
		"reg_instance":             generateRegInstance(),
		"fb_api_req_friendly_name": "validateRegistrationData",
		"fb_api_caller_class":      "RegistrationValidateDataFragment",
		"access_token":             "350685531728|62f8ce9f74b12f84c123cc23437a4a32",
	}

	jsonData, err := json.Marshal(payload)
	if err != nil {
		return fmt.Sprintf("[UNLINKED] %s", email), nil
	}

	req.SetBody(jsonData)

	if err := client.Do(req, resp); err != nil {
		return fmt.Sprintf("[UNLINKED] %s", email), nil
	}

	responseBody := make([]byte, len(resp.Body()))
	copy(responseBody, resp.Body())

	var fbError struct {
		Error struct {
			Code      int         `json:"code"`
			ErrorData interface{} `json:"error_data"`
		} `json:"error"`
	}

	if err := json.Unmarshal(responseBody, &fbError); err != nil {
		return fmt.Sprintf("[UNLINKED] %s", email), responseBody
	}

	if fbError.Error.Code == 3116 {
		if errorDataStr, ok := fbError.Error.ErrorData.(string); ok {
			var errorData ErrorData
			if err := json.Unmarshal([]byte(errorDataStr), &errorData); err == nil && errorData.Email.ErrorCode == 3113 {
				return fmt.Sprintf("[LINKED] %s", email), responseBody
			}
		}
	}

	return fmt.Sprintf("[UNLINKED] %s", email), responseBody
}

func formatDuration(d time.Duration) string {
	hours := int(d.Hours())
	minutes := int(d.Minutes()) % 60
	seconds := int(d.Seconds()) % 60
	return fmt.Sprintf("%02d:%02d:%02d", hours, minutes, seconds)
}

func updateConsoleTitle(stats *Stats) {
	elapsed := time.Since(stats.startTime)
	title := fmt.Sprintf("CPM: %.0f | Processed: %d | Linked: %d | Unlinked: %d | ĐANG CHẠY: %s",
		stats.getCPM(),
		atomic.LoadInt64(&stats.processed),
		atomic.LoadInt64(&stats.linked),
		atomic.LoadInt64(&stats.unlinked),
		formatDuration(elapsed))

	kernel32 := syscall.NewLazyDLL("kernel32.dll")
	setConsoleTitle := kernel32.NewProc("SetConsoleTitleW")
	utf16Title, _ := syscall.UTF16PtrFromString(title)
	setConsoleTitle.Call(uintptr(unsafe.Pointer(utf16Title)))
}

func init() {
	stdout := windows.Handle(os.Stdout.Fd())
	var originalMode uint32

	if err := windows.GetConsoleMode(stdout, &originalMode); err == nil {
		windows.SetConsoleMode(stdout, originalMode|windows.ENABLE_VIRTUAL_TERMINAL_PROCESSING)
	}
	runtime.GOMAXPROCS(runtime.NumCPU())
}

func main() {
	const bufferSize = 100 * 1024 * 1024
	var wg sync.WaitGroup
	var emailData, proxyData []byte
	var emailErr, proxyErr error

	var threadCount int
	fmt.Print("Nhập số luồng (>0): ")
	fmt.Scanln(&threadCount)

	if threadCount < 1 {
		fmt.Println("Số luồng phải lớn hơn 0. Đang đặt số luồng thành 1...")
		threadCount = 1
	}

	wg.Add(2)
	go func() {
		defer wg.Done()
		file, err := os.OpenFile("emails.txt", os.O_RDONLY, 0)
		if err != nil {
			emailErr = err
			return
		}
		defer file.Close()

		buffer := make([]byte, bufferSize)
		var data []byte
		for {
			n, err := file.Read(buffer)
			if n > 0 {
				data = append(data, buffer[:n]...)
			}
			if err != nil {
				if err != io.EOF {
					emailErr = err
				}
				break
			}
		}
		emailData = data
	}()

	go func() {
		defer wg.Done()
		file, err := os.OpenFile("proxies.txt", os.O_RDONLY, 0)
		if err != nil {
			proxyErr = err
			return
		}
		defer file.Close()

		buffer := make([]byte, bufferSize)
		var data []byte
		for {
			n, err := file.Read(buffer)
			if n > 0 {
				data = append(data, buffer[:n]...)
			}
			if err != nil {
				if err != io.EOF {
					proxyErr = err
				}
				break
			}
		}
		proxyData = data
	}()
	wg.Wait()

	if emailErr != nil {
		fmt.Printf("Lỗi khi đọc file emails.txt: %v\n", emailErr)
		return
	}
	if proxyErr != nil {
		fmt.Printf("Lỗi khi đọc file proxies.txt: %v\n", proxyErr)
		return
	}

	emails := strings.Split(strings.TrimSpace(string(emailData)), "\n")
	proxies := strings.Split(strings.TrimSpace(string(proxyData)), "\n")

	if len(proxies) == 0 {
		fmt.Println("Không tìm thấy proxy trong file proxies.txt")
		return
	}

	fmt.Printf("Bắt đầu kiểm tra %d email với %d proxy và %d thread...\n", len(emails), len(proxies), threadCount)
	fmt.Println("Mỗi email sẽ được gán với một proxy cố định")

	startTime := time.Now()
	results := processEmails(emails, proxies, threadCount)

	var linked, unlinked int
	for _, result := range results {
		switch {
		case strings.Contains(result.Status, "[LINKED]"):
			linked++
		default:
			unlinked++
		}
	}

	duration := time.Since(startTime)
	fmt.Printf("\nKết quả kiểm tra:\n")
	fmt.Printf("- Tổng số email: %d\n", len(results))
	fmt.Printf("- Số proxy sử dụng: %d\n", len(proxies))
	fmt.Printf("- Đã liên kết FB: %d\n", linked)
	fmt.Printf("- Chưa liên kết FB: %d\n", unlinked)
	fmt.Printf("- Thời gian chạy: %s\n", formatDuration(duration))
}

type FileWriter struct {
	file *os.File
	mu   sync.Mutex
}

func NewFileWriter(filename string) (*FileWriter, error) {
	file, err := os.OpenFile(filename, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	if err != nil {
		return nil, err
	}
	return &FileWriter{
		file: file,
		mu:   sync.Mutex{},
	}, nil
}

func (w *FileWriter) WriteLine(line string) error {
	w.mu.Lock()
	defer w.mu.Unlock()
	_, err := w.file.WriteString(line + "\n")
	return err
}

func (w *FileWriter) Close() error {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.file.Close()
}

func processEmails(emails []string, proxies []string, threadCount int) []CheckResult {
	linkedWriter, err := NewFileWriter("linked.txt")
	if err != nil {
		fmt.Printf("Lỗi khi tạo file linked.txt: %v\n", err)
		return nil
	}
	defer linkedWriter.Close()

	unlinkedWriter, err := NewFileWriter("unlinked.txt")
	if err != nil {
		fmt.Printf("Lỗi khi tạo file unlinked.txt: %v\n", err)
		return nil
	}
	defer unlinkedWriter.Close()

	stats := &Stats{startTime: time.Now()}
	results := make([]CheckResult, 0, len(emails))
	resultsChan := make(chan CheckResult, threadCount*4)

	type EmailProxy struct {
		Email string
		Proxy string
	}

	emailChan := make(chan EmailProxy, threadCount*4)

	emailProxyPairs := make([]EmailProxy, 0, len(emails))

	proxyCount := len(proxies)
	for i, email := range emails {
		emailProxyPairs = append(emailProxyPairs, EmailProxy{
			Email: email,
			Proxy: proxies[i%proxyCount],
		})
	}

	ticker := time.NewTicker(10 * time.Millisecond)
	go func() {
		for range ticker.C {
			if atomic.LoadInt64(&stats.processed) >= int64(len(emails)) {
				ticker.Stop()
				return
			}
			updateConsoleTitle(stats)
		}
	}()

	var wg sync.WaitGroup
	wg.Add(threadCount)

	for i := 0; i < threadCount; i++ {
		go func() {
			defer wg.Done()
			for pair := range emailChan {
				status, response := checkEmailWithProxy(pair.Email, pair.Proxy)
				stats.increment(status)

				resultsChan <- CheckResult{
					Email:    pair.Email,
					Status:   status,
					Response: response,
				}

				if strings.Contains(status, "[LINKED]") {
					fmt.Printf("[LINKED] | %s\n", pair.Email)
					linkedWriter.WriteLine(pair.Email)
				} else {
					fmt.Printf("[UNLINKED] | %s\n", pair.Email)
					unlinkedWriter.WriteLine(pair.Email)
				}
			}
		}()
	}

	const batchSize = 1000
	go func() {
		for i := 0; i < len(emailProxyPairs); i += batchSize {
			end := i + batchSize
			if end > len(emailProxyPairs) {
				end = len(emailProxyPairs)
			}
			for _, pair := range emailProxyPairs[i:end] {
				emailChan <- pair
			}
		}
		close(emailChan)
	}()

	go func() {
		wg.Wait()
		close(resultsChan)
	}()

	for result := range resultsChan {
		results = append(results, result)
	}

	return results
}
