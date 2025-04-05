package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"math/rand"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/lxn/walk"
	"github.com/lxn/walk/declarative"
	"github.com/lxn/win"
	"github.com/valyala/fasthttp"
	"github.com/valyala/fasthttp/fasthttpproxy"
)

const (
	pauseButtonText    = "Tam dung"
	continueButtonText = "Tiep tuc"
	messageBoxTitle    = "Thong bao"
	exportErrorMessage = "Khong the xuat file: %v"
	errorFormat        = "[ERROR] %s - %v"
	windowWidth        = 500
	windowHeight       = 500
)

type ErrorData struct {
	Email struct {
		ErrorCode int    `json:"error_code"`
		ErrorBody string `json:"error_body"`
	} `json:"email"`
}

type FacebookError struct {
	Error struct {
		Message   string `json:"message"`
		Type      string `json:"type"`
		Code      int    `json:"code"`
		ErrorData string `json:"error_data"`
		FbTraceID string `json:"fbtrace_id"`
	} `json:"error"`
}

type CheckResult struct {
	Email    string
	Status   string
	Response []byte
}

type MyMainWindow struct {
	*walk.MainWindow
	emailEdit     *walk.TextEdit
	proxyEdit     *walk.TextEdit
	resultEdit    *walk.TextEdit
	progressBar   *walk.ProgressBar
	statsLabel    *walk.TextLabel
	cpmLabel      *walk.TextLabel
	errorLabel    *walk.TextLabel
	linkedBtn     *walk.PushButton
	unlinkedBtn   *walk.PushButton
	exportAllBtn  *walk.PushButton
	pauseBtn      *walk.PushButton
	stopBtn       *walk.PushButton
	threadNumEdit *walk.NumberEdit
	running       bool
	paused        bool
	mutex         sync.Mutex
	linkedMails   []string
	unlinkedMails []string
	errorMails    []string
	fullResults   []string
	checkResults  []CheckResult
	startTime     time.Time
	pauseTime     time.Duration
	pauseStart    time.Time
	checkCount    int32
	stopChan      chan struct{}
	shouldStop    bool
	errorBtn      *walk.PushButton
}

func (mw *MyMainWindow) togglePause() {
	mw.mutex.Lock()
	defer mw.mutex.Unlock()

	if !mw.running {
		return
	}

	mw.paused = !mw.paused
	if mw.paused {
		mw.pauseStart = time.Now()
		mw.pauseBtn.SetText(continueButtonText)
	} else {
		mw.pauseTime += time.Since(mw.pauseStart)
		mw.pauseBtn.SetText(pauseButtonText)
	}
}

func (mw *MyMainWindow) updateStats() {
	total := len(mw.linkedMails) + len(mw.unlinkedMails) + len(mw.errorMails)
	statsText := fmt.Sprintf("Tong: %d | Da lien ket: %d | Chua lien ket: %d",
		total, len(mw.linkedMails), len(mw.unlinkedMails))
	mw.statsLabel.SetText(statsText)

	errorText := fmt.Sprintf("Loi: %d", len(mw.errorMails))
	mw.errorLabel.SetText(errorText)

	if mw.running {
		elapsed := time.Since(mw.startTime) - mw.pauseTime
		if mw.paused {
			elapsed -= time.Since(mw.pauseStart)
		}
		minutes := elapsed.Minutes()
		if minutes > 0 {
			cpm := float64(atomic.LoadInt32(&mw.checkCount)) / minutes
			timeText := fmt.Sprintf("CPM: %.0f | Thoi gian: %02d:%02d",
				cpm,
				int(elapsed.Minutes()),
				int(elapsed.Seconds())%60,
			)
			mw.cpmLabel.SetText(timeText)
		}
	}
}

func (mw *MyMainWindow) startStatsTimer() {
	ticker := time.NewTicker(100 * time.Millisecond)
	go func() {
		for {
			select {
			case <-ticker.C:
				if mw.running && !mw.paused {
					mw.updateStats()
				}
			case <-mw.stopChan:
				ticker.Stop()
				return
			}
		}
	}()
}

func (mw *MyMainWindow) exportToFile(mails []string, defaultFilename string) error {
	dlg := new(walk.FileDialog)
	dlg.Title = "Chon noi luu file"
	dlg.Filter = "Text Files (*.txt)|*.txt|All Files (*.*)|*.*"
	dlg.InitialDirPath = "."
	dlg.FilePath = defaultFilename

	if ok, err := dlg.ShowSave(mw); err != nil {
		return err
	} else if !ok {
		return nil
	}

	return os.WriteFile(dlg.FilePath, []byte(strings.Join(mails, "\n")), 0644)
}

func formatProxy(proxy string) string {
	parts := strings.Split(proxy, ":")
	if len(parts) == 2 {
		return fmt.Sprintf("http://%s", proxy)
	} else if len(parts) == 4 {
		return fmt.Sprintf("http://%s:%s@%s:%s", parts[2], parts[3], parts[0], parts[1])
	}
	return proxy
}

func (mw *MyMainWindow) exportLinked() {
	if len(mw.linkedMails) == 0 {
		walk.MsgBox(mw, messageBoxTitle, "Khong co email da lien ket FB!", walk.MsgBoxIconInformation)
		return
	}

	if err := mw.exportToFile(mw.linkedMails, "linked_emails.txt"); err != nil && err.Error() != "null" {
		walk.MsgBox(mw, messageBoxTitle, fmt.Sprintf(exportErrorMessage, err), walk.MsgBoxIconError)
		return
	}

	walk.MsgBox(mw, messageBoxTitle, "Da xuat danh sach email da lien ket FB!", walk.MsgBoxIconInformation)
}

func (mw *MyMainWindow) exportUnlinked() {
	if len(mw.unlinkedMails) == 0 {
		walk.MsgBox(mw, messageBoxTitle, "Khong co email chua lien ket FB!", walk.MsgBoxIconInformation)
		return
	}

	if err := mw.exportToFile(mw.unlinkedMails, "unlinked_emails.txt"); err != nil && err.Error() != "null" {
		walk.MsgBox(mw, messageBoxTitle, fmt.Sprintf(exportErrorMessage, err), walk.MsgBoxIconError)
		return
	}

	walk.MsgBox(mw, messageBoxTitle, "Da xuat danh sach email chua lien ket FB!", walk.MsgBoxIconInformation)
}

func (mw *MyMainWindow) exportErrors() {
	if len(mw.errorMails) == 0 {
		walk.MsgBox(mw, messageBoxTitle, "Khong co email bi loi!", walk.MsgBoxIconInformation)
		return
	}

	if err := mw.exportToFile(mw.errorMails, "error_emails.txt"); err != nil && err.Error() != "null" {
		walk.MsgBox(mw, messageBoxTitle, fmt.Sprintf(exportErrorMessage, err), walk.MsgBoxIconError)
		return
	}

	walk.MsgBox(mw, messageBoxTitle, "Da xuat danh sach email bi loi!", walk.MsgBoxIconInformation)
}

func (mw *MyMainWindow) exportAll() {
	if len(mw.fullResults) == 0 {
		walk.MsgBox(mw, messageBoxTitle, "Chua co ket qua nao!", walk.MsgBoxIconInformation)
		return
	}

	elapsed := time.Since(mw.startTime) - mw.pauseTime
	if mw.paused {
		elapsed -= time.Since(mw.pauseStart)
	}
	minutes := elapsed.Minutes()
	cpm := float64(len(mw.fullResults)) / minutes

	content := "=== THONG TIN CHAY ===\n"
	content += fmt.Sprintf("Thoi gian chay: %02d:%02d\n", int(elapsed.Minutes()), int(elapsed.Seconds())%60)
	content += fmt.Sprintf("CPM: %.0f\n", cpm)
	content += fmt.Sprintf("So luong Thread: %d\n", int(mw.threadNumEdit.Value()))
	content += fmt.Sprintf("Tong so loi: %d\n\n", len(mw.errorMails))

	content += "=== DANH SACH KIEM TRA ===\n\n"
	for _, result := range mw.checkResults {
		content += result.Status + "\n"
		if result.Response != nil {
			var prettyJSON bytes.Buffer
			if err := json.Indent(&prettyJSON, result.Response, "", "    "); err == nil {
				content += "Response:\n" + prettyJSON.String() + "\n"
			}
		}
		content += "------------------------\n"
	}

	content += "\n=== THONG KE ===\n"
	content += fmt.Sprintf("Tong so: %d\n", len(mw.linkedMails)+len(mw.unlinkedMails))
	content += fmt.Sprintf("Da lien ket FB: %d\n", len(mw.linkedMails))
	content += fmt.Sprintf("Chua lien ket FB: %d\n", len(mw.unlinkedMails))
	content += "\n=== EMAIL DA LIEN KET FB ===\n"
	content += strings.Join(mw.linkedMails, "\n")
	content += "\n\n=== EMAIL CHUA LIEN KET FB ===\n"
	content += strings.Join(mw.unlinkedMails, "\n")

	if err := mw.exportToFile([]string{content}, "full_results.txt"); err != nil && err.Error() != "null" {
		walk.MsgBox(mw, messageBoxTitle, fmt.Sprintf(exportErrorMessage, err), walk.MsgBoxIconError)
		return
	}

	walk.MsgBox(mw, messageBoxTitle, "Da xuat toan bo ket qua!", walk.MsgBoxIconInformation)
}

func generateRegInstance() string {
	const charset = "0123456789"
	result := make([]byte, 16)
	for i := range result {
		result[i] = charset[rand.Intn(len(charset))]
	}
	return string(result)
}

func (mw *MyMainWindow) checkEmailWithProxy(email, proxy string) (string, []byte) {
	client := &fasthttp.Client{
		MaxConnsPerHost: 10000,
		ReadTimeout:     5 * time.Second,
		WriteTimeout:    5 * time.Second,
	}

	if proxy != "" {
		formattedProxy := formatProxy(proxy)
		client = &fasthttp.Client{
			MaxConnsPerHost: 10000,
			ReadTimeout:     5 * time.Second,
			WriteTimeout:    5 * time.Second,
			Dial:            fasthttpproxy.FasthttpHTTPDialer(formattedProxy),
		}
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
		return fmt.Sprintf(errorFormat, email, err), nil
	}

	req.SetBody(jsonData)

	if err := client.Do(req, resp); err != nil {
		return fmt.Sprintf(errorFormat, email, err), nil
	}

	responseBody := make([]byte, len(resp.Body()))
	copy(responseBody, resp.Body())

	var resultResponse struct {
		Result bool `json:"result"`
	}
	if err := json.Unmarshal(resp.Body(), &resultResponse); err == nil && resultResponse.Result {
		return fmt.Sprintf("[UNLINKED] %s", email), responseBody
	}

	var fbError struct {
		Error struct {
			Message      string      `json:"message"`
			Type         string      `json:"type"`
			Code         int         `json:"code"`
			ErrorData    interface{} `json:"error_data"`
			ErrorSubcode int         `json:"error_subcode"`
			FbTraceID    string      `json:"fbtrace_id"`
		} `json:"error"`
	}

	if err := json.Unmarshal(resp.Body(), &fbError); err != nil {
		return fmt.Sprintf(errorFormat, email, err), responseBody
	}

	if fbError.Error.Code == 368 || fbError.Error.ErrorSubcode == 1348007 {
		return fmt.Sprintf("[ERROR] %s - Rate limit/Not logged in", email), responseBody
	}

	if fbError.Error.Code == 3116 {
		if errorDataStr, ok := fbError.Error.ErrorData.(string); ok {
			var errorData ErrorData
			if err := json.Unmarshal([]byte(errorDataStr), &errorData); err == nil && errorData.Email.ErrorCode == 3113 {
				return fmt.Sprintf("[LINKED] %s", email), responseBody
			}
		}

		if _, ok := fbError.Error.ErrorData.(map[string]interface{}); ok {
			return fmt.Sprintf("[ERROR] %s - Invalid error_data format", email), responseBody
		}
	}

	return fmt.Sprintf("[UNLINKED] %s", email), responseBody
}

func (mw *MyMainWindow) stopChecking() {
	mw.mutex.Lock()
	if mw.running {
		mw.shouldStop = true
		mw.running = false
		mw.paused = false
		close(mw.stopChan)
		mw.pauseBtn.SetEnabled(false)
		mw.stopBtn.SetEnabled(false)
	}
	mw.mutex.Unlock()
}

func (mw *MyMainWindow) checkEmails() {
	if mw.running {
		return
	}

	mw.linkedMails = make([]string, 0)
	mw.unlinkedMails = make([]string, 0)
	mw.errorMails = make([]string, 0)
	mw.fullResults = make([]string, 0)
	mw.checkResults = make([]CheckResult, 0)
	atomic.StoreInt32(&mw.checkCount, 0)
	mw.startTime = time.Now()
	mw.pauseTime = 0
	mw.paused = false
	mw.running = true
	mw.shouldStop = false
	mw.stopChan = make(chan struct{})
	mw.pauseBtn.SetEnabled(true)
	mw.stopBtn.SetEnabled(true)
	mw.pauseBtn.SetText(pauseButtonText)

	mw.startStatsTimer()

	emails := strings.Split(strings.TrimSpace(mw.emailEdit.Text()), "\n")
	proxies := strings.Split(strings.TrimSpace(mw.proxyEdit.Text()), "\n")

	validEmails := make([]string, 0)
	validProxies := make([]string, 0)

	for _, email := range emails {
		if strings.TrimSpace(email) != "" {
			validEmails = append(validEmails, strings.TrimSpace(email))
		}
	}

	for _, proxy := range proxies {
		if strings.TrimSpace(proxy) != "" {
			validProxies = append(validProxies, strings.TrimSpace(proxy))
		}
	}

	if len(validEmails) == 0 {
		walk.MsgBox(mw, messageBoxTitle, "Vui long nhap danh sach email!", walk.MsgBoxIconInformation)
		return
	}

	mw.resultEdit.SetText("")
	mw.progressBar.SetRange(0, len(validEmails))
	mw.progressBar.SetValue(0)
	mw.statsLabel.SetText("Dang kiem tra...")

	var wg sync.WaitGroup
	results := make(chan string, len(validEmails))
	workerCount := int(mw.threadNumEdit.Value())

	emailChan := make(chan string, len(validEmails))
	proxyIndex := 0

	for i := 0; i < workerCount; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for email := range emailChan {
				if mw.shouldStop {
					return
				}
				for mw.paused {
					if mw.shouldStop {
						return
					}
					time.Sleep(100 * time.Millisecond)
				}

				proxy := ""
				if len(validProxies) > 0 {
					mw.mutex.Lock()
					proxy = validProxies[proxyIndex]
					proxyIndex = (proxyIndex + 1) % len(validProxies)
					mw.mutex.Unlock()
				}
				status, response := mw.checkEmailWithProxy(email, proxy)
				results <- status

				mw.mutex.Lock()
				if strings.Contains(status, "[UNLINKED]") {
					mw.unlinkedMails = append(mw.unlinkedMails, email)
				} else if strings.Contains(status, "[LINKED]") {
					mw.linkedMails = append(mw.linkedMails, email)
				} else if strings.Contains(status, "[ERROR]") {
					mw.errorMails = append(mw.errorMails, email)
				}
				mw.checkResults = append(mw.checkResults, CheckResult{
					Email:    email,
					Status:   status,
					Response: response,
				})
				mw.mutex.Unlock()
			}
		}()
	}

	go func() {
		for _, email := range validEmails {
			emailChan <- email
		}
		close(emailChan)
	}()

	go func() {
		wg.Wait()
		close(results)
	}()

	go func() {
		count := 0
		for result := range results {
			if mw.shouldStop {
				break
			}
			mw.mutex.Lock()
			currentText := mw.resultEdit.Text()
			mw.resultEdit.SetText(currentText + result + "\r\n")
			mw.fullResults = append(mw.fullResults, result)
			count++
			atomic.AddInt32(&mw.checkCount, 1)
			mw.progressBar.SetValue(count)
			mw.mutex.Unlock()
		}
		mw.running = false
		mw.pauseBtn.SetEnabled(false)
		mw.stopBtn.SetEnabled(false)
		if !mw.shouldStop {
			close(mw.stopChan)
		}

		mw.mutex.Lock()
		mw.updateStats()
		mw.mutex.Unlock()
	}()
}

func main() {
	mw := &MyMainWindow{}

	if err := (declarative.MainWindow{
		AssignTo: &mw.MainWindow,
		Title:    "Mail Linked Checker",
		MinSize:  declarative.Size{Width: windowWidth, Height: windowHeight},
		MaxSize:  declarative.Size{Width: windowWidth, Height: windowHeight},
		Layout:   declarative.VBox{MarginsZero: true},
		Visible:  false,
		Children: []declarative.Widget{
			declarative.Composite{
				Layout: declarative.VBox{Margins: declarative.Margins{Left: 5, Top: 5, Right: 5, Bottom: 5}},
				Children: []declarative.Widget{
					declarative.GroupBox{
						Title:  "Danh sach Email (moi email mot dong)",
						Layout: declarative.VBox{},
						Children: []declarative.Widget{
							declarative.TextEdit{
								AssignTo: &mw.emailEdit,
								MinSize:  declarative.Size{Height: 100},
								VScroll:  true,
							},
						},
					},
					declarative.GroupBox{
						Title:  "Danh sach Proxy (tuy chon)",
						Layout: declarative.VBox{},
						Children: []declarative.Widget{
							declarative.TextEdit{
								AssignTo: &mw.proxyEdit,
								MinSize:  declarative.Size{Height: 60},
								VScroll:  true,
							},
						},
					},
					declarative.Composite{
						Layout: declarative.HBox{},
						Children: []declarative.Widget{
							declarative.Label{
								Text: "So luong Thread:",
							},
							declarative.NumberEdit{
								AssignTo: &mw.threadNumEdit,
								Value:    10.0,
								MinValue: 1.0,
								MaxValue: 100.0,
							},
							declarative.PushButton{
								Text:      "Bat dau kiem tra",
								MinSize:   declarative.Size{Width: 100},
								OnClicked: mw.checkEmails,
							},
							declarative.PushButton{
								AssignTo:  &mw.pauseBtn,
								Text:      pauseButtonText,
								Enabled:   false,
								MinSize:   declarative.Size{Width: 80},
								OnClicked: mw.togglePause,
							},
							declarative.PushButton{
								AssignTo:  &mw.stopBtn,
								Text:      "Dung lai",
								Enabled:   false,
								MinSize:   declarative.Size{Width: 80},
								OnClicked: mw.stopChecking,
							},
							declarative.ProgressBar{
								AssignTo: &mw.progressBar,
								MinSize:  declarative.Size{Width: 200},
							},
						},
					},
					declarative.TextLabel{
						AssignTo: &mw.statsLabel,
						Text:     "Chua co du lieu",
						MinSize:  declarative.Size{Height: 20},
					},
					declarative.TextLabel{
						AssignTo: &mw.cpmLabel,
						Text:     "CPM: 0 | Thoi gian: 00:00",
						MinSize:  declarative.Size{Height: 20},
					},
					declarative.TextLabel{
						AssignTo: &mw.errorLabel,
						Text:     "Loi: 0",
						MinSize:  declarative.Size{Height: 20},
					},
					declarative.Composite{
						Layout: declarative.HBox{},
						Children: []declarative.Widget{
							declarative.PushButton{
								AssignTo:  &mw.linkedBtn,
								Text:      "Xuat da lien ket FB",
								MinSize:   declarative.Size{Width: 120},
								OnClicked: mw.exportLinked,
							},
							declarative.PushButton{
								AssignTo:  &mw.unlinkedBtn,
								Text:      "Xuat chua lien ket FB",
								MinSize:   declarative.Size{Width: 120},
								OnClicked: mw.exportUnlinked,
							},
							declarative.PushButton{
								AssignTo:  &mw.errorBtn,
								Text:      "Xuat email loi",
								MinSize:   declarative.Size{Width: 120},
								OnClicked: mw.exportErrors,
							},
							declarative.PushButton{
								AssignTo:  &mw.exportAllBtn,
								Text:      "Xuat toan bo ket qua",
								MinSize:   declarative.Size{Width: 120},
								OnClicked: mw.exportAll,
							},
						},
					},
					declarative.GroupBox{
						Title:  "Ket qua",
						Layout: declarative.VBox{},
						Children: []declarative.Widget{
							declarative.TextEdit{
								AssignTo: &mw.resultEdit,
								ReadOnly: true,
								VScroll:  true,
								MinSize:  declarative.Size{Height: 150},
							},
						},
					},
				},
			},
		},
	}.Create()); err != nil {
		panic(err)
	}

	style := win.GetWindowLong(mw.Handle(), win.GWL_STYLE)
	style &^= win.WS_THICKFRAME | win.WS_MAXIMIZEBOX
	win.SetWindowLong(mw.Handle(), win.GWL_STYLE, style)

	screenWidth := win.GetSystemMetrics(win.SM_CXSCREEN)
	screenHeight := win.GetSystemMetrics(win.SM_CYSCREEN)
	x := (screenWidth - windowWidth) / 2
	y := (screenHeight - windowHeight) / 2

	win.SetWindowPos(
		mw.Handle(),
		0,
		x,
		y,
		windowWidth,
		windowHeight,
		win.SWP_FRAMECHANGED,
	)

	win.ShowWindow(mw.Handle(), win.SW_SHOW)

	mw.SetIcon(walk.IconInformation())
	mw.Run()
}
