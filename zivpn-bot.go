package main

import (
	"archive/zip"
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	tgbotapi "github.com/go-telegram-bot-api/telegram-bot-api/v5"
)

// ==========================================
// Constants & Configuration
// ==========================================

const (
	BotConfigFile = "/etc/zivpn/bot-config.json"
	ApiPortFile   = "/etc/zivpn/api_port"
	ApiKeyFile    = "/etc/zivpn/apikey"
	DomainFile    = "/etc/zivpn/domain"
	PortFile	  = "/etc/zivpn/port"
)

var ApiUrl = "http://127.0.0.1:" + PortFile + "/api"

var ApiKey = "AutoFtBot-agskjgdvsbdreiWG1234512SDKrqw"

type BotConfig struct {
	BotToken  string  `json:"bot_token"`
	OwnerID   int64   `json:"owner_id"`
	AdminIDs  []int64 `json:"admin_ids"`
	ViewerIDs []int64 `json:"viewer_ids"`
	Mode      string  `json:"mode"`   // "public" or "private"
	Domain    string  `json:"domain"` // Domain from setup
}

type IpInfo struct {
	City  string `json:"city"`
	Isp   string `json:"isp"`
	Query string `json:"query"`
}

type UserData struct {
	Password string `json:"password"`
	Expired  string `json:"expired"`
	Status   string `json:"status"`
	IpLimit  int    `json:"ip_limit"`
}

// ==========================================
// Global State
// ==========================================

var userStates = make(map[int64]string)
var tempUserData = make(map[int64]map[string]string)
var lastMessageIDs = make(map[int64]int)

// ==========================================
// Main Entry Point
// ==========================================

func main() {
	// Load API Key
	if keyBytes, err := ioutil.ReadFile(ApiKeyFile); err == nil {
		ApiKey = strings.TrimSpace(string(keyBytes))
	}

	// Load API Port
	if portBytes, err := ioutil.ReadFile(ApiPortFile); err == nil {
		port := strings.TrimSpace(string(portBytes))
		ApiUrl = fmt.Sprintf("http://127.0.0.1:%s/api", port)
	}

	// Load Config
	config, err := loadConfig()
	if err != nil {
		log.Fatal("Gagal memuat konfigurasi bot:", err)
	}

	// Initialize Bot
	bot, err := tgbotapi.NewBotAPI(config.BotToken)
	if err != nil {
		log.Panic(err)
	}

	bot.Debug = false
	log.Printf("Authorized on account %s", bot.Self.UserName)

	u := tgbotapi.NewUpdate(0)
	u.Timeout = 60
	updates := bot.GetUpdatesChan(u)

	// Main Loop
	for update := range updates {
		if update.Message != nil {
			handleMessage(bot, update.Message, &config)
		} else if update.CallbackQuery != nil {
			handleCallback(bot, update.CallbackQuery, &config)
		}
	}
}

// ==========================================
// Telegram Event Handlers
// ==========================================

func handleMessage(bot *tgbotapi.BotAPI, msg *tgbotapi.Message, config *BotConfig) {
	// Access Control
	if !isAllowed(config, msg.From.ID) {
		replyError(bot, msg.Chat.ID, "⛔ Akses Ditolak. Bot ini Private.")
		return
	}

	// Handle Document Upload (Restore)
	if msg.Document != nil && isAdmin(msg.From.ID, config) {
		if state, exists := userStates[msg.From.ID]; exists && state == "waiting_restore_file" {
			processRestoreFile(bot, msg, config)
			return
		}
	}

	// Handle State (User Input)
	if state, exists := userStates[msg.From.ID]; exists {
		handleState(bot, msg, state, config)
		return
	}

	// Handle Commands
	if msg.IsCommand() {
		switch msg.Command() {
		case "start":
			showMainMenu(bot, msg.Chat.ID, config)

		// Owner-only role management
		case "addadmin", "deladmin", "addviewer", "delviewer":
			if !isOwner(msg.From.ID, config) {
				replyError(bot, msg.Chat.ID, "⛔ Hanya owner yang bisa mengubah role.")
				return
			}
			args := strings.TrimSpace(msg.CommandArguments())
			id, err := strconv.ParseInt(args, 10, 64)
			if err != nil {
				replyError(bot, msg.Chat.ID, "Format: /"+msg.Command()+" <telegram_id>")
				return
			}
			switch msg.Command() {
			case "addadmin":
				addUnique(&config.AdminIDs, id)
				replyInfo(bot, msg.Chat.ID, "✅ Admin ditambahkan: "+args)
			case "deladmin":
				removeID(&config.AdminIDs, id)
				replyInfo(bot, msg.Chat.ID, "✅ Admin dihapus: "+args)
			case "addviewer":
				addUnique(&config.ViewerIDs, id)
				replyInfo(bot, msg.Chat.ID, "✅ Viewer ditambahkan: "+args)
			case "delviewer":
				removeID(&config.ViewerIDs, id)
				replyInfo(bot, msg.Chat.ID, "✅ Viewer dihapus: "+args)
			}
			_ = saveConfig(config)
			return

		case "scheduler":
			if !isAdmin(msg.From.ID, config) {
				replyError(bot, msg.Chat.ID, "⛔ Akses ditolak.")
				return
			}
			showSchedulerMenu(bot, msg.Chat.ID, config)

		case "alerts":
			if !isAdmin(msg.From.ID, config) {
				replyError(bot, msg.Chat.ID, "⛔ Akses ditolak.")
				return
			}
			showAlertsMenu(bot, msg.Chat.ID, config)

		case "security":
			if !isAdmin(msg.From.ID, config) {
				replyError(bot, msg.Chat.ID, "⛔ Akses ditolak.")
				return
			}
			showSecurityMenu(bot, msg.Chat.ID, config)

		case "stats":
			if !isAdmin(msg.From.ID, config) {
				replyError(bot, msg.Chat.ID, "⛔ Akses ditolak.")
				return
			}
			showStatsMenu(bot, msg.Chat.ID, config)

		case "bindreset":
			if !isAdmin(msg.From.ID, config) {
				replyError(bot, msg.Chat.ID, "⛔ Akses ditolak.")
				return
			}
			u := strings.TrimSpace(msg.CommandArguments())
			if u == "" {
				replyError(bot, msg.Chat.ID, "Format: /bindreset <username>")
				return
			}
			exec.Command("/usr/local/bin/zivpn-security.sh", "device-reset", u).Run()
			replyInfo(bot, msg.Chat.ID, "✅ Binding direset untuk: "+u)

		default:
			replyError(bot, msg.Chat.ID, "Perintah tidak dikenal.")
		}
	}


func handleCallback(bot *tgbotapi.BotAPI, query *tgbotapi.CallbackQuery, config *BotConfig) {
	// Access Control (Special case for toggle_mode)
	if !isAllowed(config, query.From.ID) {
		if query.Data != "toggle_mode" || !isOwner(query.From.ID, config) {
			bot.Request(tgbotapi.NewCallback(query.ID, "Akses Ditolak"))
			return
		}
	}

	chatID := query.Message.Chat.ID
	userID := query.From.ID

	switch {
	// --- Menu Navigation ---
	case query.Data == "main_menu":
		showMainMenu(bot, chatID, config)
	case query.Data == "menu_create":
		startCreateUser(bot, chatID, userID)
	case query.Data == "menu_delete":
		showUserSelection(bot, chatID, 1, "delete")
	case query.Data == "menu_renew":
		showUserSelection(bot, chatID, 1, "renew")
	case query.Data == "menu_list":
		if isAdmin(userID, config) {
			listUsers(bot, chatID)
		}
	case query.Data == "menu_info":
		if isAllowed(config, userID) {
			systemInfo(bot, chatID, config)
		}
	case query.Data == "menu_online":
		if isAllowed(config, userID) {
			showOnlineAccounts(bot, chatID, config)
		}
	case query.Data == "menu_security":
		if isAdmin(userID, config) {
			showSecurityMenu(bot, chatID, config)
		}
	case query.Data == "menu_stats":
		if isAdmin(userID, config) {
			showStatsMenu(bot, chatID, config)
		}
	case strings.HasPrefix(query.Data, "security_"):
		if isAdmin(userID, config) {
			handleSecurityCallback(bot, chatID, query.Data, config)
		}
	case strings.HasPrefix(query.Data, "stats_"):
		if isAdmin(userID, config) {
			handleStatsCallback(bot, chatID, query.Data, config)
		}
	case query.Data == "menu_iplimit":
		if isAdmin(userID, config) {
			showIPLimitMenu(bot, chatID, config)
		}
	case query.Data == "iplimit_set_1":
		if isAdmin(userID, config) {
			setIPLimit(bot, chatID, config, 1)
		}
	case query.Data == "iplimit_set_2":
		if isAdmin(userID, config) {
			setIPLimit(bot, chatID, config, 2)
		}
	case query.Data == "menu_backup_restore":
		if isAdmin(userID, config) {
			showBackupRestoreMenu(bot, chatID)
		}
	case query.Data == "menu_alerts":
		if isAdmin(userID, config) {
			showAlertsMenu(bot, chatID, config)
		}
	case query.Data == "menu_scheduler":
		if isAdmin(userID, config) {
			showSchedulerMenu(bot, chatID, config)
		}
	case query.Data == "menu_roles":
		if isOwner(userID, config) {
			showRolesMenu(bot, chatID, config)
		}

	case query.Data == "menu_backup_action":
		if isAdmin(userID, config) {
			performBackup(bot, chatID)
		}
	case query.Data == "menu_restore_action":
		if isAdmin(userID, config) {
			startRestore(bot, chatID, userID)
		}
	case query.Data == "alerts_toggle":
		if isAdmin(userID, config) {
			toggleAlerts(bot, chatID)
		}
	case strings.HasPrefix(query.Data, "sched_"):
		if isAdmin(userID, config) {
			handleSchedulerCallback(bot, chatID, query.Data)
		}
	case strings.HasPrefix(query.Data, "role_"):
		if isOwner(userID, config) {
			handleRoleCallback(bot, chatID, query.Data, config)
		}

	case query.Data == "cancel":
		cancelOperation(bot, chatID, userID, config)

	// --- Pagination ---
	case strings.HasPrefix(query.Data, "page_"):
		handlePagination(bot, chatID, query.Data)

	// --- Action Selection ---
	case strings.HasPrefix(query.Data, "select_renew:"):
		startRenewUser(bot, chatID, userID, query.Data)
	case strings.HasPrefix(query.Data, "select_delete:"):
		confirmDeleteUser(bot, chatID, query.Data)

	// --- Action Confirmation ---
	case strings.HasPrefix(query.Data, "confirm_delete:"):
		username := strings.TrimPrefix(query.Data, "confirm_delete:")
		deleteUser(bot, chatID, username, config)

	// --- Admin Actions ---
	case query.Data == "toggle_mode":
		if !isOwner(userID, config) {
			replyError(bot, chatID, "⛔ Hanya owner yang bisa mengganti mode.")
			return
		}
		toggleMode(bot, chatID, userID, config)
	}

	bot.Request(tgbotapi.NewCallback(query.ID, ""))
}

func handleState(bot *tgbotapi.BotAPI, msg *tgbotapi.Message, state string, config *BotConfig) {
	userID := msg.From.ID
	text := strings.TrimSpace(msg.Text)
	chatID := msg.Chat.ID

	switch state {
	case "create_username":
		if !validateUsername(bot, chatID, text) {
			return
		}
		tempUserData[userID]["username"] = text
		userStates[userID] = "create_days"
		sendMessage(bot, chatID, "⏳ Masukkan Durasi (hari):")

	case "create_days":
		_, ok := validateNumber(bot, chatID, text, 1, 9999, "Durasi")
		if !ok {
			return
		}
		tempUserData[userID]["days"] = text
		
		days, _ := strconv.Atoi(text)
		createUser(bot, chatID, tempUserData[userID]["username"], days, config)
		resetState(userID)

	case "renew_days":
		days, ok := validateNumber(bot, chatID, text, 1, 9999, "Durasi")
		if !ok {
			return
		}
		renewUser(bot, chatID, tempUserData[userID]["username"], days, config)
		resetState(userID)
	}
}

// ==========================================
// Feature Implementation
// ==========================================

func startCreateUser(bot *tgbotapi.BotAPI, chatID int64, userID int64) {
	userStates[userID] = "create_username"
	tempUserData[userID] = make(map[string]string)
	sendMessage(bot, chatID, "👤 Masukkan Password:")
}

func startRenewUser(bot *tgbotapi.BotAPI, chatID int64, userID int64, data string) {
	username := strings.TrimPrefix(data, "select_renew:")
	tempUserData[userID] = map[string]string{"username": username}
	userStates[userID] = "renew_days"
	sendMessage(bot, chatID, fmt.Sprintf("🔄 Renewing %s\n⏳ Masukkan Tambahan Durasi (hari):", username))
}

func confirmDeleteUser(bot *tgbotapi.BotAPI, chatID int64, data string) {
	username := strings.TrimPrefix(data, "select_delete:")
	msg := tgbotapi.NewMessage(chatID, fmt.Sprintf("❓ Yakin ingin menghapus user `%s`?", username))
	msg.ParseMode = "Markdown"
	msg.ReplyMarkup = tgbotapi.NewInlineKeyboardMarkup(
		tgbotapi.NewInlineKeyboardRow(
			tgbotapi.NewInlineKeyboardButtonData("✅ Ya, Hapus", "confirm_delete:"+username),
			tgbotapi.NewInlineKeyboardButtonData("❌ Batal", "cancel"),
		),
	)
	sendAndTrack(bot, msg)
}

func cancelOperation(bot *tgbotapi.BotAPI, chatID int64, userID int64, config *BotConfig) {
	resetState(userID)
	showMainMenu(bot, chatID, config)
}

func handlePagination(bot *tgbotapi.BotAPI, chatID int64, data string) {
	parts := strings.Split(data, ":")
	action := parts[0][5:] // remove "page_"
	page, _ := strconv.Atoi(parts[1])
	showUserSelection(bot, chatID, page, action)
}

func toggleMode(bot *tgbotapi.BotAPI, chatID int64, userID int64, config *BotConfig) {
	if !isOwner(userID, config) {
		return
	}
	if config.Mode == "public" {
		config.Mode = "private"
	} else {
		config.Mode = "public"
	}
	saveConfig(config)
	showMainMenu(bot, chatID, config)
}

func createUser(bot *tgbotapi.BotAPI, chatID int64, username string, days int, config *BotConfig) {
	res, err := apiCall("POST", "/user/create", map[string]interface{}{
		"password": username,
		"days":     days,
	})

	if err != nil {
		replyError(bot, chatID, "Error API: "+err.Error())
		return
	}

	if res["success"] == true {
		data := res["data"].(map[string]interface{})
		sendAccountInfo(bot, chatID, data, config)
	} else {
		replyError(bot, chatID, fmt.Sprintf("Gagal: %s", res["message"]))
		showMainMenu(bot, chatID, config)
	}
}

func renewUser(bot *tgbotapi.BotAPI, chatID int64, username string, days int, config *BotConfig) {
	res, err := apiCall("POST", "/user/renew", map[string]interface{}{
		"password": username,
		"days":     days,
	})

	if err != nil {
		replyError(bot, chatID, "Error API: "+err.Error())
		return
	}

	if res["success"] == true {
		data := res["data"].(map[string]interface{})
		// For renew, we might not have the limit handy, so passing 0 or fetching it would be ideal.
		// But for now, let's just display what we have.
		sendAccountInfo(bot, chatID, data, config)
	} else {
		replyError(bot, chatID, fmt.Sprintf("Gagal: %s", res["message"]))
		showMainMenu(bot, chatID, config)
	}
}

func deleteUser(bot *tgbotapi.BotAPI, chatID int64, username string, config *BotConfig) {
	res, err := apiCall("POST", "/user/delete", map[string]interface{}{
		"password": username,
	})

	if err != nil {
		replyError(bot, chatID, "Error API: "+err.Error())
		return
	}

	if res["success"] == true {
		msg := tgbotapi.NewMessage(chatID, "✅ Password berhasil dihapus.")
		deleteLastMessage(bot, chatID)
		bot.Send(msg)
		showMainMenu(bot, chatID, config)
	} else {
		replyError(bot, chatID, fmt.Sprintf("Gagal: %s", res["message"]))
		showMainMenu(bot, chatID, config)
	}
}

func listUsers(bot *tgbotapi.BotAPI, chatID int64) {
	res, err := apiCall("GET", "/users", nil)
	if err != nil {
		replyError(bot, chatID, "Error API: "+err.Error())
		return
	}

	if res["success"] == true {
		users := res["data"].([]interface{})
		if len(users) == 0 {
			sendMessage(bot, chatID, "📂 Tidak ada user.")
			return
		}

		msg := "📋 *List Passwords*\n"
		for _, u := range users {
			user := u.(map[string]interface{})
			status := "🟢"
			if user["status"] == "Expired" {
				status = "🔴"
			}
			msg += fmt.Sprintf("\n%s `%s` (%s)", status, user["password"], user["expired"])
		}

		reply := tgbotapi.NewMessage(chatID, msg)
		reply.ParseMode = "Markdown"
		sendAndTrack(bot, reply)
	} else {
		replyError(bot, chatID, "Gagal mengambil data.")
	}
}

func systemInfo(bot *tgbotapi.BotAPI, chatID int64, config *BotConfig) {
	res, err := apiCall("GET", "/info", nil)
	if err != nil {
		replyError(bot, chatID, "Error API: "+err.Error())
		return
	}

	if res["success"] == true {
		data := res["data"].(map[string]interface{})

		domain := fmt.Sprintf("%v", data["domain"])
		ipv4 := fmt.Sprintf("%v", data["public_ipv4"])
		ipv6 := fmt.Sprintf("%v", data["public_ipv6"])
		priv := fmt.Sprintf("%v", data["private_ip"])
		port := fmt.Sprintf("%v", data["port"])
		svc := fmt.Sprintf("%v", data["service"])
		osName := fmt.Sprintf("%v", data["os"])
		uptime := fmt.Sprintf("%v", data["uptime"])
		load := fmt.Sprintf("%v", data["loadavg"])
		cpu := fmt.Sprintf("%v", data["cpu"])
		ramUsed := fmt.Sprintf("%v", data["ram_used"])
		ramTotal := fmt.Sprintf("%v", data["ram_total"])
		diskUsed := fmt.Sprintf("%v", data["disk_used"])
		diskTotal := fmt.Sprintf("%v", data["disk_total"])
		diskAvail := fmt.Sprintf("%v", data["disk_avail"])
		ipLimit := fmt.Sprintf("%v", data["iplimit"])

		msg := fmt.Sprintf("```\n━━━━━━━━━━━━━━━━━━━━━━\n      ZIVPN SYSTEM\n━━━━━━━━━━━━━━━━━━━━━━\nDomain        : %s\nService       : %s\nPort          : %s\nPublic IPv4   : %s\nPublic IPv6   : %s\nPrivate IP    : %s\nIP Limit      : %s IP\n━━━━━━━━━━━━━━━━━━━━━━\nOS            : %s\nUptime        : %s\nLoad Avg      : %s\nCPU           : %s\nRAM           : %s / %s\nDisk          : %s / %s (Free %s)\n━━━━━━━━━━━━━━━━━━━━━━\n```",
			domain, svc, port, ipv4, ipv6, priv, ipLimit, osName, uptime, load, cpu, ramUsed, ramTotal, diskUsed, diskTotal, diskAvail)

		reply := tgbotapi.NewMessage(chatID, msg)
		reply.ParseMode = "Markdown"
		deleteLastMessage(bot, chatID)
		bot.Send(reply)
		showMainMenu(bot, chatID, config)
	} else {
		replyError(bot, chatID, "Gagal mengambil info.")
	}
}


func showOnlineAccounts(bot *tgbotapi.BotAPI, chatID int64, config *BotConfig) {
	res, err := apiCall("GET", "/online", nil)
	if err != nil {
		replyError(bot, chatID, "Error API: "+err.Error())
		return
	}

	if res["success"] == true {
		data := res["data"].(map[string]interface{})
		total := int(data["total_users"].(float64))
		users := data["users"].([]interface{})

		var b strings.Builder
		b.WriteString("```\n━━━━━━━━━━━━━━━━━━━━━━\n     ONLINE ACCOUNTS\n━━━━━━━━━━━━━━━━━━━━━━\n")
		b.WriteString(fmt.Sprintf("Total Online : %d\n", total))
		b.WriteString("━━━━━━━━━━━━━━━━━━━━━━\n")

		if total == 0 {
			b.WriteString("Tidak ada user online.\n")
		} else {
			limit := len(users)
			if limit > 30 {
				limit = 30
			}
			for i := 0; i < limit; i++ {
				u := users[i].(map[string]interface{})
				user := fmt.Sprintf("%v", u["user"])
				ipCount := int(u["ip_count"].(float64))
				sessions := int(u["sessions"].(float64))
				ips := u["ips"].([]interface{})
				ipList := ""
				for j, ip := range ips {
					if j > 1 {
						ipList += " ..."
						break
					}
					if j > 0 {
						ipList += ", "
					}
					ipList += fmt.Sprintf("%v", ip)
				}
				b.WriteString(fmt.Sprintf("%-16s | IP:%d | Ses:%d | %s\n", user, ipCount, sessions, ipList))
			}
			if len(users) > 30 {
				b.WriteString("... (lebih banyak)\n")
			}
		}
		b.WriteString("━━━━━━━━━━━━━━━━━━━━━━\n```")

		reply := tgbotapi.NewMessage(chatID, b.String())
		reply.ParseMode = "Markdown"
		deleteLastMessage(bot, chatID)
		bot.Send(reply)
	} else {
		replyError(bot, chatID, "Gagal mengambil online accounts.")
	}

	showMainMenu(bot, chatID, config)
}

func showIPLimitMenu(bot *tgbotapi.BotAPI, chatID int64, config *BotConfig) {
	res, err := apiCall("GET", "/iplimit", nil)
	if err != nil {
		replyError(bot, chatID, "Error API: "+err.Error())
		return
	}
	current := 1
	if res["success"] == true {
		data := res["data"].(map[string]interface{})
		current = int(data["limit"].(float64))
	}

	msgText := fmt.Sprintf("```\n━━━━━━━━━━━━━━━━━━━━━━\n        IP LIMIT\n━━━━━━━━━━━━━━━━━━━━━━\nLimit saat ini : %d IP\n\nPilih limit baru:\n━━━━━━━━━━━━━━━━━━━━━━\n```", current)

	msg := tgbotapi.NewMessage(chatID, msgText)
	msg.ParseMode = "Markdown"
	msg.ReplyMarkup = tgbotapi.NewInlineKeyboardMarkup(
		tgbotapi.NewInlineKeyboardRow(
			tgbotapi.NewInlineKeyboardButtonData("1 IP", "iplimit_set_1"),
			tgbotapi.NewInlineKeyboardButtonData("2 IP", "iplimit_set_2"),
		),
		tgbotapi.NewInlineKeyboardRow(
			tgbotapi.NewInlineKeyboardButtonData("⬅️ Back", "back_to_menu"),
		),
	)
	sendAndTrack(bot, msg)
}

func setIPLimit(bot *tgbotapi.BotAPI, chatID int64, config *BotConfig, limit int) {
	payload := map[string]interface{}{"limit": limit}
	res, err := apiCall("POST", "/iplimit", payload)
	if err != nil {
		replyError(bot, chatID, "Error API: "+err.Error())
		return
	}
	if res["success"] == true {
		replySuccess(bot, chatID, fmt.Sprintf("IP Limit berhasil diubah menjadi %d IP.", limit))
	} else {
		replyError(bot, chatID, "Gagal mengubah IP Limit.")
	}
	showMainMenu(bot, chatID, config)
}


func showBackupRestoreMenu(bot *tgbotapi.BotAPI, chatID int64) {
	msg := tgbotapi.NewMessage(chatID, "💾 *Backup & Restore*\nSilakan pilih menu:")
	msg.ParseMode = "Markdown"
	msg.ReplyMarkup = tgbotapi.NewInlineKeyboardMarkup(
		tgbotapi.NewInlineKeyboardRow(
			tgbotapi.NewInlineKeyboardButtonData("⬇️ Backup Data", "menu_backup_action"),
			tgbotapi.NewInlineKeyboardButtonData("⬆️ Restore Data", "menu_restore_action"),
		),
		tgbotapi.NewInlineKeyboardRow(
			tgbotapi.NewInlineKeyboardButtonData("❌ Kembali", "cancel"),
		),
	)
	sendAndTrack(bot, msg)
}

func performBackup(bot *tgbotapi.BotAPI, chatID int64) {
	sendMessage(bot, chatID, "⏳ Sedang membuat backup...")

	// Files to backup
	files := []string{
		"/etc/zivpn/config.json",
		"/etc/zivpn/users.json",
		"/etc/zivpn/domain",
	}

	buf := new(bytes.Buffer)
	zipWriter := zip.NewWriter(buf)

	for _, file := range files {
		if _, err := os.Stat(file); os.IsNotExist(err) {
			continue
		}

		f, err := os.Open(file)
		if err != nil {
			continue
		}
		defer f.Close()

		w, err := zipWriter.Create(filepath.Base(file))
		if err != nil {
			continue
		}

		if _, err := io.Copy(w, f); err != nil {
			continue
		}
	}

	zipWriter.Close()

	fileName := fmt.Sprintf("zivpn-backup-%s.zip", time.Now().Format("20060102-150405"))
	
	// Create a temporary file for the upload
	tmpFile := "/tmp/" + fileName
	if err := ioutil.WriteFile(tmpFile, buf.Bytes(), 0644); err != nil {
		replyError(bot, chatID, "Gagal membuat file backup.")
		return
	}
	defer os.Remove(tmpFile)

	doc := tgbotapi.NewDocument(chatID, tgbotapi.FilePath(tmpFile))
	doc.Caption = "✅ Backup Data ZiVPN"
	
	deleteLastMessage(bot, chatID)
	bot.Send(doc)
}

func startRestore(bot *tgbotapi.BotAPI, chatID int64, userID int64) {
	userStates[userID] = "waiting_restore_file"
	sendMessage(bot, chatID, "⬆️ *Restore Data*\n\nSilakan kirim file ZIP backup Anda sekarang.\n\n⚠️ PERINGATAN: Data saat ini akan ditimpa!")
}

func processRestoreFile(bot *tgbotapi.BotAPI, msg *tgbotapi.Message, config *BotConfig) {
	chatID := msg.Chat.ID
	userID := msg.From.ID
	
	resetState(userID)
	sendMessage(bot, chatID, "⏳ Sedang memproses file...")

	// Download file
	fileID := msg.Document.FileID
	file, err := bot.GetFile(tgbotapi.FileConfig{FileID: fileID})
	if err != nil {
		replyError(bot, chatID, "Gagal mengunduh file.")
		return
	}

	fileUrl := file.Link(config.BotToken)
	resp, err := http.Get(fileUrl)
	if err != nil {
		replyError(bot, chatID, "Gagal mengunduh file content.")
		return
	}
	defer resp.Body.Close()

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		replyError(bot, chatID, "Gagal membaca file.")
		return
	}

	// Unzip
	zipReader, err := zip.NewReader(bytes.NewReader(body), int64(len(body)))
	if err != nil {
		replyError(bot, chatID, "File bukan format ZIP yang valid.")
		return
	}

	for _, f := range zipReader.File {
		// Security check: only allow specific files
		validFiles := map[string]bool{
			"config.json": true,
			"users.json": true,
			"bot-config.json": true,
			"domain": true,
			"apikey": true,
		}
		
		if !validFiles[f.Name] {
			continue
		}

		rc, err := f.Open()
		if err != nil {
			continue
		}
		defer rc.Close()

		dstPath := filepath.Join("/etc/zivpn", f.Name)
		dst, err := os.Create(dstPath)
		if err != nil {
			continue
		}
		defer dst.Close()

		io.Copy(dst, rc)
	}

	// Restart Services
	exec.Command("systemctl", "restart", "zivpn").Run()
	exec.Command("systemctl", "restart", "zivpn-api").Run()
	
	msgSuccess := tgbotapi.NewMessage(chatID, "✅ Restore Berhasil!\nService ZiVPN, API, dan Bot telah direstart.")
	bot.Send(msgSuccess)
	
	// Restart Bot with delay to allow message sending
	go func() {
		time.Sleep(2 * time.Second)
		exec.Command("systemctl", "restart", "zivpn-bot").Run()
	}()

	showMainMenu(bot, chatID, config)
}

// ==========================================
// UI & Helpers
// ==========================================

func showMainMenu(bot *tgbotapi.BotAPI, chatID int64, config *BotConfig) {
	ipInfo, _ := getIpInfo()
	domain := config.Domain
	if domain == "" {
		domain = "(Not Configured)"
	}

	msgText := fmt.Sprintf("```\n━━━━━━━━━━━━━━━━━━━━━\n    MENU ZIVPN UDP\n━━━━━━━━━━━━━━━━━━━━━\n • Domain   : %s\n • City     : %s\n • ISP      : %s\n━━━━━━━━━━━━━━━━━━━━━\n```\n👇 Silakan pilih menu dibawah ini:", domain, ipInfo.City, ipInfo.Isp)

	msg := tgbotapi.NewMessage(chatID, msgText)
	msg.ParseMode = "Markdown"
	msg.ReplyMarkup = getMainMenuKeyboard(config, chatID)
	sendAndTrack(bot, msg)
}

func getMainMenuKeyboard(config *BotConfig, userID int64) tgbotapi.InlineKeyboardMarkup {
	rows := [][]tgbotapi.InlineKeyboardButton{}

	// PUBLIC: everyone can manage accounts
	if config.Mode == "public" {
		rows = append(rows, tgbotapi.NewInlineKeyboardRow(
			tgbotapi.NewInlineKeyboardButtonData("👤 Create Password", "menu_create"),
			tgbotapi.NewInlineKeyboardButtonData("🗑️ Delete Password", "menu_delete"),
		))
		rows = append(rows, tgbotapi.NewInlineKeyboardRow(
			tgbotapi.NewInlineKeyboardButtonData("🔄 Renew Password", "menu_renew"),
		))
	}

	// PRIVATE: only Admin/Owner can manage accounts
	if config.Mode != "public" && isAdmin(userID, config) {
		rows = append(rows, tgbotapi.NewInlineKeyboardRow(
			tgbotapi.NewInlineKeyboardButtonData("👤 Create Password", "menu_create"),
			tgbotapi.NewInlineKeyboardButtonData("🗑️ Delete Password", "menu_delete"),
		))
		rows = append(rows, tgbotapi.NewInlineKeyboardRow(
			tgbotapi.NewInlineKeyboardButtonData("🔄 Renew Password", "menu_renew"),
		))
	}

	// Viewer/Admin menu (read-only allowed)
	if config.Mode == "public" || isViewer(userID, config) {
		rows = append(rows, tgbotapi.NewInlineKeyboardRow(
			tgbotapi.NewInlineKeyboardButtonData("📊 System Info", "menu_info"),
			tgbotapi.NewInlineKeyboardButtonData("🟢 Online Accounts", "menu_online"),
		))
	}

	// Admin menu
	if isAdmin(userID, config) {
		rows = append(rows, tgbotapi.NewInlineKeyboardRow(
			tgbotapi.NewInlineKeyboardButtonData("🌐 IP Limit", "menu_iplimit"),
			tgbotapi.NewInlineKeyboardButtonData("💾 Backup & Restore", "menu_backup_restore"),
		))
		rows = append(rows, tgbotapi.NewInlineKeyboardRow(
			tgbotapi.NewInlineKeyboardButtonData("🛡️ Security", "menu_security"),
			tgbotapi.NewInlineKeyboardButtonData("📈 Daily Stats", "menu_stats"),
		))
		rows = append(rows, tgbotapi.NewInlineKeyboardRow(
			tgbotapi.NewInlineKeyboardButtonData("🔔 Live Alerts", "menu_alerts"),
			tgbotapi.NewInlineKeyboardButtonData("⏱ Scheduler", "menu_scheduler"),
		))
	}

	// Owner menu
	if isOwner(userID, config) {
		modeLabel := "🔐 Mode: Private"
		if config.Mode == "public" {
			modeLabel = "🌐 Mode: Public"
		}
		rows = append(rows, tgbotapi.NewInlineKeyboardRow(
			tgbotapi.NewInlineKeyboardButtonData(modeLabel, "toggle_mode"),
		))
		rows = append(rows, tgbotapi.NewInlineKeyboardRow(
			tgbotapi.NewInlineKeyboardButtonData("👥 Manage Roles", "menu_roles"),
		))
	}

	return tgbotapi.NewInlineKeyboardMarkup(rows...)
}

func sendAccountInfo(bot *tgbotapi.BotAPI, chatID int64, data map[string]interface{}, config *BotConfig) {
	ipInfo, _ := getIpInfo()
	domain := config.Domain
	if domain == "" {
		domain = "(Not Configured)"
	}

	msg := fmt.Sprintf("```\n━━━━━━━━━━━━━━━━━━━━━\n  ACCOUNT ZIVPN UDP\n━━━━━━━━━━━━━━━━━━━━━\nPassword   : %s\nCITY       : %s\nISP        : %s\nIP ISP     : %s\nDomain     : %s\nExpired On : %s\n━━━━━━━━━━━━━━━━━━━━━\n```",
		data["password"],
		ipInfo.City,
		ipInfo.Isp,
		ipInfo.Query,
		domain,
		data["expired"],
	)

	reply := tgbotapi.NewMessage(chatID, msg)
	reply.ParseMode = "Markdown"
	deleteLastMessage(bot, chatID)
	bot.Send(reply)
	showMainMenu(bot, chatID, config)
}

func showUserSelection(bot *tgbotapi.BotAPI, chatID int64, page int, action string) {
	users, err := getUsers()
	if err != nil {
		replyError(bot, chatID, "Gagal mengambil data user.")
		return
	}

	if len(users) == 0 {
		sendMessage(bot, chatID, "📂 Tidak ada user.")
		return
	}

	perPage := 10
	totalPages := (len(users) + perPage - 1) / perPage

	if page < 1 {
		page = 1
	}
	if page > totalPages {
		page = totalPages
	}

	start := (page - 1) * perPage
	end := start + perPage
	if end > len(users) {
		end = len(users)
	}

	var rows [][]tgbotapi.InlineKeyboardButton
	for _, u := range users[start:end] {
		label := fmt.Sprintf("%s (%s)", u.Password, u.Status)
		if u.Status == "Expired" {
			label = fmt.Sprintf("🔴 %s", label)
		} else {
			label = fmt.Sprintf("🟢 %s", label)
		}
		data := fmt.Sprintf("select_%s:%s", action, u.Password)
		rows = append(rows, tgbotapi.NewInlineKeyboardRow(
			tgbotapi.NewInlineKeyboardButtonData(label, data),
		))
	}

	var navRow []tgbotapi.InlineKeyboardButton
	if page > 1 {
		navRow = append(navRow, tgbotapi.NewInlineKeyboardButtonData("⬅️ Prev", fmt.Sprintf("page_%s:%d", action, page-1)))
	}
	if page < totalPages {
		navRow = append(navRow, tgbotapi.NewInlineKeyboardButtonData("Next ➡️", fmt.Sprintf("page_%s:%d", action, page+1)))
	}
	if len(navRow) > 0 {
		rows = append(rows, navRow)
	}

	rows = append(rows, tgbotapi.NewInlineKeyboardRow(tgbotapi.NewInlineKeyboardButtonData("❌ Batal", "cancel")))

	msg := tgbotapi.NewMessage(chatID, fmt.Sprintf("📋 Pilih User untuk %s (Halaman %d/%d):", strings.Title(action), page, totalPages))
	msg.ReplyMarkup = tgbotapi.NewInlineKeyboardMarkup(rows...)
	sendAndTrack(bot, msg)
}

func sendMessage(bot *tgbotapi.BotAPI, chatID int64, text string) {
	msg := tgbotapi.NewMessage(chatID, text)
	if _, inState := userStates[chatID]; inState {
		cancelKb := tgbotapi.NewInlineKeyboardMarkup(
			tgbotapi.NewInlineKeyboardRow(tgbotapi.NewInlineKeyboardButtonData("❌ Batal", "cancel")),
		)
		msg.ReplyMarkup = cancelKb
	}
	sendAndTrack(bot, msg)
}

func replyError(bot *tgbotapi.BotAPI, chatID int64, text string) {
	sendMessage(bot, chatID, "❌ "+text)
}

func sendAndTrack(bot *tgbotapi.BotAPI, msg tgbotapi.MessageConfig) {
	deleteLastMessage(bot, msg.ChatID)
	sentMsg, err := bot.Send(msg)
	if err == nil {
		lastMessageIDs[msg.ChatID] = sentMsg.MessageID
	}
}

func deleteLastMessage(bot *tgbotapi.BotAPI, chatID int64) {
	if msgID, ok := lastMessageIDs[chatID]; ok {
		deleteMsg := tgbotapi.NewDeleteMessage(chatID, msgID)
		bot.Request(deleteMsg)
		delete(lastMessageIDs, chatID)
	}
}

func resetState(userID int64) {
	delete(userStates, userID)
	delete(tempUserData, userID)
}

// ==========================================
// Validation Helpers
// ==========================================

func validateUsername(bot *tgbotapi.BotAPI, chatID int64, text string) bool {
	if len(text) < 3 || len(text) > 20 {
		sendMessage(bot, chatID, "❌ Password harus 3-20 karakter. Coba lagi:")
		return false
	}
	if !regexp.MustCompile(`^[a-zA-Z0-9_-]+$`).MatchString(text) {
		sendMessage(bot, chatID, "❌ Password hanya boleh huruf, angka, - dan _. Coba lagi:")
		return false
	}
	return true
}

func validateNumber(bot *tgbotapi.BotAPI, chatID int64, text string, min, max int, fieldName string) (int, bool) {
	val, err := strconv.Atoi(text)
	if err != nil || val < min || val > max {
		sendMessage(bot, chatID, fmt.Sprintf("❌ %s harus angka positif (%d-%d). Coba lagi:", fieldName, min, max))
		return 0, false
	}
	return val, true
}

// ==========================================
// Configuration & Utils
// ==========================================

func isOwner(userID int64, config *BotConfig) bool {
	return userID == config.OwnerID
}

func isAdmin(userID int64, config *BotConfig) bool {
	if isOwner(userID, config) {
		return true
	}
	for _, id := range config.AdminIDs {
		if userID == id {
			return true
		}
	}
	return false
}

func isViewer(userID int64, config *BotConfig) bool {
	if isAdmin(userID, config) {
		return true
	}
	for _, id := range config.ViewerIDs {
		if userID == id {
			return true
		}
	}
	return false
}

func isAllowed(config *BotConfig, userID int64) bool {
	return config.Mode == "public" || isViewer(userID, config)
}


func saveConfig(config *BotConfig) error {
	data, err := json.MarshalIndent(config, "", "  ")
	if err != nil {
		return err
	}
	return ioutil.WriteFile(BotConfigFile, data, 0644)
}

func loadConfig() (BotConfig, error) {
	var config BotConfig
	file, err := ioutil.ReadFile(BotConfigFile)
	if err != nil {
		return config, err
	}
	err = json.Unmarshal(file, &config)

	// Jika domain kosong di config, coba baca dari file domain
	if config.Domain == "" {
		if domainBytes, err := ioutil.ReadFile(DomainFile); err == nil {
			config.Domain = strings.TrimSpace(string(domainBytes))
		}
	}

	return config, err
}

// ==========================================
// API Client
// ==========================================

func apiCall(method, endpoint string, payload interface{}) (map[string]interface{}, error) {
	var reqBody []byte
	var err error

	if payload != nil {
		reqBody, err = json.Marshal(payload)
		if err != nil {
			return nil, err
		}
	}

	client := &http.Client{}
	req, err := http.NewRequest(method, ApiUrl+endpoint, bytes.NewBuffer(reqBody))
	if err != nil {
		return nil, err
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-API-Key", ApiKey)

	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, _ := ioutil.ReadAll(resp.Body)
	var result map[string]interface{}
	json.Unmarshal(body, &result)

	return result, nil
}

func getIpInfo() (IpInfo, error) {
	resp, err := http.Get("http://ip-api.com/json/")
	if err != nil {
		return IpInfo{}, err
	}
	defer resp.Body.Close()

	var info IpInfo
	if err := json.NewDecoder(resp.Body).Decode(&info); err != nil {
		return IpInfo{}, err
	}
	return info, nil
}

func getUsers() ([]UserData, error) {
	res, err := apiCall("GET", "/users", nil)
	if err != nil {
		return nil, err
	}

	if res["success"] != true {
		return nil, fmt.Errorf("failed to get users")
	}

	var users []UserData
	dataBytes, _ := json.Marshal(res["data"])
	json.Unmarshal(dataBytes, &users)
	return users, nil
}


// ==========================================
// v1.4 - Live Alerts + Scheduler Center
// ==========================================

const (
	SchedulerConfigFile = "/etc/zivpn/scheduler.json"
	AlertsCronFile      = "/etc/cron.d/zivpn-alerts"
	SchedulerCronFile   = "/etc/cron.d/zivpn-scheduler"
)

type SchedulerConfig struct {
	AlertsEnabled bool   `json:"alerts_enabled"`
	ExpireEnabled bool   `json:"expire_enabled"`
	ExpireTime    string `json:"expire_time"`  // HH:MM
	CleanupEnabled bool  `json:"cleanup_enabled"`
	CleanupTime   string `json:"cleanup_time"` // HH:MM
	BackupEnabled bool   `json:"backup_enabled"`
	BackupTime    string `json:"backup_time"`  // HH:MM
}

func defaultSchedulerConfig() SchedulerConfig {
	return SchedulerConfig{
		AlertsEnabled: true,
		ExpireEnabled: true,
		ExpireTime:    "00:00",
		CleanupEnabled: true,
		CleanupTime:   "00:30",
		BackupEnabled: false,
		BackupTime:    "01:00",
	}
}

func loadSchedulerConfig() SchedulerConfig {
	cfg := defaultSchedulerConfig()
	b, err := ioutil.ReadFile(SchedulerConfigFile)
	if err != nil {
		return cfg
	}
	_ = json.Unmarshal(b, &cfg)
	if cfg.ExpireTime == "" { cfg.ExpireTime = "00:00" }
	if cfg.CleanupTime == "" { cfg.CleanupTime = "00:30" }
	if cfg.BackupTime == "" { cfg.BackupTime = "01:00" }
	return cfg
}

func saveSchedulerConfig(cfg SchedulerConfig) error {
	b, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil { return err }
	return ioutil.WriteFile(SchedulerConfigFile, b, 0644)
}

func writeCronFromScheduler(cfg SchedulerConfig) error {
	var lines []string
	lines = append(lines, "# ZiVPN v1.4 Scheduler (auto-generated)")
	if cfg.ExpireEnabled {
		mm, hh := parseHHMM(cfg.ExpireTime)
		lines = append(lines, fmt.Sprintf("%d %d * * * root /usr/local/bin/zivpn-auto-expire.sh >/dev/null 2>&1", mm, hh))
	}
	if cfg.CleanupEnabled {
		mm, hh := parseHHMM(cfg.CleanupTime)
		lines = append(lines, fmt.Sprintf("%d %d * * * root /usr/local/bin/zivpn-auto-cleanup.sh >/dev/null 2>&1", mm, hh))
	}
	if cfg.BackupEnabled {
		mm, hh := parseHHMM(cfg.BackupTime)
		lines = append(lines, fmt.Sprintf("%d %d * * * root /usr/local/bin/zivpn-backup-local.sh >/dev/null 2>&1", mm, hh))
	}

	cronText := strings.Join(lines, "\n") + "\n"
	if err := ioutil.WriteFile(SchedulerCronFile, []byte(cronText), 0644); err != nil {
		return err
	}
	return nil
}

func parseHHMM(s string) (minute int, hour int) {
	parts := strings.Split(strings.TrimSpace(s), ":")
	if len(parts) != 2 {
		return 0, 0
	}
	h, _ := strconv.Atoi(parts[0])
	m, _ := strconv.Atoi(parts[1])
	if h < 0 || h > 23 { h = 0 }
	if m < 0 || m > 59 { m = 0 }
	return m, h
}

func ensureAlertsCron(enabled bool) error {
	if !enabled {
		_ = os.Remove(AlertsCronFile)
		return nil
	}
	cronText := "# ZiVPN v1.4 Live Alerts\n* * * * * root /usr/local/bin/zivpn-alert-check.sh >/dev/null 2>&1\n"
	return ioutil.WriteFile(AlertsCronFile, []byte(cronText), 0644)
}

func showAlertsMenu(bot *tgbotapi.BotAPI, chatID int64, config *BotConfig) {
	s := loadSchedulerConfig()
	status := "OFF"
	if s.AlertsEnabled { status = "ON" }
	text := fmt.Sprintf("🔔 *Live Alerts*\n\nStatus: *%s*\n\nNotifikasi real-time untuk:\n• Overlimit IP\n• IP baru\n• Service down/recover\n• Event auto-expire/cleanup\n\nKlik tombol di bawah untuk toggle.", status)
	msg := tgbotapi.NewMessage(chatID, text)
	msg.ParseMode = "Markdown"
	msg.ReplyMarkup = tgbotapi.NewInlineKeyboardMarkup(
		tgbotapi.NewInlineKeyboardRow(
			tgbotapi.NewInlineKeyboardButtonData("Toggle Alerts", "alerts_toggle"),
			tgbotapi.NewInlineKeyboardButtonData("⬅️ Back", "main_menu"),
		),
	)
	sendAndTrack(bot, msg)
}

func toggleAlerts(bot *tgbotapi.BotAPI, chatID int64) {
	s := loadSchedulerConfig()
	s.AlertsEnabled = !s.AlertsEnabled
	_ = saveSchedulerConfig(s)
	_ = ensureAlertsCron(s.AlertsEnabled)
	_ = writeCronFromScheduler(s)
	status := "OFF"
	if s.AlertsEnabled { status = "ON" }
	replyInfo(bot, chatID, "✅ Live Alerts: "+status)
}

func showSchedulerMenu(bot *tgbotapi.BotAPI, chatID int64, config *BotConfig) {
	s := loadSchedulerConfig()
	_ = writeCronFromScheduler(s)
	_ = ensureAlertsCron(s.AlertsEnabled)

	text := fmt.Sprintf("⏱ *Scheduler Center*\n\n*Auto Expire*: %s (%s)\n*Auto Cleanup*: %s (%s)\n*Backup Local*: %s (%s)\n\nPilih aksi di bawah.",
		onOff(s.ExpireEnabled), s.ExpireTime,
		onOff(s.CleanupEnabled), s.CleanupTime,
		onOff(s.BackupEnabled), s.BackupTime,
	)

	msg := tgbotapi.NewMessage(chatID, text)
	msg.ParseMode = "Markdown"
	msg.ReplyMarkup = schedulerKeyboard(s)
	sendAndTrack(bot, msg)
}

func onOff(b bool) string {
	if b { return "ON" }
	return "OFF"
}

func schedulerKeyboard(s SchedulerConfig) tgbotapi.InlineKeyboardMarkup {
	// Presets (cepat & aman)
	presets := []string{"00:00","00:05","00:30","01:00","06:00","12:00","18:00","23:55"}
	presetButtons := []tgbotapi.InlineKeyboardButton{}
	for i, t := range presets {
		presetButtons = append(presetButtons, tgbotapi.NewInlineKeyboardButtonData(t, "sched_preset:"+t))
		if (i+1)%4 == 0 {
			// new row handled below
		}
	}

	rows := [][]tgbotapi.InlineKeyboardButton{
		tgbotapi.NewInlineKeyboardRow(
			tgbotapi.NewInlineKeyboardButtonData("Toggle Expire", "sched_toggle:expire"),
			tgbotapi.NewInlineKeyboardButtonData("Toggle Cleanup", "sched_toggle:cleanup"),
		),
		tgbotapi.NewInlineKeyboardRow(
			tgbotapi.NewInlineKeyboardButtonData("Toggle Backup", "sched_toggle:backup"),
		),
		tgbotapi.NewInlineKeyboardRow(
			tgbotapi.NewInlineKeyboardButtonData("Set Expire Time", "sched_settarget:expire"),
			tgbotapi.NewInlineKeyboardButtonData("Set Cleanup Time", "sched_settarget:cleanup"),
		),
		tgbotapi.NewInlineKeyboardRow(
			tgbotapi.NewInlineKeyboardButtonData("Set Backup Time", "sched_settarget:backup"),
		),
	}

	// Add presets rows
	for i := 0; i < len(presets); i += 4 {
		end := i+4
		if end > len(presets) { end = len(presets) }
		row := []tgbotapi.InlineKeyboardButton{}
		for _, t := range presets[i:end] {
			row = append(row, tgbotapi.NewInlineKeyboardButtonData(t, "sched_preset:"+t))
		}
		rows = append(rows, row)
	}

	rows = append(rows, tgbotapi.NewInlineKeyboardRow(
		tgbotapi.NewInlineKeyboardButtonData("⬅️ Back", "main_menu"),
	))
	return tgbotapi.NewInlineKeyboardMarkup(rows...)
}

// We store target in memory per chat (simple approach)
var schedTargetByChat = map[int64]string{}

func handleSchedulerCallback(bot *tgbotapi.BotAPI, chatID int64, data string) {
	s := loadSchedulerConfig()

	if strings.HasPrefix(data, "sched_toggle:") {
		target := strings.TrimPrefix(data, "sched_toggle:")
		switch target {
		case "expire":
			s.ExpireEnabled = !s.ExpireEnabled
		case "cleanup":
			s.CleanupEnabled = !s.CleanupEnabled
		case "backup":
			s.BackupEnabled = !s.BackupEnabled
		}
		_ = saveSchedulerConfig(s)
		_ = writeCronFromScheduler(s)
		showSchedulerMenu(bot, chatID, nil)
		return
	}

	if strings.HasPrefix(data, "sched_settarget:") {
		target := strings.TrimPrefix(data, "sched_settarget:")
		schedTargetByChat[chatID] = target
		replyInfo(bot, chatID, "✅ Target di-set: "+target+"\nSekarang pilih salah satu waktu preset.")
		return
	}

	if strings.HasPrefix(data, "sched_preset:") {
		t := strings.TrimPrefix(data, "sched_preset:")
		target := schedTargetByChat[chatID]
		if target == "" { target = "expire" }
		switch target {
		case "expire":
			s.ExpireTime = t
		case "cleanup":
			s.CleanupTime = t
		case "backup":
			s.BackupTime = t
		}
		_ = saveSchedulerConfig(s)
		_ = writeCronFromScheduler(s)
		replyInfo(bot, chatID, fmt.Sprintf("✅ %s time set to %s", target, t))
		showSchedulerMenu(bot, chatID, nil)
		return
	}
}

func showRolesMenu(bot *tgbotapi.BotAPI, chatID int64, config *BotConfig) {
	text := "👥 *Manage Roles*\n\nPerubahan role dilakukan via command (owner only):\n" +
		"`/addadmin <telegram_id>`\n`/deladmin <telegram_id>`\n" +
		"`/addviewer <telegram_id>`\n`/delviewer <telegram_id>`\n\n" +
		"Admin bisa manage akun & scheduler.\nViewer hanya monitoring (System Info & Online Accounts)."

	msg := tgbotapi.NewMessage(chatID, text)
	msg.ParseMode = "Markdown"
	msg.ReplyMarkup = tgbotapi.NewInlineKeyboardMarkup(
		tgbotapi.NewInlineKeyboardRow(
			tgbotapi.NewInlineKeyboardButtonData("⬅️ Back", "main_menu"),
		),
	)
	sendAndTrack(bot, msg)
}

// ==========================================
// Security (Firewall Harden / Torrent / Device Binding)
// ==========================================

func showSecurityMenu(bot *tgbotapi.BotAPI, chatID int64, config *BotConfig) {
	// Quick status via script
	out, _ := exec.Command("/usr/local/bin/zivpn-security.sh", "status").CombinedOutput()
	out2, _ := exec.Command("/usr/local/bin/zivpn-security.sh", "torrent-status").CombinedOutput()
	out3, _ := exec.Command("/usr/local/bin/zivpn-security.sh", "device-status").CombinedOutput()

	text := "🛡️ *Security Center*\n\n" +
		"`Firewall`\n" + "```\n" + string(out) + "```\n" +
		"`Torrent Blocker`\n" + "```\n" + string(out2) + "```\n" +
		"`Device Binding`\n" + "```\n" + string(out3) + "```\n" +
		"\nCatatan: Firewall hardening ini aman (tidak set default DROP).\n"

	msg := tgbotapi.NewMessage(chatID, text)
	msg.ParseMode = "Markdown"
	msg.ReplyMarkup = tgbotapi.NewInlineKeyboardMarkup(
		tgbotapi.NewInlineKeyboardRow(
			tgbotapi.NewInlineKeyboardButtonData("Apply Firewall", "security_firewall_apply"),
			tgbotapi.NewInlineKeyboardButtonData("Disable Firewall", "security_firewall_off"),
		),
		tgbotapi.NewInlineKeyboardRow(
			tgbotapi.NewInlineKeyboardButtonData("Apply Torrent Block", "security_torrent_apply"),
			tgbotapi.NewInlineKeyboardButtonData("Device Binding ON", "security_device_on"),
		),
		tgbotapi.NewInlineKeyboardRow(
			tgbotapi.NewInlineKeyboardButtonData("Device Binding OFF", "security_device_off"),
			tgbotapi.NewInlineKeyboardButtonData("⬅️ Back", "main_menu"),
		),
	)
	sendAndTrack(bot, msg)
}

func handleSecurityCallback(bot *tgbotapi.BotAPI, chatID int64, data string, config *BotConfig) {
	switch data {
	case "security_firewall_apply":
		exec.Command("/usr/local/bin/zivpn-security.sh", "firewall-apply").Run()
		replyInfo(bot, chatID, "✅ Firewall hardening applied")
	case "security_firewall_off":
		exec.Command("/usr/local/bin/zivpn-security.sh", "firewall-off").Run()
		replyInfo(bot, chatID, "✅ Firewall hardening disabled")
	case "security_torrent_apply":
		exec.Command("/usr/local/bin/zivpn-security.sh", "torrent-apply").Run()
		replyInfo(bot, chatID, "✅ Torrent blocker applied")
	case "security_device_on":
		exec.Command("/usr/local/bin/zivpn-security.sh", "device-on").Run()
		replyInfo(bot, chatID, "✅ Device binding enabled")
	case "security_device_off":
		exec.Command("/usr/local/bin/zivpn-security.sh", "device-off").Run()
		replyInfo(bot, chatID, "✅ Device binding disabled")
	}
	showSecurityMenu(bot, chatID, config)
}

// ==========================================
// Daily Stats
// ==========================================

func showStatsMenu(bot *tgbotapi.BotAPI, chatID int64, config *BotConfig) {
	text := "📈 *Daily Stats*\n\nPilih laporan yang ingin ditampilkan." 
	msg := tgbotapi.NewMessage(chatID, text)
	msg.ParseMode = "Markdown"
	msg.ReplyMarkup = tgbotapi.NewInlineKeyboardMarkup(
		tgbotapi.NewInlineKeyboardRow(
			tgbotapi.NewInlineKeyboardButtonData("Today", "stats_today"),
			tgbotapi.NewInlineKeyboardButtonData("Yesterday", "stats_yesterday"),
		),
		tgbotapi.NewInlineKeyboardRow(
			tgbotapi.NewInlineKeyboardButtonData("⬅️ Back", "main_menu"),
		),
	)
	sendAndTrack(bot, msg)
}

func handleStatsCallback(bot *tgbotapi.BotAPI, chatID int64, data string, config *BotConfig) {
	arg := "today"
	if data == "stats_yesterday" { arg = "yesterday" }
	out, _ := exec.Command("/usr/local/bin/zivpn-stats-daily.sh", arg).CombinedOutput()
	if len(out) == 0 {
		replyError(bot, chatID, "Gagal mengambil stats (pastikan metrics sudah terbentuk).")
		return
	}
	text := "*ZiVPN Daily Stats*\n```\n" + string(out) + "\n```"
	msg := tgbotapi.NewMessage(chatID, text)
	msg.ParseMode = "Markdown"
	msg.ReplyMarkup = tgbotapi.NewInlineKeyboardMarkup(
		tgbotapi.NewInlineKeyboardRow(
			tgbotapi.NewInlineKeyboardButtonData("⬅️ Back", "menu_stats"),
		),
	)
	sendAndTrack(bot, msg)
}

func handleRoleCallback(bot *tgbotapi.BotAPI, chatID int64, data string, config *BotConfig) {
	// Reserved for future UI-driven role edits
	replyInfo(bot, chatID, "Use command: /addadmin /deladmin /addviewer /delviewer")
}

func addUnique(slice *[]int64, id int64) {
	for _, v := range *slice {
		if v == id {
			return
		}
	}
	*slice = append(*slice, id)
}

func removeID(slice *[]int64, id int64) {
	out := []int64{}
	for _, v := range *slice {
		if v != id {
			out = append(out, v)
		}
	}
	*slice = out
}
