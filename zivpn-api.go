package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"regexp"
	"sync"
	"time"
)

const (
	ConfigFile = "/etc/zivpn/config.json"
	UserDB     = "/etc/zivpn/users.json"
	DomainFile = "/etc/zivpn/domain"
	ApiKeyFile = "/etc/zivpn/apikey"
	Port       = "/etc/zivpn/api_port"
)

var AuthToken = "AutoFtBot-agskjgdvsbdreiWG1234512SDKrqw"

type Config struct {
	Listen string `json:"listen"`
	Cert   string `json:"cert"`
	Key    string `json:"key"`
	Obfs   string `json:"obfs"`
	Auth   struct {
		Mode   string   `json:"mode"`
		Config []string `json:"config"`
	} `json:"auth"`
}

type UserRequest struct {
	Password string `json:"password"`
	Days     int    `json:"days"`
}

type UserStore struct {
	Password string `json:"password"`
	Expired  string `json:"expired"`
	Status   string `json:"status"`
}

type Response struct {
	Success bool   `json:"success"`
	Message string `json:"message"`
	Data    interface{} `json:"data,omitempty"`
}

var mutex = &sync.Mutex{}

func main() {
	port := flag.Int("port", 8080, "Port to run the API server on")
	flag.Parse()

	if keyBytes, err := ioutil.ReadFile(ApiKeyFile); err == nil {
		AuthToken = strings.TrimSpace(string(keyBytes))
	}

	http.HandleFunc("/api/user/create", authMiddleware(createUser))
	http.HandleFunc("/api/user/delete", authMiddleware(deleteUser))
	http.HandleFunc("/api/user/renew", authMiddleware(renewUser))
	http.HandleFunc("/api/users", authMiddleware(listUsers))
	http.HandleFunc("/api/info", authMiddleware(getSystemInfo))
	http.HandleFunc("/api/online", authMiddleware(getOnlineAccounts))
	http.HandleFunc("/api/iplimit", authMiddleware(ipLimitHandler))
	http.HandleFunc("/api/cron/expire", authMiddleware(checkExpiration))

	log.Printf("Server started at :%d", *port)
	log.Fatal(http.ListenAndServe(fmt.Sprintf(":%d", *port), nil))
}

func authMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		token := r.Header.Get("X-API-Key")
		if token != AuthToken {
			jsonResponse(w, http.StatusUnauthorized, false, "Unauthorized", nil)
			return
		}
		next(w, r)
	}
}

func jsonResponse(w http.ResponseWriter, status int, success bool, message string, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(Response{
		Success: success,
		Message: message,
		Data:    data,
	})
}

func createUser(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		jsonResponse(w, http.StatusMethodNotAllowed, false, "Method not allowed", nil)
		return
	}

	var req UserRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		jsonResponse(w, http.StatusBadRequest, false, "Invalid request body", nil)
		return
	}

	if req.Password == "" || req.Days <= 0 {
		jsonResponse(w, http.StatusBadRequest, false, "Password dan days harus valid", nil)
		return
	}

	mutex.Lock()
	defer mutex.Unlock()

	config, err := loadConfig()
	if err != nil {
		jsonResponse(w, http.StatusInternalServerError, false, "Gagal membaca config", nil)
		return
	}

	for _, p := range config.Auth.Config {
		if p == req.Password {
			jsonResponse(w, http.StatusConflict, false, "User sudah ada", nil)
			return
		}
	}

	config.Auth.Config = append(config.Auth.Config, req.Password)
	if err := saveConfig(config); err != nil {
		jsonResponse(w, http.StatusInternalServerError, false, "Gagal menyimpan config", nil)
		return
	}

	expDate := time.Now().Add(time.Duration(req.Days) * 24 * time.Hour).Format("2006-01-02")

	users, err := loadUsers()
	if err != nil {
		jsonResponse(w, http.StatusInternalServerError, false, "Gagal membaca database user", nil)
		return
	}

	newUser := UserStore{
		Password: req.Password,
		Expired:  expDate,
		Status:   "active",
	}
	users = append(users, newUser)

	if err := saveUsers(users); err != nil {
		jsonResponse(w, http.StatusInternalServerError, false, "Gagal menyimpan database user", nil)
		return
	}

	if err := ensureSystemUser(req.Password, req.Password, expDate); err != nil {
		jsonResponse(w, http.StatusInternalServerError, false, "Gagal membuat akun multi-protocol (system user)", map[string]string{"detail": err.Error()})
		return
	}

	if err := restartService(); err != nil {
		jsonResponse(w, http.StatusInternalServerError, false, "Gagal merestart service", nil)
		return
	}

	domain := "Tidak diatur"
	if domainBytes, err := ioutil.ReadFile(DomainFile); err == nil {
		domain = strings.TrimSpace(string(domainBytes))
	}

	jsonResponse(w, http.StatusOK, true, "User berhasil dibuat", map[string]string{
		"password": req.Password,
		"expired":  expDate,
		"domain":   domain,
	})
}

func deleteUser(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		jsonResponse(w, http.StatusMethodNotAllowed, false, "Method not allowed", nil)
		return
	}

	var req UserRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		jsonResponse(w, http.StatusBadRequest, false, "Invalid request body", nil)
		return
	}

	mutex.Lock()
	defer mutex.Unlock()

	config, err := loadConfig()
	if err != nil {
		jsonResponse(w, http.StatusInternalServerError, false, "Gagal membaca config", nil)
		return
	}

	foundInConfig := false
	newConfigAuth := []string{}
	for _, p := range config.Auth.Config {
		if p == req.Password {
			foundInConfig = true
		} else {
			newConfigAuth = append(newConfigAuth, p)
		}
	}

	if foundInConfig {
		config.Auth.Config = newConfigAuth
		if err := saveConfig(config); err != nil {
			jsonResponse(w, http.StatusInternalServerError, false, "Gagal menyimpan config", nil)
			return
		}
	}

	users, err := loadUsers()
	if err != nil {
		jsonResponse(w, http.StatusInternalServerError, false, "Gagal membaca database user", nil)
		return
	}

	foundInDB := false
	newUsers := []UserStore{}
	for _, u := range users {
		if u.Password == req.Password {
			foundInDB = true
			continue
		}
		newUsers = append(newUsers, u)
	}

	if !foundInConfig && !foundInDB {
		jsonResponse(w, http.StatusNotFound, false, "User tidak ditemukan", nil)
		return
	}

	if foundInDB {
		if err := saveUsers(newUsers); err != nil {
			jsonResponse(w, http.StatusInternalServerError, false, "Gagal menyimpan database user", nil)
			return
		}
	}

	if foundInConfig {
		if err := restartService(); err != nil {
			jsonResponse(w, http.StatusInternalServerError, false, "Gagal merestart service", nil)
			return
		}
	}

	if err := deleteSystemUser(req.Password); err != nil {
		jsonResponse(w, http.StatusInternalServerError, false, "User dihapus dari ZiVPN, tapi gagal hapus akun multi-protocol", map[string]string{"detail": err.Error()})
		return
	}

	jsonResponse(w, http.StatusOK, true, "User berhasil dihapus", nil)
}

func renewUser(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		jsonResponse(w, http.StatusMethodNotAllowed, false, "Method not allowed", nil)
		return
	}

	var req UserRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		jsonResponse(w, http.StatusBadRequest, false, "Invalid request body", nil)
		return
	}

	mutex.Lock()
	defer mutex.Unlock()

	users, err := loadUsers()
	if err != nil {
		jsonResponse(w, http.StatusInternalServerError, false, "Gagal membaca database user", nil)
		return
	}

	found := false
	newUsers := []UserStore{}
	var newExpDate string

	for _, u := range users {
		if u.Password == req.Password {
			found = true
			currentExp, err := time.Parse("2006-01-02", u.Expired)
			if err != nil {
				currentExp = time.Now()
			}
			
			if currentExp.Before(time.Now()) {
				currentExp = time.Now()
			}

			newExp := currentExp.Add(time.Duration(req.Days) * 24 * time.Hour)
			newExpDate = newExp.Format("2006-01-02")
			
			u.Expired = newExpDate
			
			if u.Status == "locked" {
				u.Status = "active"
				go enableUser(req.Password)
			}

			newUsers = append(newUsers, u)
		} else {
			newUsers = append(newUsers, u)
		}
	}

	if !found {
		jsonResponse(w, http.StatusNotFound, false, "User tidak ditemukan di database", nil)
		return
	}

	if err := saveUsers(newUsers); err != nil {
		jsonResponse(w, http.StatusInternalServerError, false, "Gagal menyimpan database user", nil)
		return
	}

	if err := ensureSystemUser(req.Password, req.Password, newExpDate); err != nil {
		jsonResponse(w, http.StatusInternalServerError, false, "Gagal update akun multi-protocol (system user)", map[string]string{"detail": err.Error()})
		return
	}

	if err := restartService(); err != nil {
		jsonResponse(w, http.StatusInternalServerError, false, "Gagal merestart service", nil)
		return
	}

	jsonResponse(w, http.StatusOK, true, "User berhasil diperpanjang", map[string]string{
		"password": req.Password,
		"expired":  newExpDate,
	})
}

func listUsers(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		jsonResponse(w, http.StatusMethodNotAllowed, false, "Method not allowed", nil)
		return
	}

	users, err := loadUsers()
	if err != nil {
		jsonResponse(w, http.StatusInternalServerError, false, "Gagal membaca database user", nil)
		return
	}

	type UserInfo struct {
		Password string `json:"password"`
		Expired  string `json:"expired"`
		Status   string `json:"status"`
	}

	userList := []UserInfo{}
	today := time.Now().Format("2006-01-02")

	for _, u := range users {
		status := "Active"
		if u.Status == "locked" {
			status = "Locked"
		} else if u.Expired < today {
			status = "Expired"
		}
		
		userList = append(userList, UserInfo{
			Password: u.Password,
			Expired:  u.Expired,
			Status:   status,
		})
	}

	jsonResponse(w, http.StatusOK, true, "Daftar user", userList)
}

func getSystemInfo(w http.ResponseWriter, r *http.Request) {
	// Public IP (prefer IPv4 but keep IPv6 if present)
	ipv4, _ := exec.Command("curl", "-4", "-s", "--max-time", "5", "ifconfig.me").Output()
	ipv6, _ := exec.Command("curl", "-6", "-s", "--max-time", "5", "ifconfig.me").Output()

	// Private IPs
	ipPrivBytes, _ := exec.Command("hostname", "-I").Output()
	privateIPs := strings.Fields(string(ipPrivBytes))
	privateIP := ""
	if len(privateIPs) > 0 {
		privateIP = privateIPs[0]
	}

	// OS
	osName := "Unknown"
	if b, err := ioutil.ReadFile("/etc/os-release"); err == nil {
		for _, line := range strings.Split(string(b), "\n") {
			if strings.HasPrefix(line, "PRETTY_NAME=") {
				osName = strings.Trim(strings.TrimPrefix(line, "PRETTY_NAME="), "\"")
				break
			}
		}
	}

	// Uptime
	uptime, _ := exec.Command("uptime", "-p").Output()

	// Load
	load, _ := exec.Command("cat", "/proc/loadavg").Output()

	// CPU (model)
	cpuModel := "Unknown"
	if b, err := ioutil.ReadFile("/proc/cpuinfo"); err == nil {
		for _, line := range strings.Split(string(b), "\n") {
			if strings.HasPrefix(line, "model name") {
				parts := strings.SplitN(line, ":", 2)
				if len(parts) == 2 {
					cpuModel = strings.TrimSpace(parts[1])
				}
				break
			}
		}
	}

	// RAM
	ramTotal := ""
	ramUsed := ""
	if out, err := exec.Command("free", "-m").Output(); err == nil {
		lines := strings.Split(string(out), "\n")
		for _, l := range lines {
			if strings.HasPrefix(l, "Mem:") {
				f := strings.Fields(l)
				if len(f) >= 3 {
					ramTotal = f[1] + " MB"
					ramUsed = f[2] + " MB"
				}
			}
		}
	}

	// Disk
	diskTotal := ""
	diskUsed := ""
	diskAvail := ""
	if out, err := exec.Command("df", "-h", "/").Output(); err == nil {
		lines := strings.Split(string(out), "\n")
		if len(lines) >= 2 {
			f := strings.Fields(lines[1])
			if len(f) >= 5 {
				diskTotal = f[1]
				diskUsed = f[2]
				diskAvail = f[3]
			}
		}
	}

	domain := "Tidak diatur"
	if domainBytes, err := ioutil.ReadFile(DomainFile); err == nil {
		domain = strings.TrimSpace(string(domainBytes))
	}

	info := map[string]string{
		"domain":       domain,
		"public_ipv4":  strings.TrimSpace(string(ipv4)),
		"public_ipv6":  strings.TrimSpace(string(ipv6)),
		"private_ip":   privateIP,
		"os":           osName,
		"uptime":       strings.TrimSpace(string(uptime)),
		"loadavg":      strings.Fields(string(load))[0] + " " + strings.Fields(string(load))[1] + " " + strings.Fields(string(load))[2],
		"cpu":          cpuModel,
		"ram_total":    ramTotal,
		"ram_used":     ramUsed,
		"disk_total":   diskTotal,
		"disk_used":    diskUsed,
		"disk_avail":   diskAvail,
		"port":         "5667",
		"service":      "zivpn",
		"iplimit_mode": "global",
	}

	if lim, err := readIPLimit(); err == nil {
		info["iplimit"] = fmt.Sprintf("%d", lim)
	} else {
		info["iplimit"] = "0"
	}

	jsonResponse(w, http.StatusOK, true, "System Info", info)
}


type OnlineUser struct {
	User     string   `json:"user"`
	IPs      []string `json:"ips"`
	IPCount  int      `json:"ip_count"`
	Sessions int      `json:"sessions"`
}

func getOnlineAccounts(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		jsonResponse(w, http.StatusMethodNotAllowed, false, "Method not allowed", nil)
		return
	}

	online, err := collectOnlineUsers()
	if err != nil {
		jsonResponse(w, http.StatusInternalServerError, false, "Gagal membaca online user", nil)
		return
	}

	jsonResponse(w, http.StatusOK, true, "Online Accounts", map[string]interface{}{
		"total_users": len(online),
		"users":       online,
	})
}

func ipLimitHandler(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		lim, err := readIPLimit()
		if err != nil {
			jsonResponse(w, http.StatusInternalServerError, false, "Gagal membaca iplimit", nil)
			return
		}
		jsonResponse(w, http.StatusOK, true, "IP Limit", map[string]int{"limit": lim})
		return
	case http.MethodPost:
		var body struct {
			Limit int `json:"limit"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			jsonResponse(w, http.StatusBadRequest, false, "Invalid request body", nil)
			return
		}
		if body.Limit < 1 || body.Limit > 2 {
			jsonResponse(w, http.StatusBadRequest, false, "Limit hanya boleh 1 atau 2", nil)
			return
		}
		if err := writeIPLimit(body.Limit); err != nil {
			jsonResponse(w, http.StatusInternalServerError, false, "Gagal menyimpan iplimit", nil)
			return
		}
		jsonResponse(w, http.StatusOK, true, "IP Limit updated", map[string]int{"limit": body.Limit})
		return
	default:
		jsonResponse(w, http.StatusMethodNotAllowed, false, "Method not allowed", nil)
		return
	}
}

const IPLimitFile = "/etc/zivpn/iplimit.conf"

func readIPLimit() (int, error) {
	b, err := ioutil.ReadFile(IPLimitFile)
	if err != nil {
		// default = 1
		return 1, nil
	}
	s := strings.TrimSpace(string(b))
	if s == "" {
		return 1, nil
	}
	if s == "2" {
		return 2, nil
	}
	return 1, nil
}

func writeIPLimit(limit int) error {
	return ioutil.WriteFile(IPLimitFile, []byte(fmt.Sprintf("%d\n", limit)), 0644)
}

func collectOnlineUsers() ([]OnlineUser, error) {
	// Best effort: parse `who` for SSH sessions: user tty date time (ip/host)
	out, err := exec.Command("who").Output()
	if err != nil {
		return []OnlineUser{}, nil
	}
	lines := strings.Split(strings.TrimSpace(string(out)), "\n")
	type agg struct {
		ips      map[string]bool
		sessions int
	}
	m := map[string]*agg{}
	for _, l := range lines {
		l = strings.TrimSpace(l)
		if l == "" {
			continue
		}
		f := strings.Fields(l)
		if len(f) < 1 {
			continue
		}
		user := f[0]
		host := ""
		// host appears like (1.2.3.4)
		if strings.Contains(l, "(") && strings.Contains(l, ")") {
			host = l[strings.LastIndex(l, "(")+1 : strings.LastIndex(l, ")")]
		}
		if _, ok := m[user]; !ok {
			m[user] = &agg{ips: map[string]bool{}, sessions: 0}
		}
		m[user].sessions++
		if host != "" {
			m[user].ips[host] = true
		}
	}

	online := make([]OnlineUser, 0, len(m))
	for u, a := range m {
		ips := make([]string, 0, len(a.ips))
		for ip := range a.ips {
			ips = append(ips, ip)
		}
		online = append(online, OnlineUser{
			User:     u,
			IPs:      ips,
			IPCount:  len(ips),
			Sessions: a.sessions,
		})
	}
	return online, nil
}


func checkExpiration(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		jsonResponse(w, http.StatusMethodNotAllowed, false, "Method not allowed", nil)
		return
	}

	users, err := loadUsers()
	if err != nil {
		jsonResponse(w, http.StatusInternalServerError, false, "Gagal membaca database user", nil)
		return
	}

	today := time.Now().Format("2006-01-02")
	
	// Load config to check who is currently active
	config, err := loadConfig()
	if err != nil {
		jsonResponse(w, http.StatusInternalServerError, false, "Gagal membaca config", nil)
		return
	}

	activeUsers := make(map[string]bool)
	for _, p := range config.Auth.Config {
		activeUsers[p] = true
	}

	revokedCount := 0
	for _, u := range users {
		if u.Expired < today && activeUsers[u.Password] {
			log.Printf("User %s expired (Exp: %s). Revoking access.\n", u.Password, u.Expired)
			revokeAccess(u.Password)
			revokedCount++
		}
	}

	jsonResponse(w, http.StatusOK, true, fmt.Sprintf("Expiration check complete. Revoked: %d", revokedCount), nil)
}

func revokeAccess(password string) {
	mutex.Lock()
	defer mutex.Unlock()

	lockSystemUser(password)

	config, err := loadConfig()
	if err == nil {
		newConfigAuth := []string{}
		changed := false
		for _, p := range config.Auth.Config {
			if p == password {
				changed = true
			} else {
				newConfigAuth = append(newConfigAuth, p)
			}
		}
		if changed {
			config.Auth.Config = newConfigAuth
			saveConfig(config)
			restartService()
		}
	}
}

func enableUser(password string) {
	mutex.Lock()
	defer mutex.Unlock()

	unlockSystemUser(password)

	config, err := loadConfig()
	if err != nil {
		return
	}

	exists := false
	for _, p := range config.Auth.Config {
		if p == password {
			exists = true
			break
		}
	}

	if !exists {
		config.Auth.Config = append(config.Auth.Config, password)
		saveConfig(config)
		restartService()
	}
}


func loadConfig() (Config, error) {
	var config Config
	file, err := ioutil.ReadFile(ConfigFile)
	if err != nil {
		return config, err
	}
	err = json.Unmarshal(file, &config)
	return config, err
}

func saveConfig(config Config) error {
	data, err := json.MarshalIndent(config, "", "  ")
	if err != nil {
		return err
	}
	return ioutil.WriteFile(ConfigFile, data, 0644)
}

func loadUsers() ([]UserStore, error) {
	var users []UserStore
	file, err := ioutil.ReadFile(UserDB)
	if err != nil {
		if os.IsNotExist(err) {
			return users, nil
		}
		return nil, err
	}
	err = json.Unmarshal(file, &users)
	return users, err
}

func saveUsers(users []UserStore) error {
	data, err := json.MarshalIndent(users, "", "  ")
	if err != nil {
		return err
	}
	return ioutil.WriteFile(UserDB, data, 0644)
}


// --- Multi-protocol account helpers (SSH/Dropbear/Stunnel/WS etc rely on OS user) ---

func sanitizeUsername(in string) string {
	// allow: a-z A-Z 0-9 underscore, max 32
	re := regexp.MustCompile(`[^a-zA-Z0-9_]+`)
	out := re.ReplaceAllString(in, "_")
	if len(out) > 32 {
		out = out[:32]
	}
	out = strings.Trim(out, "_")
	if out == "" {
		out = "user"
	}
	return strings.ToLower(out)
}

func ensureSystemUser(rawName, password, expiredYYYYMMDD string) error {
	name := sanitizeUsername(rawName)

	// Create user if not exists
	if err := exec.Command("id", "-u", name).Run(); err != nil {
		// shell /bin/false for safety (no interactive shell)
		if out, err2 := exec.Command("useradd", "-m", "-s", "/bin/false", name).CombinedOutput(); err2 != nil {
			return fmt.Errorf("useradd: %v (%s)", err2, string(out))
		}
	}

	// Set password
	chpasswd := exec.Command("bash", "-lc", fmt.Sprintf("echo '%s:%s' | chpasswd", name, password))
	if out, err := chpasswd.CombinedOutput(); err != nil {
		return fmt.Errorf("chpasswd: %v (%s)", err, string(out))
	}

	// Set expiry date (YYYY-MM-DD -> YYYY-MM-DD)
	exp := expiredYYYYMMDD
	if len(exp) == 8 {
		exp = exp[0:4] + "-" + exp[4:6] + "-" + exp[6:8]
	}
	if out, err := exec.Command("chage", "-E", exp, name).CombinedOutput(); err != nil {
		// Not fatal for all distros, but return error so admin knows
		return fmt.Errorf("chage: %v (%s)", err, string(out))
	}

	return nil
}

func deleteSystemUser(rawName string) error {
	name := sanitizeUsername(rawName)
	// userdel -r may fail if user is logged in; best effort
	_ = exec.Command("pkill", "-KILL", "-u", name).Run()
	out, err := exec.Command("userdel", "-r", name).CombinedOutput()
	if err != nil {
		// ignore if user doesn't exist
		if strings.Contains(string(out), "does not exist") || strings.Contains(string(out), "not exist") {
			return nil
		}
		return fmt.Errorf("userdel: %v (%s)", err, string(out))
	}
	return nil
}

func lockSystemUser(rawName string) {
	name := sanitizeUsername(rawName)
	_ = exec.Command("passwd", "-l", name).Run()
}

func unlockSystemUser(rawName string) {
	name := sanitizeUsername(rawName)
	_ = exec.Command("passwd", "-u", name).Run()
}

func restartService() error {
	cmd := exec.Command("systemctl", "restart", "zivpn.service")
	if err := cmd.Run(); err != nil {
		return err
	}
	// Best-effort: apply UDP per-user IP limit rules if script exists
	if _, err := os.Stat("/usr/local/bin/zivpn-udplimit.sh"); err == nil {
		_ = exec.Command("/usr/local/bin/zivpn-udplimit.sh").Run()
	}
	return nil
}
