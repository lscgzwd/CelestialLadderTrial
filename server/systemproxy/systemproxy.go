package systemproxy

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"

	"proxy/utils/context"
	"proxy/utils/logger"
)

var (
	backupData *BackupData
	backupMu   sync.Mutex
	backupFile = "system_proxy_backup.json"
)

// BackupData 备份的系统代理配置
type BackupData struct {
	OS      string         `json:"os"`
	Windows *WindowsBackup `json:"windows,omitempty"`
	Darwin  *DarwinBackup  `json:"darwin,omitempty"`
	Linux   *LinuxBackup   `json:"linux,omitempty"`
}

// WindowsBackup Windows备份数据
type WindowsBackup struct {
	WinHTTPProxy  string `json:"winhttp_proxy"`            // WinHTTP 代理
	ProxyEnable   string `json:"proxy_enable,omitempty"`   // WinINET: ProxyEnable (REG_DWORD)
	ProxyServer   string `json:"proxy_server,omitempty"`   // WinINET: ProxyServer (REG_SZ)
	ProxyOverride string `json:"proxy_override,omitempty"` // WinINET: ProxyOverride (REG_SZ)
}

// DarwinBackup macOS备份数据
type DarwinBackup struct {
	Services map[string]*ServiceBackup `json:"services"`
}

// ServiceBackup 服务备份数据
type ServiceBackup struct {
	WebProxyEnabled    bool   `json:"web_proxy_enabled"`
	WebProxyHost       string `json:"web_proxy_host"`
	WebProxyPort       string `json:"web_proxy_port"`
	SecureProxyEnabled bool   `json:"secure_proxy_enabled"`
	SecureProxyHost    string `json:"secure_proxy_host"`
	SecureProxyPort    string `json:"secure_proxy_port"`
}

// LinuxBackup Linux备份数据
type LinuxBackup struct {
	Mode      string `json:"mode"`
	HTTPHost  string `json:"http_host"`
	HTTPPort  string `json:"http_port"`
	HTTPSHost string `json:"https_host"`
	HTTPSPort string `json:"https_port"`
}

// Apply 根据配置自动设置系统代理
// port 为本地代理监听端口（通常是 config.Config.In.Port）
func Apply(ctx *context.Context, port int) {
	// 只在启用了 SystemProxy 时调用（由上层控制）
	// 先备份原始配置
	if err := backup(ctx); err != nil {
		logger.Warn(ctx, map[string]interface{}{
			"action": "SystemProxy",
			"error":  err,
		}, "failed to backup system proxy settings")
	}

	switch runtime.GOOS {
	case "windows":
		applyWindows(ctx, port)
	case "darwin":
		applyDarwin(ctx, port)
	case "linux":
		applyLinux(ctx, port)
	default:
		// 其他平台暂不支持，静默忽略
	}
}

// Restore 恢复系统代理配置
func Restore(ctx *context.Context) {
	backupMu.Lock()
	defer backupMu.Unlock()

	if backupData == nil {
		// 尝试从文件加载备份
		if err := loadBackup(); err != nil {
			logger.Warn(ctx, map[string]interface{}{
				"action": "SystemProxy",
				"error":  err,
			}, "no backup found, skip restore")
			return
		}
	}

	switch runtime.GOOS {
	case "windows":
		restoreWindows(ctx)
	case "darwin":
		restoreDarwin(ctx)
	case "linux":
		restoreLinux(ctx)
	}

	// 清除备份文件
	os.Remove(backupFile)
	backupData = nil

	logger.Info(ctx, map[string]interface{}{
		"action": "SystemProxy",
	}, "system proxy restored")
}

// backup 备份当前系统代理配置
func backup(ctx *context.Context) error {
	backupMu.Lock()
	defer backupMu.Unlock()

	backupData = &BackupData{
		OS: runtime.GOOS,
	}

	switch runtime.GOOS {
	case "windows":
		return backupWindows(ctx)
	case "darwin":
		return backupDarwin(ctx)
	case "linux":
		return backupLinux(ctx)
	}

	return nil
}

// backupWindows 备份Windows代理配置
func backupWindows(ctx *context.Context) error {
	backup := &WindowsBackup{}

	cmd := exec.Command("netsh", "winhttp", "show", "proxy")
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("failed to get current proxy: %w", err)
	}

	output := string(out)
	proxy := ""

	// 解析输出，查找代理设置
	// 输出格式可能为:
	// - "Direct access (no proxy server)." (无代理)
	// - "代理服务器: 127.0.0.1:8080" (中文系统)
	// - "Proxy Server(s): 127.0.0.1:8080" (英文系统)
	// - "127.0.0.1:8080" (直接显示)

	// 检查是否是无代理
	if strings.Contains(output, "Direct access") || strings.Contains(output, "直接访问") {
		proxy = "" // 空字符串表示无代理
	} else {
		// 尝试提取代理地址
		lines := strings.Split(output, "\n")
		for _, line := range lines {
			line = strings.TrimSpace(line)
			// 查找包含冒号的行（IP:端口格式）
			if strings.Contains(line, ":") {
				// 尝试提取 IP:端口
				parts := strings.Fields(line)
				for _, part := range parts {
					// 检查是否是 IP:端口 格式
					if strings.Contains(part, ":") && !strings.Contains(part, "://") {
						// 验证格式
						if strings.Count(part, ":") == 1 {
							colonIdx := strings.Index(part, ":")
							if colonIdx > 0 && colonIdx < len(part)-1 {
								proxy = part
								break
							}
						}
					}
				}
				if proxy != "" {
					break
				}
			}
		}
	}

	backup.WinHTTPProxy = proxy

	// 备份 WinINET 代理（系统设置里的“使用代理服务器”）
	const regPath = `HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings`

	// ProxyEnable
	cmd = exec.Command("reg", "query", regPath, "/v", "ProxyEnable")
	if out, err := cmd.CombinedOutput(); err == nil {
		lines := strings.Split(string(out), "\n")
		for _, line := range lines {
			line = strings.TrimSpace(line)
			if strings.HasPrefix(line, "ProxyEnable") {
				fields := strings.Fields(line)
				if len(fields) >= 3 {
					backup.ProxyEnable = fields[len(fields)-1]
				}
				break
			}
		}
	}

	// ProxyServer
	cmd = exec.Command("reg", "query", regPath, "/v", "ProxyServer")
	if out, err := cmd.CombinedOutput(); err == nil {
		lines := strings.Split(string(out), "\n")
		for _, line := range lines {
			line = strings.TrimSpace(line)
			if strings.HasPrefix(line, "ProxyServer") {
				// 格式: ProxyServer    REG_SZ    127.0.0.1:8080
				fields := strings.Fields(line)
				if len(fields) >= 3 {
					backup.ProxyServer = strings.Join(fields[2:], " ")
				}
				break
			}
		}
	}

	// ProxyOverride
	cmd = exec.Command("reg", "query", regPath, "/v", "ProxyOverride")
	if out, err := cmd.CombinedOutput(); err == nil {
		lines := strings.Split(string(out), "\n")
		for _, line := range lines {
			line = strings.TrimSpace(line)
			if strings.HasPrefix(line, "ProxyOverride") {
				fields := strings.Fields(line)
				if len(fields) >= 3 {
					backup.ProxyOverride = strings.Join(fields[2:], " ")
				}
				break
			}
		}
	}

	backupData.Windows = backup
	return saveBackup()
}

// restoreWindows 恢复Windows代理配置
func restoreWindows(ctx *context.Context) {
	if backupData.Windows == nil {
		return
	}

	// 恢复 WinHTTP 代理
	if backupData.Windows.WinHTTPProxy == "" {
		exec.Command("netsh", "winhttp", "reset", "proxy").Run()
	} else {
		exec.Command("netsh", "winhttp", "set", "proxy", backupData.Windows.WinHTTPProxy).Run()
	}

	// 恢复 WinINET 代理（系统设置）
	const regPath = `HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings`

	// ProxyEnable
	if backupData.Windows.ProxyEnable != "" {
		exec.Command("reg", "add", regPath, "/v", "ProxyEnable", "/t", "REG_DWORD", "/d", backupData.Windows.ProxyEnable, "/f").Run()
	}

	// ProxyServer
	if backupData.Windows.ProxyServer != "" {
		exec.Command("reg", "add", regPath, "/v", "ProxyServer", "/t", "REG_SZ", "/d", backupData.Windows.ProxyServer, "/f").Run()
	} else {
		// 清空
		exec.Command("reg", "delete", regPath, "/v", "ProxyServer", "/f").Run()
	}

	// ProxyOverride
	if backupData.Windows.ProxyOverride != "" {
		exec.Command("reg", "add", regPath, "/v", "ProxyOverride", "/t", "REG_SZ", "/d", backupData.Windows.ProxyOverride, "/f").Run()
	} else {
		exec.Command("reg", "delete", regPath, "/v", "ProxyOverride", "/f").Run()
	}
}

// applyWindows 配置 WinHTTP + WinINET 代理
func applyWindows(ctx *context.Context, port int) {
	proxy := "127.0.0.1:" + strconv.Itoa(port)

	// 设置 WinHTTP 代理
	cmd := exec.Command("netsh", "winhttp", "set", "proxy", proxy)
	if out, err := cmd.CombinedOutput(); err != nil {
		logger.Warn(ctx, map[string]interface{}{
			"action": "SystemProxy",
			"os":     "windows",
			"error":  err,
			"output": string(out),
		}, "set WinHTTP proxy failed")
		return
	}

	// 设置 WinINET 代理（系统“使用代理服务器”）
	const regPath = `HKCU\Software\Windows\CurrentVersion\Internet Settings`
	// 注意：这里路径写错会失败，我们使用正确路径：
	const regPathCorrect = `HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings`

	// 开启代理
	exec.Command("reg", "add", regPathCorrect, "/v", "ProxyEnable", "/t", "REG_DWORD", "/d", "1", "/f").Run()
	// 设置代理服务器
	exec.Command("reg", "add", regPathCorrect, "/v", "ProxyServer", "/t", "REG_SZ", "/d", proxy, "/f").Run()

	logger.Info(ctx, map[string]interface{}{
		"action": "SystemProxy",
		"os":     "windows",
		"proxy":  proxy,
	}, "WinHTTP + WinINET proxy configured")
}

// backupDarwin 备份macOS代理配置
func backupDarwin(ctx *context.Context) error {
	backupData.Darwin = &DarwinBackup{
		Services: make(map[string]*ServiceBackup),
	}

	services := []string{"Wi-Fi", "Ethernet"}

	for _, service := range services {
		svcBackup := &ServiceBackup{}

		// 检查HTTP代理状态
		cmd := exec.Command("networksetup", "-getwebproxy", service)
		if out, err := cmd.CombinedOutput(); err == nil {
			output := string(out)
			if strings.Contains(output, "Enabled: Yes") {
				svcBackup.WebProxyEnabled = true
				// 提取主机和端口
				lines := strings.Split(output, "\n")
				for _, line := range lines {
					line = strings.TrimSpace(line)
					if strings.HasPrefix(line, "Server:") {
						svcBackup.WebProxyHost = strings.TrimSpace(strings.TrimPrefix(line, "Server:"))
					}
					if strings.HasPrefix(line, "Port:") {
						svcBackup.WebProxyPort = strings.TrimSpace(strings.TrimPrefix(line, "Port:"))
					}
				}
			}
		}

		// 检查HTTPS代理状态
		cmd = exec.Command("networksetup", "-getsecurewebproxy", service)
		if out, err := cmd.CombinedOutput(); err == nil {
			output := string(out)
			if strings.Contains(output, "Enabled: Yes") {
				svcBackup.SecureProxyEnabled = true
				// 提取主机和端口
				lines := strings.Split(output, "\n")
				for _, line := range lines {
					line = strings.TrimSpace(line)
					if strings.HasPrefix(line, "Server:") {
						svcBackup.SecureProxyHost = strings.TrimSpace(strings.TrimPrefix(line, "Server:"))
					}
					if strings.HasPrefix(line, "Port:") {
						svcBackup.SecureProxyPort = strings.TrimSpace(strings.TrimPrefix(line, "Port:"))
					}
				}
			}
		}

		backupData.Darwin.Services[service] = svcBackup
	}

	return saveBackup()
}

// restoreDarwin 恢复macOS代理配置
func restoreDarwin(ctx *context.Context) {
	if backupData.Darwin == nil {
		return
	}

	for service, svcBackup := range backupData.Darwin.Services {
		if svcBackup.WebProxyEnabled {
			exec.Command("networksetup", "-setwebproxy", service, svcBackup.WebProxyHost, svcBackup.WebProxyPort).Run()
			exec.Command("networksetup", "-setwebproxystate", service, "on").Run()
		} else {
			exec.Command("networksetup", "-setwebproxystate", service, "off").Run()
		}

		if svcBackup.SecureProxyEnabled {
			exec.Command("networksetup", "-setsecurewebproxy", service, svcBackup.SecureProxyHost, svcBackup.SecureProxyPort).Run()
			exec.Command("networksetup", "-setsecurewebproxystate", service, "on").Run()
		} else {
			exec.Command("networksetup", "-setsecurewebproxystate", service, "off").Run()
		}
	}
}

// applyDarwin 使用 networksetup 配置 macOS 系统代理（Wi-Fi/Ethernet）
func applyDarwin(ctx *context.Context, port int) {
	proxyHost := "127.0.0.1"
	proxyPort := strconv.Itoa(port)

	services := []string{"Wi-Fi", "Ethernet"}

	for _, service := range services {
		// HTTP 代理
		cmd := exec.Command("networksetup", "-setwebproxy", service, proxyHost, proxyPort)
		if out, err := cmd.CombinedOutput(); err != nil {
			logger.Warn(ctx, map[string]interface{}{
				"action":  "SystemProxy",
				"os":      "darwin",
				"service": service,
				"error":   err,
				"output":  string(out),
			}, "set web proxy failed")
			continue
		}
		// HTTPS 代理
		cmd = exec.Command("networksetup", "-setsecurewebproxy", service, proxyHost, proxyPort)
		if out, err := cmd.CombinedOutput(); err != nil {
			logger.Warn(ctx, map[string]interface{}{
				"action":  "SystemProxy",
				"os":      "darwin",
				"service": service,
				"error":   err,
				"output":  string(out),
			}, "set secure web proxy failed")
			continue
		}
		// 开启代理
		exec.Command("networksetup", "-setwebproxystate", service, "on").Run()
		exec.Command("networksetup", "-setsecurewebproxystate", service, "on").Run()

		logger.Info(ctx, map[string]interface{}{
			"action":  "SystemProxy",
			"os":      "darwin",
			"service": service,
			"proxy":   fmt.Sprintf("%s:%s", proxyHost, proxyPort),
		}, "system proxy configured")
	}
}

// backupLinux 备份Linux代理配置
func backupLinux(ctx *context.Context) error {
	// 检查 gsettings 是否可用
	if _, err := exec.LookPath("gsettings"); err != nil {
		return fmt.Errorf("gsettings not found")
	}

	backupData.Linux = &LinuxBackup{}

	// 获取代理模式
	cmd := exec.Command("gsettings", "get", "org.gnome.system.proxy", "mode")
	if out, err := cmd.CombinedOutput(); err == nil {
		mode := strings.Trim(strings.TrimSpace(string(out)), "'\"")
		backupData.Linux.Mode = mode
	}

	// 获取HTTP代理
	cmd = exec.Command("gsettings", "get", "org.gnome.system.proxy.http", "host")
	if out, err := cmd.CombinedOutput(); err == nil {
		backupData.Linux.HTTPHost = strings.Trim(strings.TrimSpace(string(out)), "'\"")
	}

	cmd = exec.Command("gsettings", "get", "org.gnome.system.proxy.http", "port")
	if out, err := cmd.CombinedOutput(); err == nil {
		backupData.Linux.HTTPPort = strings.Trim(strings.TrimSpace(string(out)), "'\"")
	}

	// 获取HTTPS代理
	cmd = exec.Command("gsettings", "get", "org.gnome.system.proxy.https", "host")
	if out, err := cmd.CombinedOutput(); err == nil {
		backupData.Linux.HTTPSHost = strings.Trim(strings.TrimSpace(string(out)), "'\"")
	}

	cmd = exec.Command("gsettings", "get", "org.gnome.system.proxy.https", "port")
	if out, err := cmd.CombinedOutput(); err == nil {
		backupData.Linux.HTTPSPort = strings.Trim(strings.TrimSpace(string(out)), "'\"")
	}

	return saveBackup()
}

// restoreLinux 恢复Linux代理配置
func restoreLinux(ctx *context.Context) {
	if backupData.Linux == nil {
		return
	}

	// 检查 gsettings 是否可用
	if _, err := exec.LookPath("gsettings"); err != nil {
		return
	}

	// 恢复代理模式
	if backupData.Linux.Mode != "" {
		exec.Command("gsettings", "set", "org.gnome.system.proxy", "mode", backupData.Linux.Mode).Run()
	}

	// 恢复HTTP代理
	if backupData.Linux.HTTPHost != "" {
		exec.Command("gsettings", "set", "org.gnome.system.proxy.http", "host", backupData.Linux.HTTPHost).Run()
	}
	if backupData.Linux.HTTPPort != "" {
		exec.Command("gsettings", "set", "org.gnome.system.proxy.http", "port", backupData.Linux.HTTPPort).Run()
	}

	// 恢复HTTPS代理
	if backupData.Linux.HTTPSHost != "" {
		exec.Command("gsettings", "set", "org.gnome.system.proxy.https", "host", backupData.Linux.HTTPSHost).Run()
	}
	if backupData.Linux.HTTPSPort != "" {
		exec.Command("gsettings", "set", "org.gnome.system.proxy.https", "port", backupData.Linux.HTTPSPort).Run()
	}
}

// applyLinux 使用 gsettings 配置 GNOME 系统代理（如可用），否则仅记录提示
func applyLinux(ctx *context.Context, port int) {
	proxyHost := "127.0.0.1"
	proxyPort := strconv.Itoa(port)

	// 检查 gsettings 是否可用
	if _, err := exec.LookPath("gsettings"); err != nil {
		logger.Warn(ctx, map[string]interface{}{
			"action": "SystemProxy",
			"os":     "linux",
		}, "gsettings not found, skip system proxy configuration")
		return
	}

	// 设置代理模式为手动
	exec.Command("gsettings", "set", "org.gnome.system.proxy", "mode", "manual").Run()

	// HTTP 代理
	exec.Command("gsettings", "set", "org.gnome.system.proxy.http", "host", proxyHost).Run()
	exec.Command("gsettings", "set", "org.gnome.system.proxy.http", "port", proxyPort).Run()

	// HTTPS 代理
	exec.Command("gsettings", "set", "org.gnome.system.proxy.https", "host", proxyHost).Run()
	exec.Command("gsettings", "set", "org.gnome.system.proxy.https", "port", proxyPort).Run()

	logger.Info(ctx, map[string]interface{}{
		"action": "SystemProxy",
		"os":     "linux",
		"proxy":  fmt.Sprintf("%s:%s", proxyHost, proxyPort),
	}, "GNOME system proxy configured")
}

// saveBackup 保存备份到文件
func saveBackup() error {
	data, err := json.MarshalIndent(backupData, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal backup: %w", err)
	}

	// 获取可执行文件所在目录
	exePath, err := os.Executable()
	if err != nil {
		return fmt.Errorf("failed to get executable path: %w", err)
	}
	exeDir := filepath.Dir(exePath)
	backupPath := filepath.Join(exeDir, backupFile)

	return os.WriteFile(backupPath, data, 0644)
}

// loadBackup 从文件加载备份
func loadBackup() error {
	// 获取可执行文件所在目录
	exePath, err := os.Executable()
	if err != nil {
		return fmt.Errorf("failed to get executable path: %w", err)
	}
	exeDir := filepath.Dir(exePath)
	backupPath := filepath.Join(exeDir, backupFile)

	data, err := os.ReadFile(backupPath)
	if err != nil {
		return fmt.Errorf("failed to read backup file: %w", err)
	}

	if err := json.Unmarshal(data, &backupData); err != nil {
		return fmt.Errorf("failed to unmarshal backup: %w", err)
	}

	return nil
}
