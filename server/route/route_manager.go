package route

import (
	"fmt"
	"net"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"sync"

	"proxy/config"
	"proxy/server/common"
	"proxy/utils/context"
	"proxy/utils/logger"
)

// RouteManager 路由管理器
type RouteManager struct {
	originalGateway string // 原默认网关 IP
	tunInterface    string // TUN 接口名称
	tunGateway      string // TUN 接口的网关/本地 IP（如 10.0.0.1）
	backedUp        bool
	remoteServerIPs []net.IP // 远程服务器 IP 列表（用于快速检查）
	remoteIPsMu     sync.RWMutex
}

// NewRouteManager 创建路由管理器
func NewRouteManager(tunInterface, tunGateway string) *RouteManager {
	return &RouteManager{
		tunInterface: tunInterface,
		tunGateway:   tunGateway,
	}
}

// BackupRoutes 备份原始路由表
func (rm *RouteManager) BackupRoutes(ctx *context.Context) error {
	if rm.backedUp {
		return nil
	}

	// 检测当前默认网关
	gateway, err := rm.getDefaultGateway(ctx)
	if err != nil {
		logger.Error(ctx, map[string]interface{}{
			"action":    config.ActionRuntime,
			"errorCode": logger.ErrCodeHandshake,
			"error":     err,
		}, "failed to get default gateway")
		return fmt.Errorf("failed to get default gateway: %w", err)
	}

	rm.originalGateway = gateway

	// 获取原默认接口的 IP 地址，用于绑定远程连接
	interfaceIP, err := rm.getDefaultInterfaceIP(ctx)
	if err != nil {
		logger.Warn(ctx, map[string]interface{}{
			"action": config.ActionRuntime,
			"error":  err,
		}, "failed to get default interface IP, remote connections may not bind to original interface")
	} else if interfaceIP != nil {
		// 设置全局 Dialer 绑定到原接口
		common.SetOriginalInterfaceIP(ctx, interfaceIP)
	}

	rm.backedUp = true

	logger.Info(ctx, map[string]interface{}{
		"action":  config.ActionRuntime,
		"gateway": gateway,
	}, "backed up original gateway")

	return nil
}

// SetupRoutes 配置路由表
func (rm *RouteManager) SetupRoutes(ctx *context.Context) error {
	if !rm.backedUp {
		if err := rm.BackupRoutes(ctx); err != nil {
			return err
		}
	}

	// 1. 为远端服务器添加直连路由（必须在 TUN 接管前添加，走原默认网关）
	// 注意：这个必须在最前面，因为后续的 DNS 查询可能也需要访问远程服务器
	if err := rm.addRemoteServerRoute(ctx); err != nil {
		return fmt.Errorf("failed to add remote server route: %w", err)
	}

	// 2. 添加本地网络路由（不走 TUN）
	if err := rm.addLocalNetworkRoutes(ctx); err != nil {
		return fmt.Errorf("failed to add local network routes: %w", err)
	}

	// 3. 中国 IP 路由：不在路由表层面添加，改由代理程序内部判断
	// 原因：添加大量路由太慢（1000条需要100秒），且 tun2socks 会将流量转到 SOCKS5 代理
	// 代理内部的 IsCnIp() 函数会判断是否走直连
	logger.Info(ctx, map[string]interface{}{
		"action": config.ActionRuntime,
	}, "China IP routing handled by proxy, not route table")

	// 4. 添加白名单路由（不走 TUN）
	if err := rm.addWhiteListRoutes(ctx); err != nil {
		return fmt.Errorf("failed to add whitelist routes: %w", err)
	}

	// 5. 设置默认路由到 TUN 接口（最后设置，让 TUN 接管所有其他流量）
	if err := rm.setDefaultRoute(ctx); err != nil {
		return fmt.Errorf("failed to set default route: %w", err)
	}

	logger.Info(ctx, map[string]interface{}{
		"action": config.ActionRuntime,
	}, "routes configured successfully")

	return nil
}

// addRemoteServerRoute 为远端代理服务器添加直连路由，避免走 TUN 形成死循环
// 注意：此函数在 TUN 启动前调用，此时 DNS 查询不会走 TUN
func (rm *RouteManager) addRemoteServerRoute(ctx *context.Context) error {
	host := strings.TrimSpace(config.Config.Out.RemoteAddr)
	if host == "" {
		return nil
	}

	// 在 TUN 启动前解析，避免 DNS 查询走 TUN
	ips, err := net.LookupIP(host)
	if err != nil {
		logger.Warn(ctx, map[string]interface{}{
			"action": config.ActionRuntime,
			"host":   host,
			"error":  err,
		}, "failed to lookup remote server IP, skip remote route")
		return nil // 不阻塞启动
	}

	// 保存远程服务器 IP 列表，用于快速检查
	rm.remoteIPsMu.Lock()
	rm.remoteServerIPs = make([]net.IP, 0)
	for _, ip := range ips {
		ip4 := ip.To4()
		if ip4 == nil {
			continue
		}
		rm.remoteServerIPs = append(rm.remoteServerIPs, ip4)
		cidr := ip4.String() + "/32"
		if err := rm.addRoute(ctx, cidr, rm.originalGateway); err != nil {
			logger.Warn(ctx, map[string]interface{}{
				"action": config.ActionRuntime,
				"cidr":   cidr,
				"error":  err,
			}, "failed to add remote server route")
		} else {
			logger.Info(ctx, map[string]interface{}{
				"action":  config.ActionRuntime,
				"cidr":    cidr,
				"gateway": rm.originalGateway,
			}, "added remote server route")
		}
	}
	rm.remoteIPsMu.Unlock()
	return nil
}

// IsRemoteServerIP 检查 IP 是否是远程服务器 IP
func (rm *RouteManager) IsRemoteServerIP(ip net.IP) bool {
	if ip == nil {
		return false
	}
	ip4 := ip.To4()
	if ip4 == nil {
		return false
	}
	rm.remoteIPsMu.RLock()
	defer rm.remoteIPsMu.RUnlock()
	for _, remoteIP := range rm.remoteServerIPs {
		if remoteIP.Equal(ip4) {
			return true
		}
	}
	return false
}

// GetRouteManager 获取全局路由管理器实例（用于 TUN handler 检查）
var globalRouteManager *RouteManager
var globalRouteManagerMu sync.RWMutex

// SetGlobalRouteManager 设置全局路由管理器
func SetGlobalRouteManager(rm *RouteManager) {
	globalRouteManagerMu.Lock()
	defer globalRouteManagerMu.Unlock()
	globalRouteManager = rm
}

// GetGlobalRouteManager 获取全局路由管理器
func GetGlobalRouteManager() *RouteManager {
	globalRouteManagerMu.RLock()
	defer globalRouteManagerMu.RUnlock()
	return globalRouteManager
}

// RestoreRoutes 恢复原始路由表
func (rm *RouteManager) RestoreRoutes(ctx *context.Context) error {
	if !rm.backedUp {
		return nil
	}

	// 删除默认路由
	if err := rm.deleteDefaultRoute(ctx); err != nil {
		logger.Error(ctx, map[string]interface{}{
			"action":    config.ActionRuntime,
			"errorCode": logger.ErrCodeHandshake,
			"error":     err,
		}, "failed to delete default route")
	}

	logger.Info(ctx, map[string]interface{}{
		"action": config.ActionRuntime,
	}, "routes restored")

	rm.backedUp = false
	return nil
}

// addLocalNetworkRoutes 添加本地网络路由
func (rm *RouteManager) addLocalNetworkRoutes(ctx *context.Context) error {
	localNetworks := []string{
		"127.0.0.0/8",    // 本地回环
		"10.0.0.0/8",     // 私有网络
		"172.16.0.0/12",  // 私有网络
		"192.168.0.0/16", // 私有网络
		"169.254.0.0/16", // 链路本地
	}

	for _, network := range localNetworks {
		if err := rm.addRoute(ctx, network, rm.originalGateway); err != nil {
			logger.Warn(ctx, map[string]interface{}{
				"action":  config.ActionRuntime,
				"network": network,
				"error":   err,
			}, "failed to add local network route")
			// 继续处理其他路由，不中断
		}
	}

	return nil
}

// addChinaIpRoutes 添加中国 IP 段路由
func (rm *RouteManager) addChinaIpRoutes(ctx *context.Context) error {
	// 从配置中读取中国 IP 文件
	if len(config.Config.ChinaIpFile) == 0 {
		return nil
	}

	// 读取中国IP文件
	fileContent, err := os.ReadFile(config.Config.ChinaIpFile)
	if err != nil {
		logger.Warn(ctx, map[string]interface{}{
			"action": config.ActionRuntime,
			"error":  err,
			"file":   config.Config.ChinaIpFile,
		}, "failed to read China IP file, skipping China IP routes")
		return nil // 不阻塞启动
	}

	lines := strings.Split(string(fileContent), "\n")
	addedCount := 0
	maxRoutes := 1000 // 限制路由数量，避免路由表过大

	for k, line := range lines {
		if addedCount >= maxRoutes {
			logger.Warn(ctx, map[string]interface{}{
				"action": config.ActionRuntime,
			}, "reached max China IP routes limit, some routes may be skipped")
			break
		}

		line = strings.TrimSpace(line)
		if len(line) == 0 || strings.HasPrefix(line, "#") {
			continue
		}

		// 解析CIDR
		_, ipNet, err := net.ParseCIDR(line)
		if err != nil {
			logger.Warn(ctx, map[string]interface{}{
				"action": config.ActionRuntime,
				"line":   k + 1,
				"error":  err,
			}, "invalid CIDR in China IP file")
			continue
		}

		// 添加路由
		if err := rm.addRoute(ctx, ipNet.String(), rm.originalGateway); err != nil {
			logger.Warn(ctx, map[string]interface{}{
				"action": config.ActionRuntime,
				"cidr":   ipNet.String(),
				"error":  err,
			}, "failed to add China IP route")
			continue
		}

		addedCount++
	}

	logger.Info(ctx, map[string]interface{}{
		"action": config.ActionRuntime,
		"count":  addedCount,
	}, "added China IP routes")

	return nil
}

// addWhiteListRoutes 添加白名单路由
func (rm *RouteManager) addWhiteListRoutes(ctx *context.Context) error {
	engine := GetRuleEngine()
	engine.mu.RLock()
	rules := engine.whiteRules
	engine.mu.RUnlock()

	for _, rule := range rules {
		// 只处理IP相关的规则（CIDR和IP范围）
		// 使用类型断言检查规则类型
		if cidrRule, ok := rule.(*cidrRule); ok {
			if err := rm.addRoute(ctx, cidrRule.network.String(), rm.originalGateway); err != nil {
				logger.Warn(ctx, map[string]interface{}{
					"action": config.ActionRuntime,
					"cidr":   cidrRule.network.String(),
					"error":  err,
				}, "failed to add whitelist route")
			}
		} else if ipRangeRule, ok := rule.(*ipRangeRule); ok {
			// IP范围需要转换为多个路由或单个大范围路由
			// 这里简化处理，添加起始IP的路由
			cidr := ipRangeRule.start.String() + "/32"
			if err := rm.addRoute(ctx, cidr, rm.originalGateway); err != nil {
				logger.Warn(ctx, map[string]interface{}{
					"action": config.ActionRuntime,
					"ip":     ipRangeRule.start.String(),
					"error":  err,
				}, "failed to add whitelist route")
			}
		}
		// 域名规则不需要添加路由，在路由决策时处理
	}

	return nil
}

// setDefaultRoute 设置默认路由到 TUN 接口
func (rm *RouteManager) setDefaultRoute(ctx *context.Context) error {
	switch runtime.GOOS {
	case "windows":
		// Windows 下默认路由需要指定网关 IP，这里使用 TUN 地址作为网关
		if rm.tunGateway == "" {
			return fmt.Errorf("tun gateway is empty")
		}
		// 使用较高的 metric（10），确保更具体的路由（如 /32）优先
		return rm.addDefaultRouteWindows(ctx, rm.tunGateway)
	default:
		// 其他平台沿用原逻辑（后续可根据需要细化为 dev 语义）
		return rm.addRoute(ctx, "0.0.0.0/0", rm.tunInterface)
	}
}

// addDefaultRouteWindows 添加 Windows 默认路由（使用较高 metric）
func (rm *RouteManager) addDefaultRouteWindows(ctx *context.Context, gateway string) error {
	// Windows 下，使用 metric 10 确保更具体的路由优先
	cmd := exec.Command("route", "add", "0.0.0.0", "mask", "0.0.0.0", gateway, "metric", "10")
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("route add default failed: %w, output: %s", err, string(output))
	}
	return nil
}

// deleteDefaultRoute 删除默认路由
func (rm *RouteManager) deleteDefaultRoute(ctx *context.Context) error {
	switch runtime.GOOS {
	case "windows":
		// Windows 下删除默认路由需要指定网关
		if rm.tunGateway == "" {
			return fmt.Errorf("tun gateway is empty")
		}
		cmd := exec.Command("route", "delete", "0.0.0.0", "mask", "0.0.0.0", rm.tunGateway)
		output, err := cmd.CombinedOutput()
		if err != nil {
			return fmt.Errorf("route delete default failed: %w, output: %s", err, string(output))
		}
		return nil
	default:
		return rm.deleteRoute(ctx, "0.0.0.0/0", rm.tunInterface)
	}
}

// addRoute 添加路由
func (rm *RouteManager) addRoute(ctx *context.Context, network, gateway string) error {
	switch runtime.GOOS {
	case "windows":
		return rm.addRouteWindows(ctx, network, gateway)
	case "linux":
		return rm.addRouteLinux(ctx, network, gateway)
	case "darwin":
		return rm.addRouteDarwin(ctx, network, gateway)
	default:
		return fmt.Errorf("unsupported OS: %s", runtime.GOOS)
	}
}

// deleteRoute 删除路由
func (rm *RouteManager) deleteRoute(ctx *context.Context, network, gateway string) error {
	switch runtime.GOOS {
	case "windows":
		return rm.deleteRouteWindows(ctx, network, gateway)
	case "linux":
		return rm.deleteRouteLinux(ctx, network, gateway)
	case "darwin":
		return rm.deleteRouteDarwin(ctx, network, gateway)
	default:
		return fmt.Errorf("unsupported OS: %s", runtime.GOOS)
	}
}

// getDefaultGateway 获取默认网关
func (rm *RouteManager) getDefaultGateway(ctx *context.Context) (string, error) {
	switch runtime.GOOS {
	case "windows":
		return rm.getDefaultGatewayWindows(ctx)
	case "linux":
		return rm.getDefaultGatewayLinux(ctx)
	case "darwin":
		return rm.getDefaultGatewayDarwin(ctx)
	default:
		return "", fmt.Errorf("unsupported OS: %s", runtime.GOOS)
	}
}

// getDefaultInterfaceIP 获取默认接口的 IP 地址
// 用于绑定远程连接，确保不走 TUN
func (rm *RouteManager) getDefaultInterfaceIP(ctx *context.Context) (net.IP, error) {
	switch runtime.GOOS {
	case "windows":
		return rm.getDefaultInterfaceIPWindows(ctx)
	case "linux":
		return rm.getDefaultInterfaceIPLinux(ctx)
	case "darwin":
		return rm.getDefaultInterfaceIPDarwin(ctx)
	default:
		return nil, fmt.Errorf("unsupported OS: %s", runtime.GOOS)
	}
}

// Windows 实现
func (rm *RouteManager) getDefaultGatewayWindows(ctx *context.Context) (string, error) {
	cmd := exec.Command("route", "print", "0.0.0.0")
	output, err := cmd.Output()
	if err != nil {
		return "", err
	}

	// 解析输出，查找默认网关
	lines := strings.Split(string(output), "\n")
	for _, line := range lines {
		if strings.Contains(line, "0.0.0.0") {
			fields := strings.Fields(line)
			// 检查是否是默认路由行（包含两个 0.0.0.0）
			if len(fields) >= 3 && fields[0] == "0.0.0.0" && fields[1] == "0.0.0.0" {
				return fields[2], nil
			}
		}
	}

	return "", fmt.Errorf("default gateway not found")
}

func (rm *RouteManager) addRouteWindows(ctx *context.Context, network, gateway string) error {
	// 解析网络
	_, ipNet, err := net.ParseCIDR(network)
	if err != nil {
		return err
	}

	// 使用 route add 命令
	// metric 1 确保优先级最高，比默认路由的 metric 10 更优先
	// Windows 的 metric 值必须大于 0，所以使用 1 作为最高优先级
	cmd := exec.Command("route", "add", ipNet.IP.String(), "mask", net.IP(ipNet.Mask).String(), gateway, "metric", "1", "if", "0")
	output, err := cmd.CombinedOutput()
	if err != nil {
		// 如果失败，尝试不使用 if 参数
		cmd = exec.Command("route", "add", ipNet.IP.String(), "mask", net.IP(ipNet.Mask).String(), gateway, "metric", "1")
		output, err = cmd.CombinedOutput()
		if err != nil {
			return fmt.Errorf("route add failed: %w, output: %s", err, string(output))
		}
	}
	return nil
}

func (rm *RouteManager) deleteRouteWindows(ctx *context.Context, network, gateway string) error {
	_, ipNet, err := net.ParseCIDR(network)
	if err != nil {
		return err
	}

	cmd := exec.Command("route", "delete", ipNet.IP.String(), "mask", net.IP(ipNet.Mask).String(), gateway)
	return cmd.Run()
}

// Linux 实现
func (rm *RouteManager) getDefaultGatewayLinux(ctx *context.Context) (string, error) {
	cmd := exec.Command("ip", "route", "show", "default")
	output, err := cmd.Output()
	if err != nil {
		return "", err
	}

	// 解析输出
	line := strings.TrimSpace(string(output))
	fields := strings.Fields(line)
	for i, field := range fields {
		if field == "via" && i+1 < len(fields) {
			return fields[i+1], nil
		}
	}

	return "", fmt.Errorf("default gateway not found")
}

func (rm *RouteManager) addRouteLinux(ctx *context.Context, network, gateway string) error {
	cmd := exec.Command("ip", "route", "add", network, "via", gateway)
	return cmd.Run()
}

func (rm *RouteManager) deleteRouteLinux(ctx *context.Context, network, gateway string) error {
	cmd := exec.Command("ip", "route", "delete", network, "via", gateway)
	return cmd.Run()
}

// macOS 实现
func (rm *RouteManager) getDefaultGatewayDarwin(ctx *context.Context) (string, error) {
	cmd := exec.Command("route", "-n", "get", "default")
	output, err := cmd.Output()
	if err != nil {
		return "", err
	}

	// 解析输出
	lines := strings.Split(string(output), "\n")
	for _, line := range lines {
		if strings.Contains(line, "gateway:") {
			fields := strings.Fields(line)
			if len(fields) >= 2 {
				return fields[1], nil
			}
		}
	}

	return "", fmt.Errorf("default gateway not found")
}

func (rm *RouteManager) addRouteDarwin(ctx *context.Context, network, gateway string) error {
	_, ipNet, err := net.ParseCIDR(network)
	if err != nil {
		return err
	}

	cmd := exec.Command("route", "add", "-net", ipNet.IP.String(), "-netmask", net.IP(ipNet.Mask).String(), gateway)
	return cmd.Run()
}

func (rm *RouteManager) deleteRouteDarwin(ctx *context.Context, network, gateway string) error {
	_, ipNet, err := net.ParseCIDR(network)
	if err != nil {
		return err
	}

	cmd := exec.Command("route", "delete", "-net", ipNet.IP.String(), "-netmask", net.IP(ipNet.Mask).String(), gateway)
	return cmd.Run()
}

// getDefaultInterfaceIPWindows 获取 Windows 默认接口的 IP 地址
func (rm *RouteManager) getDefaultInterfaceIPWindows(ctx *context.Context) (net.IP, error) {
	// 获取默认网关
	gateway, err := rm.getDefaultGatewayWindows(ctx)
	if err != nil {
		return nil, err
	}

	// 通过默认网关找到对应的接口
	// 使用 route print 查找默认路由对应的接口
	cmd := exec.Command("route", "print", "0.0.0.0")
	output, err := cmd.Output()
	if err != nil {
		return nil, err
	}

	// 解析输出，查找默认路由对应的接口索引
	lines := strings.Split(string(output), "\n")
	var interfaceIndex string
	for _, line := range lines {
		if strings.Contains(line, "0.0.0.0") {
			fields := strings.Fields(line)
			// 检查是否是默认路由行（包含两个 0.0.0.0）
			if len(fields) >= 5 && fields[0] == "0.0.0.0" && fields[1] == "0.0.0.0" {
				interfaceIndex = fields[3] // 接口索引通常在字段3
				break
			}
		}
	}

	if interfaceIndex == "" {
		// 如果找不到接口索引，尝试通过网关 IP 查找接口
		return rm.findInterfaceIPByGateway(gateway)
	}

	// 使用 netsh 获取接口 IP
	cmd = exec.Command("netsh", "interface", "ip", "show", "address", "index="+interfaceIndex)
	output, err = cmd.Output()
	if err != nil {
		return rm.findInterfaceIPByGateway(gateway)
	}

	// 解析输出，查找 IP 地址
	outputStr := string(output)
	lines = strings.Split(outputStr, "\n")
	for _, line := range lines {
		if strings.Contains(line, "IP Address:") {
			fields := strings.Fields(line)
			for i, field := range fields {
				if field == "Address:" && i+1 < len(fields) {
					ip := net.ParseIP(fields[i+1])
					if ip != nil && ip.To4() != nil {
						return ip, nil
					}
				}
			}
		}
	}

	// 如果解析失败，尝试通过网关查找
	return rm.findInterfaceIPByGateway(gateway)
}

// findInterfaceIPByGateway 通过网关 IP 查找接口 IP
func (rm *RouteManager) findInterfaceIPByGateway(gateway string) (net.IP, error) {
	gatewayIP := net.ParseIP(gateway)
	if gatewayIP == nil {
		return nil, fmt.Errorf("invalid gateway IP: %s", gateway)
	}

	// 遍历所有接口，找到与网关在同一网段的接口 IP
	interfaces, err := net.Interfaces()
	if err != nil {
		return nil, err
	}

	for _, iface := range interfaces {
		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}
		for _, addr := range addrs {
			if ipNet, ok := addr.(*net.IPNet); ok {
				if ip := ipNet.IP.To4(); ip != nil {
					// 检查网关是否在同一网段
					if ipNet.Contains(gatewayIP) {
						return ip, nil
					}
				}
			}
		}
	}

	return nil, fmt.Errorf("interface IP not found for gateway: %s", gateway)
}

// getDefaultInterfaceIPLinux 获取 Linux 默认接口的 IP 地址
func (rm *RouteManager) getDefaultInterfaceIPLinux(ctx *context.Context) (net.IP, error) {
	// 获取默认路由，找到对应的接口
	cmd := exec.Command("ip", "route", "show", "default")
	output, err := cmd.Output()
	if err != nil {
		return nil, err
	}

	// 解析输出，查找接口名称
	line := strings.TrimSpace(string(output))
	fields := strings.Fields(line)
	var interfaceName string
	for i, field := range fields {
		if field == "dev" && i+1 < len(fields) {
			interfaceName = fields[i+1]
			break
		}
	}

	if interfaceName == "" {
		return nil, fmt.Errorf("default interface not found")
	}

	// 获取接口 IP
	iface, err := net.InterfaceByName(interfaceName)
	if err != nil {
		return nil, err
	}

	addrs, err := iface.Addrs()
	if err != nil {
		return nil, err
	}

	// 返回第一个 IPv4 地址
	for _, addr := range addrs {
		if ipNet, ok := addr.(*net.IPNet); ok {
			if ip := ipNet.IP.To4(); ip != nil {
				return ip, nil
			}
		}
	}

	return nil, fmt.Errorf("no IPv4 address found on interface: %s", interfaceName)
}

// getDefaultInterfaceIPDarwin 获取 macOS 默认接口的 IP 地址
func (rm *RouteManager) getDefaultInterfaceIPDarwin(ctx *context.Context) (net.IP, error) {
	// 获取默认路由，找到对应的接口
	cmd := exec.Command("route", "-n", "get", "default")
	output, err := cmd.Output()
	if err != nil {
		return nil, err
	}

	// 解析输出，查找接口名称
	lines := strings.Split(string(output), "\n")
	var interfaceName string
	for _, line := range lines {
		if strings.Contains(line, "interface:") {
			fields := strings.Fields(line)
			if len(fields) >= 2 {
				interfaceName = fields[1]
				break
			}
		}
	}

	if interfaceName == "" {
		return nil, fmt.Errorf("default interface not found")
	}

	// 获取接口 IP
	iface, err := net.InterfaceByName(interfaceName)
	if err != nil {
		return nil, err
	}

	addrs, err := iface.Addrs()
	if err != nil {
		return nil, err
	}

	// 返回第一个 IPv4 地址
	for _, addr := range addrs {
		if ipNet, ok := addr.(*net.IPNet); ok {
			if ip := ipNet.IP.To4(); ip != nil {
				return ip, nil
			}
		}
	}

	return nil, fmt.Errorf("no IPv4 address found on interface: %s", interfaceName)
}
