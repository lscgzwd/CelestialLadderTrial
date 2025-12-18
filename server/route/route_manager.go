package route

import (
	"fmt"
	"net"
	"os"
	"os/exec"
	"runtime"
	"strings"

	"proxy/config"
	"proxy/utils/context"
	"proxy/utils/logger"
)

// RouteManager 路由管理器
type RouteManager struct {
	originalGateway string
	tunInterface    string
	backedUp        bool
}

// NewRouteManager 创建路由管理器
func NewRouteManager(tunInterface string) *RouteManager {
	return &RouteManager{
		tunInterface: tunInterface,
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

	// 1. 添加本地网络路由（不走 TUN）
	if err := rm.addLocalNetworkRoutes(ctx); err != nil {
		return fmt.Errorf("failed to add local network routes: %w", err)
	}

	// 2. 添加中国 IP 段路由（不走 TUN）
	if err := rm.addChinaIpRoutes(ctx); err != nil {
		return fmt.Errorf("failed to add China IP routes: %w", err)
	}

	// 3. 添加白名单路由（不走 TUN）
	if err := rm.addWhiteListRoutes(ctx); err != nil {
		return fmt.Errorf("failed to add whitelist routes: %w", err)
	}

	// 4. 设置默认路由到 TUN 接口
	if err := rm.setDefaultRoute(ctx); err != nil {
		return fmt.Errorf("failed to set default route: %w", err)
	}

	logger.Info(ctx, map[string]interface{}{
		"action": config.ActionRuntime,
	}, "routes configured successfully")

	return nil
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
		"127.0.0.0/8",     // 本地回环
		"10.0.0.0/8",      // 私有网络
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
	return rm.addRoute(ctx, "0.0.0.0/0", rm.tunInterface)
}

// deleteDefaultRoute 删除默认路由
func (rm *RouteManager) deleteDefaultRoute(ctx *context.Context) error {
	return rm.deleteRoute(ctx, "0.0.0.0/0", rm.tunInterface)
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
		if strings.Contains(line, "0.0.0.0") && strings.Contains(line, "0.0.0.0") {
			fields := strings.Fields(line)
			if len(fields) >= 3 {
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
	cmd := exec.Command("route", "add", ipNet.IP.String(), "mask", net.IP(ipNet.Mask).String(), gateway, "metric", "1")
	return cmd.Run()
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


