package tun

import (
	"fmt"
	"net"
	"os"
	"os/exec"
	"runtime"

	"proxy/config"
	"proxy/server/route"
	"proxy/utils/context"
	"proxy/utils/logger"
)

// Service TUN服务
type Service struct {
	device      Device
	handler     *Handler
	routeMgr    *route.RouteManager
	ipAllocator *IPAllocator
	ctx         *context.Context
}

// NewService 创建TUN服务
func NewService() (*Service, error) {
	if !config.Config.Tun.Enable {
		return nil, nil
	}

	// 检查权限
	if !isAdmin() {
		if runtime.GOOS == "windows" {
			// Windows: 尝试提升权限
			if err := elevatePrivileges(); err != nil {
				return nil, fmt.Errorf("TUN 模式需要管理员权限。尝试自动提升权限失败: %v。请右键以“管理员身份运行”启动此程序", err)
			}
			// 权限提升成功，当前进程退出，新进程会以管理员权限启动
			os.Exit(0)
		} else {
			// Linux/macOS: 提示使用 sudo
			return nil, fmt.Errorf("TUN 模式需要 root 权限。请使用 sudo 运行此程序")
		}
	}

	ctx := context.NewContext()

	// 创建IP分配器
	ipAllocator := NewIPAllocator()

	// 自动选择未使用的私有IP段
	network, gatewayIP, err := ipAllocator.FindAvailableNetwork()
	if err != nil {
		return nil, fmt.Errorf("failed to find available network: %w", err)
	}

	logger.Info(ctx, map[string]interface{}{
		"action":  config.ActionRuntime,
		"network": network.String(),
		"gateway": gatewayIP.String(),
	}, "found available network")

	// 创建TUN配置
	tunConfig := &Config{
		Name:    config.Config.Tun.Name,
		Address: gatewayIP,
		Netmask: network.Mask,
		MTU:     config.Config.Tun.MTU,
	}

	// 解析DNS配置
	if len(config.Config.Tun.DNS) > 0 {
		tunConfig.DNS = make([]net.IP, 0, len(config.Config.Tun.DNS))
		for _, dnsStr := range config.Config.Tun.DNS {
			if dnsIP := net.ParseIP(dnsStr); dnsIP != nil {
				tunConfig.DNS = append(tunConfig.DNS, dnsIP)
			}
		}
	}

	// 如果没有配置DNS，使用默认值
	if len(tunConfig.DNS) == 0 {
		tunConfig.DNS = []net.IP{
			net.ParseIP("8.8.8.8"),
			net.ParseIP("8.8.4.4"),
		}
	}

	// 如果没有配置名称，使用默认值
	if tunConfig.Name == "" {
		tunConfig.Name = "clt0"
	}

	// 如果没有配置MTU，使用默认值
	if tunConfig.MTU == 0 {
		tunConfig.MTU = 1500
	}

	// 创建TUN设备
	device, err := New(tunConfig)
	if err != nil {
		return nil, fmt.Errorf("failed to create TUN device: %w", err)
	}

	// 启动TUN接口
	if err := device.Up(); err != nil {
		device.Close()
		return nil, fmt.Errorf("failed to start TUN device: %w", err)
	}

	// 配置IP地址（平台特定）
	if err := configureDeviceIP(device, tunConfig); err != nil {
		device.Close()
		return nil, fmt.Errorf("failed to configure TUN device IP: %w", err)
	}

	// 创建路由管理器
	routeMgr := route.NewRouteManager(device.Name())

	// 备份路由表
	if err := routeMgr.BackupRoutes(ctx); err != nil {
		device.Close()
		return nil, fmt.Errorf("failed to backup routes: %w", err)
	}

	// 配置路由表
	if err := routeMgr.SetupRoutes(ctx); err != nil {
		device.Close()
		routeMgr.RestoreRoutes(ctx)
		return nil, fmt.Errorf("failed to setup routes: %w", err)
	}

	// 创建SOCKS5地址
	socks5Addr := fmt.Sprintf("127.0.0.1:%d", config.Config.In.Port)

	// 创建处理器
	handler := NewHandler(device, socks5Addr)

	return &Service{
		device:      device,
		handler:     handler,
		routeMgr:    routeMgr,
		ipAllocator: ipAllocator,
		ctx:         ctx,
	}, nil
}

// Start 启动TUN服务
func (s *Service) Start() error {
	if s == nil {
		return nil
	}

	logger.Info(s.ctx, map[string]interface{}{
		"action": config.ActionRuntime,
	}, "TUN service started")

	// 启动数据包处理循环
	return s.handler.Start()
}

// Stop 停止TUN服务
func (s *Service) Stop() error {
	if s == nil {
		return nil
	}

	logger.Info(s.ctx, map[string]interface{}{
		"action": config.ActionRuntime,
	}, "TUN service stopping")

	// 恢复路由表
	if s.routeMgr != nil {
		s.routeMgr.RestoreRoutes(s.ctx)
	}

	// 关闭TUN设备
	if s.device != nil {
		s.device.Down()
		s.device.Close()
	}

	// 释放网络
	if s.ipAllocator != nil && s.device != nil {
		// 获取设备网络信息
		// 这里简化处理，实际应该从配置中获取
	}

	logger.Info(s.ctx, map[string]interface{}{
		"action": config.ActionRuntime,
	}, "TUN service stopped")

	return nil
}

// configureDeviceIP 配置设备IP地址（平台特定）
func configureDeviceIP(device Device, cfg *Config) error {
	name := device.Name()
	if name == "" {
		return fmt.Errorf("device name is empty")
	}

	ipAddr := cfg.Address
	if ipAddr == nil {
		ipAddr = net.ParseIP("10.0.0.1")
	}
	if ipAddr.To4() == nil {
		return fmt.Errorf("only IPv4 is supported")
	}

	prefixLen := 24
	if cfg.Netmask != nil {
		if ones, _ := cfg.Netmask.Size(); ones > 0 {
			prefixLen = ones
		}
	}

	switch runtime.GOOS {
	case "windows":
		// Windows 在 tun_windows.go 中已经通过 netsh 配置过 IP，这里不重复配置
		return nil

	case "linux":
		// 使用 ip 命令配置：ip addr add <ip>/<prefix> dev <name>
		cidr := fmt.Sprintf("%s/%d", ipAddr.String(), prefixLen)
		cmd := exec.Command("ip", "addr", "add", cidr, "dev", name)
		if out, err := cmd.CombinedOutput(); err != nil {
			return fmt.Errorf("linux: failed to add addr %s on %s: %w, output: %s", cidr, name, err, string(out))
		}
		// 启动接口：ip link set <name> up
		cmd = exec.Command("ip", "link", "set", name, "up")
		if out, err := cmd.CombinedOutput(); err != nil {
			return fmt.Errorf("linux: failed to set link up on %s: %w, output: %s", name, err, string(out))
		}
		return nil

	case "darwin":
		// macOS 使用 ifconfig 配置：ifconfig <name> inet <ip> <ip> netmask <mask> up
		mask := net.CIDRMask(prefixLen, 32)
		maskIP := net.IP(mask).String()
		cmd := exec.Command("ifconfig", name, "inet", ipAddr.String(), ipAddr.String(), "netmask", maskIP, "up")
		if out, err := cmd.CombinedOutput(); err != nil {
			return fmt.Errorf("darwin: failed to configure %s: %w, output: %s", name, err, string(out))
		}
		return nil

	default:
		// 其他平台暂不支持
		return nil
	}
}
