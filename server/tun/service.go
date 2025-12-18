package tun

import (
	"fmt"
	"net"
	"os"
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
		logger.Warn(ctx, map[string]interface{}{
			"action": config.ActionRuntime,
			"error":  err,
		}, "failed to configure device IP, may need manual configuration")
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
func configureDeviceIP(device Device, config *Config) error {
	// 这个函数在不同平台有不同的实现
	// Windows: 使用winipcfg或netsh命令
	// Linux: 使用ip命令或netlink
	// macOS: 使用ifconfig命令
	// 这里暂时返回nil，实际实现应该在平台特定文件中
	return nil
}


