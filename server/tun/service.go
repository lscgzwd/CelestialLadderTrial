package tun

import (
	"fmt"
	"net"
	"os"
	"runtime"

	"proxy/config"
	"proxy/server/common"
	"proxy/server/route"
	"proxy/utils/context"
	"proxy/utils/logger"
)

// Service TUN服务
type Service struct {
	tun2socks   *Tun2SocksService
	routeMgr    *route.RouteManager
	ipAllocator *IPAllocator
	tunIP       net.IP
	tunMask     net.IPMask
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
				return nil, fmt.Errorf("TUN 模式需要管理员权限。尝试自动提升权限失败: %v。请右键以管理员身份运行启动此程序", err)
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

	// 设置原接口 IP（在 TUN 启动前，用于远程连接绑定）
	originalIP := getOriginalInterfaceIP()
	if originalIP != nil {
		common.SetOriginalInterfaceIP(ctx, originalIP)
	}

	// 创建路由管理器
	tunName := config.Config.Tun.Name
	if tunName == "" {
		tunName = "clt0"
	}
	routeMgr := route.NewRouteManager(tunName, gatewayIP.String())

	// 设置全局路由管理器，供其他模块使用
	route.SetGlobalRouteManager(routeMgr)

	// 备份路由表（此时 TUN 还未接管流量，DNS 查询正常）
	if err := routeMgr.BackupRoutes(ctx); err != nil {
		return nil, fmt.Errorf("failed to backup routes: %w", err)
	}

	// 配置路由表（包括为远程服务器添加直连路由）
	// 注意：必须在 TUN 启动前配置，确保远程服务器路由已添加
	if err := routeMgr.SetupRoutes(ctx); err != nil {
		routeMgr.RestoreRoutes(ctx)
		return nil, fmt.Errorf("failed to setup routes: %w", err)
	}

	// 创建 SOCKS5 地址
	socks5Addr := fmt.Sprintf("127.0.0.1:%d", config.Config.In.Port)

	// 获取 MTU
	mtu := config.Config.Tun.MTU
	if mtu == 0 {
		mtu = 1500
	}

	// 创建 tun2socks 服务
	tun2socks := NewTun2SocksService(tunName, socks5Addr, gatewayIP, network.Mask, mtu)

	return &Service{
		tun2socks:   tun2socks,
		routeMgr:    routeMgr,
		ipAllocator: ipAllocator,
		tunIP:       gatewayIP,
		tunMask:     network.Mask,
		ctx:         ctx,
	}, nil
}

// Start 启动TUN服务
func (s *Service) Start() error {
	if s == nil {
		return nil
	}

	// 启动 tun2socks
	if err := s.tun2socks.Start(); err != nil {
		return fmt.Errorf("failed to start tun2socks: %w", err)
	}

	logger.Info(s.ctx, map[string]interface{}{
		"action": config.ActionRuntime,
		"tunIP":  s.tunIP.String(),
	}, "TUN service started")

	return nil
}

// Stop 停止TUN服务
func (s *Service) Stop() error {
	if s == nil {
		return nil
	}

	logger.Info(s.ctx, map[string]interface{}{
		"action": config.ActionRuntime,
	}, "TUN service stopping")

	// 停止 tun2socks
	if s.tun2socks != nil {
		s.tun2socks.Stop()
	}

	// 恢复路由表
	if s.routeMgr != nil {
		s.routeMgr.RestoreRoutes(s.ctx)
	}

	logger.Info(s.ctx, map[string]interface{}{
		"action": config.ActionRuntime,
	}, "TUN service stopped")

	return nil
}

// getOriginalInterfaceIP 获取原默认接口的 IP 地址
func getOriginalInterfaceIP() net.IP {
	// 尝试连接一个公共 IP 来确定默认出口接口
	conn, err := net.Dial("udp", "8.8.8.8:80")
	if err != nil {
		return nil
	}
	defer conn.Close()

	localAddr := conn.LocalAddr().(*net.UDPAddr)
	return localAddr.IP
}

// isAdmin 和 elevatePrivileges 在 admin_windows.go 和 admin_other.go 中定义
