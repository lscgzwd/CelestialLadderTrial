// tun2socks.go - 使用 tun2socks engine 的 TUN 实现
// 这是最成熟可靠的方案，直接复用 tun2socks 的完整实现
package tun

import (
	"fmt"
	"net"
	"runtime"
	"time"

	"github.com/xjasonlyu/tun2socks/v2/engine"

	"proxy/config"
	utilContext "proxy/utils/context"
	"proxy/utils/logger"
)

// Tun2SocksService 使用 tun2socks engine 的 TUN 服务
type Tun2SocksService struct {
	tunName    string
	socks5Addr string
	tunIP      net.IP
	tunMask    net.IPMask
	mtu        int
	ctx        *utilContext.Context
	started    bool
}

// NewTun2SocksService 创建新的 tun2socks 服务
func NewTun2SocksService(tunName string, socks5Addr string, tunIP net.IP, tunMask net.IPMask, mtu int) *Tun2SocksService {
	return &Tun2SocksService{
		tunName:    tunName,
		socks5Addr: socks5Addr,
		tunIP:      tunIP,
		tunMask:    tunMask,
		mtu:        mtu,
		ctx:        utilContext.NewContext(),
	}
}

// Start 启动 tun2socks 服务
func (s *Tun2SocksService) Start() error {
	if s.started {
		return nil
	}

	// 构建设备字符串
	deviceStr := s.buildDeviceString()
	
	// 构建代理字符串 (SOCKS5)
	proxyStr := fmt.Sprintf("socks5://%s", s.socks5Addr)

	// 构建 IP 配置命令（TUN 创建后执行）
	postUpCmd := s.buildPostUpCommand()

	// 创建 engine.Key 配置
	key := &engine.Key{
		Device:     deviceStr,
		Proxy:      proxyStr,
		MTU:        s.mtu,
		LogLevel:   "info",
		UDPTimeout: 5 * time.Minute,
		TUNPostUp:  postUpCmd,
	}

	// 加载配置
	engine.Insert(key)

	// 启动 engine（这会创建 TUN 设备和 gvisor 栈）
	// 注意：Start() 会调用 log.Fatalf，这里需要处理
	go func() {
		defer func() {
			if r := recover(); r != nil {
				logger.Error(s.ctx, map[string]interface{}{
					"action": config.ActionRuntime,
					"error":  r,
				}, "tun2socks engine panic")
			}
		}()
		engine.Start()
	}()

	// 等待一小段时间让 engine 启动
	time.Sleep(500 * time.Millisecond)

	s.started = true

	logger.Info(s.ctx, map[string]interface{}{
		"action":  config.ActionRuntime,
		"device":  deviceStr,
		"proxy":   proxyStr,
		"tunIP":   s.tunIP.String(),
	}, "tun2socks service started")

	return nil
}

// Stop 停止 tun2socks 服务
func (s *Tun2SocksService) Stop() error {
	if !s.started {
		return nil
	}

	engine.Stop()
	s.started = false

	logger.Info(s.ctx, map[string]interface{}{
		"action": config.ActionRuntime,
	}, "tun2socks service stopped")

	return nil
}

// buildDeviceString 构建 tun2socks 设备字符串
// 格式: tun://tunName
func (s *Tun2SocksService) buildDeviceString() string {
	switch runtime.GOOS {
	case "windows":
		// Windows 使用 wintun，设备名作为 host
		return fmt.Sprintf("tun://%s", s.tunName)
	case "darwin":
		// macOS 使用 utun
		return fmt.Sprintf("tun://%s", s.tunName)
	default:
		// Linux 使用 tun
		return fmt.Sprintf("tun://%s", s.tunName)
	}
}

// buildPostUpCommand 构建 TUN 设备 IP 配置命令
// 在 TUN 设备创建后执行，配置 IP 地址
func (s *Tun2SocksService) buildPostUpCommand() string {
	ones, _ := s.tunMask.Size()
	ip := s.tunIP.String()
	name := s.tunName

	switch runtime.GOOS {
	case "windows":
		// Windows 使用 netsh 配置 IP
		// netsh interface ip set address "接口名" static IP掩码
		mask := net.IP(s.tunMask).String()
		return fmt.Sprintf("netsh interface ip set address \"%s\" static %s %s", name, ip, mask)
	case "darwin":
		// macOS 使用 ifconfig
		return fmt.Sprintf("ifconfig %s inet %s/%d %s up", name, ip, ones, ip)
	default:
		// Linux 使用 ip 命令
		return fmt.Sprintf("ip addr add %s/%d dev %s && ip link set %s up", ip, ones, name, name)
	}
}
