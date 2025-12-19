package common

import (
	"net"
	"runtime"
	"sync"
	"time"

	"proxy/utils/context"
	"proxy/utils/logger"
)

var (
	globalDialer     *net.Dialer
	globalDialerOnce sync.Once
	globalDialerMu   sync.RWMutex
)

// GetOriginalInterfaceDialer 获取绑定到原默认接口的 Dialer
// 所有远程连接（Direct/WSS/TLS）都应该使用这个 Dialer，确保不走 TUN
func GetOriginalInterfaceDialer() *net.Dialer {
	globalDialerOnce.Do(func() {
		// 默认 Dialer，不绑定接口（如果还没初始化 RouteManager）
		globalDialer = &net.Dialer{
			Timeout: 10 * time.Second,
		}
	})

	globalDialerMu.RLock()
	defer globalDialerMu.RUnlock()
	return globalDialer
}

// SetOriginalInterfaceIP 设置原默认接口的 IP 地址
// 调用后，所有通过 GetOriginalInterfaceDialer() 获取的 Dialer 都会绑定到这个 IP
func SetOriginalInterfaceIP(ctx *context.Context, ip net.IP) {
	if ip == nil {
		return
	}

	globalDialerMu.Lock()
	defer globalDialerMu.Unlock()

	// 创建绑定到原接口 IP 的 Dialer
	// Windows 下使用 Control 函数设置 socket 选项，强制走原接口
	globalDialer = &net.Dialer{
		LocalAddr: &net.TCPAddr{
			IP:   ip,
			Port: 0, // 系统自动分配端口
		},
		Timeout: 10 * time.Second,
	}

	// 注意：绑定接口主要通过 LocalAddr 实现
	// Windows/Linux 都通过 LocalAddr 指定源 IP，配合路由表实现接口绑定
	_ = runtime.GOOS // 标记使用

	logger.Info(ctx, map[string]interface{}{
		"action": "Runtime",
		"ip":     ip.String(),
		"os":     runtime.GOOS,
	}, "set original interface IP for remote connections")
}


