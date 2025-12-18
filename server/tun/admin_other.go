//go:build !windows

package tun

import (
	"fmt"
	"os"
)

// isAdmin 检查当前进程是否具有 root 权限（Linux/macOS）
func isAdmin() bool {
	// 检查有效用户ID（EUID），root用户的EUID为0
	return os.Geteuid() == 0
}

// elevatePrivileges 非 Windows 平台不支持自动提权，直接返回提示错误
func elevatePrivileges() error {
	return fmt.Errorf("automatic privilege elevation is not supported on this platform, please run with sudo or as root")
}


