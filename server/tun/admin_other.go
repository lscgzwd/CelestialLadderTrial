//go:build !windows

package tun

import (
	"os"
)

// isAdmin 检查当前进程是否具有 root 权限（Linux/macOS）
func isAdmin() bool {
	// 检查有效用户ID（EUID），root用户的EUID为0
	return os.Geteuid() == 0
}


