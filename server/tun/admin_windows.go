//go:build windows

package tun

import (
	"fmt"
	"os"
	"os/exec"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

// isAdmin 检查当前进程是否具有管理员权限（Windows）
func isAdmin() bool {
	// 获取当前进程令牌
	token := windows.Token(0)

	// 构造 Administrators 组 SID
	var sid *windows.SID
	err := windows.AllocateAndInitializeSid(
		&windows.SECURITY_NT_AUTHORITY,
		2,
		windows.SECURITY_BUILTIN_DOMAIN_RID,
		windows.DOMAIN_ALIAS_RID_ADMINS,
		0, 0, 0, 0, 0, 0,
		&sid,
	)
	if err != nil {
		return false
	}
	defer windows.FreeSid(sid)

	isMember, err := token.IsMember(sid)
	if err != nil {
		return false
	}
	return isMember
}

// elevatePrivileges 尝试以管理员权限重新启动程序（Windows UAC）
func elevatePrivileges() error {
	// 获取当前可执行文件路径
	exe, err := os.Executable()
	if err != nil {
		return fmt.Errorf("无法获取可执行文件路径: %w", err)
	}

	// 获取命令行参数
	args := os.Args[1:]

	// 优先使用 PowerShell 的 Start-Process -Verb RunAs（会触发 UAC）
	if err := tryPowerShellElevate(exe, args); err == nil {
		return nil
	}

	// 如果 PowerShell 失败，尝试使用 ShellExecuteEx API
	return tryShellExecuteElevate(exe, args)
}

// tryShellExecuteElevate 使用 ShellExecuteEx API 提升权限
func tryShellExecuteElevate(exe string, args []string) error {
	shell32 := windows.NewLazySystemDLL("shell32.dll")
	shellExecuteW := shell32.NewProc("ShellExecuteW")

	verb, _ := windows.UTF16PtrFromString("runas")
	exeUTF16, _ := windows.UTF16PtrFromString(exe)

	var argsUTF16 *uint16
	if len(args) > 0 {
		argsStr := joinArgs(args)
		argsUTF16, _ = windows.UTF16PtrFromString(argsStr)
	}

	ret, _, _ := shellExecuteW.Call(
		0,                              // hwnd
		uintptr(unsafe.Pointer(verb)),  // lpVerb
		uintptr(unsafe.Pointer(exeUTF16)), // lpFile
		uintptr(unsafe.Pointer(argsUTF16)), // lpParameters
		0,                               // lpDirectory
		windows.SW_NORMAL,               // nShow
	)

	// ShellExecuteW 返回值 > 32 表示成功
	if ret <= 32 {
		return fmt.Errorf("ShellExecuteW 失败，错误代码: %d", ret)
	}

	return nil
}

// tryPowerShellElevate 使用 PowerShell 尝试提升权限
func tryPowerShellElevate(exe string, args []string) error {
	// 构建 PowerShell 命令
	// 使用 -ArgumentList 数组格式，更安全
	argsList := ""
	for i, arg := range args {
		if i > 0 {
			argsList += ","
		}
		// PowerShell 需要转义引号
		escapedArg := escapePowerShellArg(arg)
		argsList += fmt.Sprintf(`'%s'`, escapedArg)
	}

	var psCmd string
	if len(args) > 0 {
		psCmd = fmt.Sprintf(`Start-Process -FilePath '%s' -ArgumentList %s -Verb RunAs`, exe, argsList)
	} else {
		psCmd = fmt.Sprintf(`Start-Process -FilePath '%s' -Verb RunAs`, exe)
	}

	cmd := exec.Command("powershell", "-Command", psCmd)
	cmd.SysProcAttr = &syscall.SysProcAttr{
		HideWindow: true,
	}

	return cmd.Start()
}

// escapePowerShellArg 转义 PowerShell 参数
func escapePowerShellArg(s string) string {
	// PowerShell 中单引号需要转义为 ''
	result := ""
	for _, r := range s {
		if r == '\'' {
			result += "''"
		} else {
			result += string(r)
		}
	}
	return result
}

// joinArgs 连接参数
func joinArgs(args []string) string {
	result := ""
	for i, arg := range args {
		if i > 0 {
			result += " "
		}
		// 转义引号和空格
		if containsSpace(arg) || containsQuote(arg) {
			result += `"` + escapeQuotes(arg) + `"`
		} else {
			result += arg
		}
	}
	return result
}

// containsQuote 检查字符串是否包含引号
func containsQuote(s string) bool {
	for _, r := range s {
		if r == '"' {
			return true
		}
	}
	return false
}

// containsSpace 检查字符串是否包含空格
func containsSpace(s string) bool {
	for _, r := range s {
		if r == ' ' {
			return true
		}
	}
	return false
}

// escapeQuotes 转义引号
func escapeQuotes(s string) string {
	result := ""
	for _, r := range s {
		if r == '"' {
			result += `\"`
		} else {
			result += string(r)
		}
	}
	return result
}


