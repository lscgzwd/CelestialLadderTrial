//go:build windows

package tun

import (
	"fmt"
	"net"
	"os/exec"

	"golang.zx2c4.com/wireguard/tun"
)

func newDevice(config *Config) (Device, error) {
	// 使用 WireGuard TUN 实现
	dev, err := tun.CreateTUN(config.Name, config.MTU)
	if err != nil {
		return nil, fmt.Errorf("failed to create TUN device: %w", err)
	}

	// 配置 IP 地址
	if err := configureWindows(dev, config); err != nil {
		dev.Close()
		return nil, fmt.Errorf("failed to configure TUN device: %w", err)
	}

	return &windowsDevice{
		dev:    dev,
		config: config,
	}, nil
}

type windowsDevice struct {
	dev    tun.Device
	config *Config
}

func (d *windowsDevice) Read(b []byte, offset int) (int, error) {
	// WireGuard TUN Read 需要 [][]byte 和 []int
	bufs := [][]byte{b[offset:]}
	sizes := make([]int, 1)
	n, err := d.dev.Read(bufs, sizes, offset)
	if n > 0 {
		return sizes[0], err
	}
	return 0, err
}

func (d *windowsDevice) Write(b []byte, offset int) (int, error) {
	// WireGuard TUN Write 需要 [][]byte
	bufs := [][]byte{b[offset:]}
	return d.dev.Write(bufs, offset)
}

func (d *windowsDevice) Close() error {
	return d.dev.Close()
}

func (d *windowsDevice) Name() string {
	name, _ := d.dev.Name()
	return name
}

func (d *windowsDevice) MTU() (int, error) {
	return d.dev.MTU()
}

func (d *windowsDevice) Up() error {
	// Windows TUN 设备创建后自动启动
	return nil
}

func (d *windowsDevice) Down() error {
	// Windows TUN 设备关闭时自动停止
	return nil
}

func configureWindows(dev tun.Device, config *Config) error {
	// 获取 TUN 设备名称
	name, err := dev.Name()
	if err != nil {
		return fmt.Errorf("failed to get device name: %w", err)
	}

	// 计算 IP 地址和子网掩码
	ipAddr := config.Address
	if ipAddr == nil {
		ipAddr = net.ParseIP("10.0.0.1")
	}
	if ipAddr.To4() == nil {
		return fmt.Errorf("only IPv4 is supported")
	}

	prefixLen := 24 // 默认 /24
	if config.Netmask != nil {
		ones, _ := config.Netmask.Size()
		prefixLen = ones
	}

	// 将前缀长度转换为子网掩码字符串
	mask := net.CIDRMask(prefixLen, 32)
	maskIP := net.IP(mask)
	maskStr := maskIP.String()

	// 使用 netsh 命令配置 IP 地址（需要管理员权限）
	// netsh interface ip set address name="<name>" static <ip> <mask> none
	cmd := exec.Command(
		"netsh", "interface", "ip", "set", "address",
		"name="+name,
		"static",
		ipAddr.String(),
		maskStr,
		"none",
	)
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("configure TUN IP failed: %w, output: %s", err, string(out))
	}

	// 配置 DNS（如果有）
	if len(config.DNS) > 0 {
		// 先设置主 DNS
		dns0 := config.DNS[0]
		if dns0 != nil {
			cmdDNS := exec.Command(
				"netsh", "interface", "ip", "set", "dns",
				"name="+name,
				"static",
				dns0.String(),
				"primary",
			)
			if out, err := cmdDNS.CombinedOutput(); err != nil {
				return fmt.Errorf("configure TUN DNS failed: %w, output: %s", err, string(out))
			}
		}
		// 追加其他 DNS
		for i := 1; i < len(config.DNS); i++ {
			dnsIP := config.DNS[i]
			if dnsIP == nil {
				continue
			}
			cmdDNS := exec.Command(
				"netsh", "interface", "ip", "add", "dns",
				"name="+name,
				dnsIP.String(),
				"index=2",
			)
			_, _ = cmdDNS.CombinedOutput() // 失败不致命，忽略错误
		}
	}

	return nil
}

