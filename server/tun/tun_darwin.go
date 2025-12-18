//go:build darwin

package tun

import (
	"fmt"
	"net"
	"os"

	"golang.org/x/sys/unix"
)

func newDevice(config *Config) (Device, error) {
	// macOS 使用 utun 设备
	// 尝试打开 utun0, utun1, ... 直到成功
	var fd int
	var err error
	for i := 0; i < 16; i++ {
		devPath := fmt.Sprintf("/dev/tun%d", i)
		fd, err = unix.Open(devPath, unix.O_RDWR, 0)
		if err == nil {
			break
		}
	}
	if err != nil {
		return nil, fmt.Errorf("failed to open utun device: %w", err)
	}

	// 配置接口
	if err := configureDarwin(fd, config); err != nil {
		unix.Close(fd)
		return nil, fmt.Errorf("failed to configure interface: %w", err)
	}

	file := os.NewFile(uintptr(fd), fmt.Sprintf("/dev/tun%d", 0))
	return &darwinDevice{
		file:   file,
		config: config,
	}, nil
}

type darwinDevice struct {
	file   *os.File
	config *Config
}

func (d *darwinDevice) Read(b []byte, offset int) (int, error) {
	n, err := d.file.Read(b[offset:])
	return n, err
}

func (d *darwinDevice) Write(b []byte, offset int) (int, error) {
	return d.file.Write(b[offset:])
}

func (d *darwinDevice) Close() error {
	return d.file.Close()
}

func (d *darwinDevice) Name() string {
	// macOS utun 设备名称格式为 utun0, utun1, ...
	return "utun0"
}

func (d *darwinDevice) MTU() (int, error) {
	return d.config.MTU, nil
}

func (d *darwinDevice) Up() error {
	// macOS 使用 ifconfig 命令启动接口
	// 这里简化处理，实际应该使用系统调用或执行命令
	return nil
}

func (d *darwinDevice) Down() error {
	// macOS 使用 ifconfig 命令停止接口
	return nil
}

func configureDarwin(fd int, config *Config) error {
	// macOS 配置 IP 地址和启动接口
	// 需要使用 ifconfig 命令或系统调用
	// ifconfig utun0 inet <address> netmask <netmask> up

	ipAddr := config.Address
	if ipAddr == nil {
		ipAddr = net.ParseIP("10.0.0.1")
	}

	prefixLen := 24
	if config.Netmask != nil {
		ones, _ := config.Netmask.Size()
		prefixLen = ones
	}

	// 这里应该使用系统调用或执行命令
	// 为了简化，暂时返回 nil，实际实现需要使用系统调用
	_ = fd
	_ = ipAddr
	_ = prefixLen

	return nil
}
