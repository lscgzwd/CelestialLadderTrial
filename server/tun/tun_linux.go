//go:build linux

package tun

import (
	"bytes"
	"fmt"
	"net"
	"os"
	"unsafe"

	"golang.org/x/sys/unix"
)

func newDevice(config *Config) (Device, error) {
	// 打开 TUN 设备
	fd, err := unix.Open("/dev/net/tun", unix.O_RDWR, 0)
	if err != nil {
		return nil, fmt.Errorf("failed to open /dev/net/tun: %w", err)
	}

	// 创建 TUN 接口
	ifr, err := createInterface(fd, config.Name)
	if err != nil {
		unix.Close(fd)
		return nil, fmt.Errorf("failed to create interface: %w", err)
	}

	// 配置 IP 地址
	if err := configureLinux(ifr, config); err != nil {
		unix.Close(fd)
		return nil, fmt.Errorf("failed to configure interface: %w", err)
	}

	file := os.NewFile(uintptr(fd), "/dev/net/tun")
	return &linuxDevice{
		file: file,
		// Ifreq.Name 是定长字节数组，这里需要去掉尾部的 0
		name:   string(bytes.Trim(ifr.Name[:], "\x00")),
		config: config,
	}, nil
}

type linuxDevice struct {
	file   *os.File
	name   string
	config *Config
}

func (d *linuxDevice) Read(b []byte, offset int) (int, error) {
	n, err := d.file.Read(b[offset:])
	return n, err
}

func (d *linuxDevice) Write(b []byte, offset int) (int, error) {
	return d.file.Write(b[offset:])
}

func (d *linuxDevice) Close() error {
	return d.file.Close()
}

func (d *linuxDevice) Name() string {
	return d.name
}

func (d *linuxDevice) MTU() (int, error) {
	return d.config.MTU, nil
}

func (d *linuxDevice) Up() error {
	// 使用 ip 命令启动接口
	// 这里简化处理，实际应该使用 netlink 或执行 ip link set <name> up
	return nil
}

func (d *linuxDevice) Down() error {
	// 使用 ip 命令停止接口
	return nil
}

// Ifreq 是 Linux 的接口请求结构
type Ifreq struct {
	Name  [unix.IFNAMSIZ]byte
	Flags uint16
	_     [22]byte
}

func createInterface(fd int, name string) (*Ifreq, error) {
	var ifr Ifreq
	copy(ifr.Name[:], name)
	ifr.Flags = unix.IFF_TUN | unix.IFF_NO_PI

	_, _, errno := unix.Syscall(
		unix.SYS_IOCTL,
		uintptr(fd),
		uintptr(unix.TUNSETIFF),
		uintptr(unsafe.Pointer(&ifr)),
	)
	if errno != 0 {
		return nil, fmt.Errorf("ioctl TUNSETIFF failed: %w", errno)
	}
	return &ifr, nil
}

func configureLinux(ifr *Ifreq, config *Config) error {
	// 配置 IP 地址和启动接口
	// 这里需要使用 netlink 或执行系统命令
	// 简化实现，实际应该使用 netlink 库或执行 ip 命令
	// ip addr add <address>/<prefix> dev <name>
	// ip link set <name> up

	ipAddr := config.Address
	if ipAddr == nil {
		ipAddr = net.ParseIP("10.0.0.1")
	}

	prefixLen := 24
	if config.Netmask != nil {
		ones, _ := config.Netmask.Size()
		prefixLen = ones
	}

	// 这里应该使用 netlink 或执行命令
	// 为了简化，暂时返回 nil，实际实现需要使用 netlink
	_ = ifr
	_ = ipAddr
	_ = prefixLen

	return nil
}
