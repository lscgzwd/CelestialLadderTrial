package tun

import (
	"io"
	"net"
)

// Device TUN 设备接口
type Device interface {
	// Read 从 TUN 设备读取数据包
	Read(b []byte, offset int) (int, error)
	// Write 向 TUN 设备写入数据包
	Write(b []byte, offset int) (int, error)
	// Close 关闭 TUN 设备
	Close() error
	// Name 返回 TUN 设备名称
	Name() string
	// MTU 返回 TUN 设备 MTU
	MTU() (int, error)
	// Up 启动 TUN 接口
	Up() error
	// Down 停止 TUN 接口
	Down() error
}

// Config TUN 设备配置
type Config struct {
	Name    string   // TUN 接口名称
	Address net.IP    // TUN 接口 IP 地址
	Netmask net.IPMask // 子网掩码
	MTU     int      // MTU 大小
	DNS     []net.IP // DNS 服务器地址
}

// New 创建 TUN 设备（跨平台）
func New(config *Config) (Device, error) {
	return newDevice(config)
}

// DefaultConfig 返回默认配置
func DefaultConfig() *Config {
	return &Config{
		Name:    "clt0",
		Address: net.ParseIP("10.0.0.1"),
		Netmask: net.CIDRMask(24, 32), // 255.255.255.0
		MTU:     1500,
		DNS: []net.IP{
			net.ParseIP("8.8.8.8"),
			net.ParseIP("8.8.4.4"),
		},
	}
}

// PacketReader 数据包读取器接口
type PacketReader interface {
	io.Reader
}

// PacketWriter 数据包写入器接口
type PacketWriter interface {
	io.Writer
}


