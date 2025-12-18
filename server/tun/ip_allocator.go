package tun

import (
	"fmt"
	"net"
	"sync"
)

// IPAllocator IP地址分配器
type IPAllocator struct {
	mu       sync.Mutex
	networks []*net.IPNet
	used     map[string]bool
}

// NewIPAllocator 创建IP地址分配器
func NewIPAllocator() *IPAllocator {
	return &IPAllocator{
		networks: []*net.IPNet{
			// 私有网络段
			{IP: net.ParseIP("10.0.0.0"), Mask: net.CIDRMask(8, 32)},   // 10.0.0.0/8
			{IP: net.ParseIP("172.16.0.0"), Mask: net.CIDRMask(12, 32)}, // 172.16.0.0/12
			{IP: net.ParseIP("192.168.0.0"), Mask: net.CIDRMask(16, 32)}, // 192.168.0.0/16
		},
		used: make(map[string]bool),
	}
}

// FindAvailableNetwork 查找可用的网络段
func (a *IPAllocator) FindAvailableNetwork() (*net.IPNet, net.IP, error) {
	a.mu.Lock()
	defer a.mu.Unlock()

	// 获取所有网络接口
	interfaces, err := net.Interfaces()
	if err != nil {
		return nil, nil, fmt.Errorf("failed to get interfaces: %w", err)
	}

	// 收集已使用的IP地址
	usedIPs := make(map[string]bool)
	for _, iface := range interfaces {
		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}
		for _, addr := range addrs {
			if ipNet, ok := addr.(*net.IPNet); ok {
				if ip := ipNet.IP.To4(); ip != nil {
					usedIPs[ip.String()] = true
					// 检查整个网络段是否被使用
					ones, _ := ipNet.Mask.Size()
					if ones <= 24 { // 只检查/24及更大的网络
						networkIP := ipNet.IP.Mask(ipNet.Mask)
						usedIPs[networkIP.String()+"/"+fmt.Sprintf("%d", ones)] = true
					}
				}
			}
		}
	}

	// 尝试每个私有网络段
	for _, network := range a.networks {
		// 尝试使用 /24 子网
		ones, _ := network.Mask.Size()
		if ones > 24 {
			continue
		}

		// 生成 /24 子网
		for i := 0; i < 256; i++ {
			subnetIP := make(net.IP, 4)
			copy(subnetIP, network.IP.To4())

			// 根据网络类型设置子网
			if ones == 8 {
				// 10.0.0.0/8 -> 10.x.0.0/24
				subnetIP[1] = byte(i)
				subnetIP[2] = 0
				subnetIP[3] = 0
			} else if ones == 12 {
				// 172.16.0.0/12 -> 172.16.x.0/24
				subnetIP[2] = byte(i)
				subnetIP[3] = 0
			} else if ones == 16 {
				// 192.168.0.0/16 -> 192.168.x.0/24
				subnetIP[2] = byte(i)
				subnetIP[3] = 0
			}

			subnet := &net.IPNet{
				IP:   subnetIP,
				Mask: net.CIDRMask(24, 32),
			}

			// 检查是否已被使用
			subnetKey := subnetIP.String() + "/24"
			if usedIPs[subnetKey] {
				continue
			}

			// 检查子网中的第一个IP（网关IP）是否被使用
			gatewayIP := make(net.IP, 4)
			copy(gatewayIP, subnetIP)
			gatewayIP[3] = 1 // 使用 .1 作为网关IP

			if usedIPs[gatewayIP.String()] {
				continue
			}

			// 找到可用网络
			a.used[subnetKey] = true
			return subnet, gatewayIP, nil
		}
	}

	return nil, nil, fmt.Errorf("no available private network found")
}

// ReleaseNetwork 释放网络
func (a *IPAllocator) ReleaseNetwork(network *net.IPNet) {
	a.mu.Lock()
	defer a.mu.Unlock()

	key := network.IP.String() + "/24"
	delete(a.used, key)
}

