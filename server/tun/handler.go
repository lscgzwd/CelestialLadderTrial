package tun

import (
	"fmt"
	"io"
	"net"
	"sync"

	"proxy/config"
	"proxy/server/common"
	"proxy/server/route"
	"proxy/utils/context"
	"proxy/utils/logger"
)

// Handler TUN数据包处理器
type Handler struct {
	device      Device
	socks5Addr  string
	connections map[string]*Connection
	dnsHandler  *DNSHandler
	mu          sync.RWMutex
	ctx         *context.Context
	maxConns    int // 最大并发连接数
	connCount   int // 当前连接数
	connCountMu sync.Mutex
}

// Connection TUN连接
type Connection struct {
	ID       string
	SrcIP    net.IP
	DstIP    net.IP
	SrcPort  uint16
	DstPort  uint16
	Protocol uint8
	conn     io.ReadWriter
	closed   bool
	mu       sync.Mutex
}

// NewHandler 创建TUN处理器
func NewHandler(device Device, socks5Addr string) *Handler {
	return &Handler{
		device:      device,
		socks5Addr:  socks5Addr,
		connections: make(map[string]*Connection),
		dnsHandler:  NewDNSHandler(),
		ctx:         context.NewContext(),
		maxConns:    1000, // 最大并发连接数，防止 goroutine 爆炸
	}
}

// Start 启动TUN数据包处理循环
func (h *Handler) Start() error {
	buf := make([]byte, 65535)

	for {
		// 从TUN读取数据包
		n, err := h.device.Read(buf, 0)
		if err != nil {
			if err == io.EOF {
				break
			}
			logger.Error(h.ctx, map[string]interface{}{
				"action":    config.ActionSocketOperate,
				"errorCode": logger.ErrCodeHandshake,
				"error":     err,
			}, "failed to read from TUN")
			continue
		}

		if n == 0 {
			continue
		}

		// 解析IP包
		ipPkt, err := ParseIPPacket(buf[:n])
		if err != nil {
			logger.Warn(h.ctx, map[string]interface{}{
				"action": config.ActionSocketOperate,
				"error":  err,
			}, "failed to parse IP packet")
			continue
		}

		// 处理数据包
		go h.handlePacket(ipPkt)
	}

	return nil
}

// handlePacket 处理IP数据包
func (h *Handler) handlePacket(ipPkt *IPPacket) {
	// 过滤掉不应该处理的包
	if !h.shouldHandle(ipPkt) {
		return
	}

	// 只处理TCP和UDP
	if ipPkt.Protocol != IPProtocolTCP && ipPkt.Protocol != IPProtocolUDP {
		return
	}

	// 处理DNS查询（UDP 53端口）
	if ipPkt.Protocol == IPProtocolUDP {
		udpPkt, err := ParseUDPPacket(ipPkt.Data)
		if err == nil {
			// DNS 查询单独处理
			if udpPkt.DstPort == 53 {
				// DNS查询，使用DNS处理器
				response, err := h.dnsHandler.HandleDNSQuery(ipPkt, udpPkt)
				if err == nil && response != nil {
					// 写回TUN接口
					_, _ = h.device.Write(response, 0)
				}
				return
			}
		}
	}

	// 生成连接ID
	connID := h.getConnectionID(ipPkt)

	h.mu.RLock()
	conn, exists := h.connections[connID]
	h.mu.RUnlock()

	if !exists {
		// 检查连接数限制
		h.connCountMu.Lock()
		if h.connCount >= h.maxConns {
			h.connCountMu.Unlock()
			logger.Warn(h.ctx, map[string]interface{}{
				"action": config.ActionRequestBegin,
				"count":   h.connCount,
				"max":     h.maxConns,
			}, "max connections reached, dropping packet")
			return
		}
		h.connCount++
		h.connCountMu.Unlock()

		// 检查是否是TCP SYN包（新连接）
		if ipPkt.Protocol == IPProtocolTCP {
			tcpPkt, err := ParseTCPPacket(ipPkt.Data)
			if err == nil {
				// 只处理SYN包（Flags & 0x02 == SYN）
				if (tcpPkt.Flags & 0x02) == 0 {
					h.connCountMu.Lock()
					h.connCount--
					h.connCountMu.Unlock()
					return // 不是SYN包，忽略
				}
			}
		}

		// 创建新连接
		var err error
		conn, err = h.createConnection(ipPkt)
		if err != nil {
			h.connCountMu.Lock()
			h.connCount--
			h.connCountMu.Unlock()
			logger.Error(h.ctx, map[string]interface{}{
				"action":    config.ActionRequestBegin,
				"errorCode": logger.ErrCodeHandshake,
				"error":     err,
				"dst":       ipPkt.DstIP.String(),
			}, "failed to create connection")
			return
		}

		h.mu.Lock()
		h.connections[connID] = conn
		h.mu.Unlock()

		// 启动双向转发
		go h.forwardSocks5ToTun(conn)
	}

	// 转发数据到SOCKS5
	if ipPkt.Protocol == IPProtocolTCP {
		tcpPkt, err := ParseTCPPacket(ipPkt.Data)
		if err == nil {
			// 跳过SYN包（已经在createConnection中处理）
			if (tcpPkt.Flags & 0x02) != 0 {
				return
			}

			// 转发数据
			if len(tcpPkt.Data) > 0 {
				conn.mu.Lock()
				if conn.conn != nil && !conn.closed {
					_, err = conn.conn.Write(tcpPkt.Data)
					if err != nil {
						logger.Error(h.ctx, map[string]interface{}{
							"action":    config.ActionSocketOperate,
							"errorCode": logger.ErrCodeTransfer,
							"error":     err,
						}, "failed to write to SOCKS5")
						conn.closed = true
					}
				}
				conn.mu.Unlock()
			}
		}
	} else if ipPkt.Protocol == IPProtocolUDP {
		udpPkt, err := ParseUDPPacket(ipPkt.Data)
		if err == nil && len(udpPkt.Data) > 0 {
			// UDP 转发：直接将负载写入远端连接
			conn.mu.Lock()
			if conn.conn != nil && !conn.closed {
				_, err = conn.conn.Write(udpPkt.Data)
				if err != nil {
					logger.Error(h.ctx, map[string]interface{}{
						"action":    config.ActionSocketOperate,
						"errorCode": logger.ErrCodeTransfer,
						"error":     err,
					}, "failed to write UDP payload to remote")
					conn.closed = true
				}
			}
			conn.mu.Unlock()
		}
	}
}

// createConnection 创建新连接
func (h *Handler) createConnection(ipPkt *IPPacket) (*Connection, error) {
	var srcPort, dstPort uint16
	var protocol uint8 = ipPkt.Protocol

	if ipPkt.Protocol == IPProtocolTCP {
		tcpPkt, err := ParseTCPPacket(ipPkt.Data)
		if err != nil {
			return nil, err
		}
		srcPort = tcpPkt.SrcPort
		dstPort = tcpPkt.DstPort
	} else if ipPkt.Protocol == IPProtocolUDP {
		udpPkt, err := ParseUDPPacket(ipPkt.Data)
		if err != nil {
			return nil, err
		}
		srcPort = udpPkt.SrcPort
		dstPort = udpPkt.DstPort
	} else {
		return nil, fmt.Errorf("unsupported protocol: %d", ipPkt.Protocol)
	}

	// 创建目标地址
	target := &common.TargetAddr{
		IP:    ipPkt.DstIP,
		Port:  int(dstPort),
		Proto: uint16(protocol),
	}

	// 路由决策
	remote := route.GetRemote(h.ctx, target)

	// 使用路由决策的Remote接口建立连接
	remoteConn, err := remote.Handshake(h.ctx, target)
	if err != nil {
		return nil, fmt.Errorf("failed to handshake: %w", err)
	}

	// 确保remoteConn是io.ReadWriter类型
	// Chacha20Stream实现了io.ReadWriter，可以直接使用
	var conn io.ReadWriter = remoteConn

	connection := &Connection{
		ID:       h.getConnectionID(ipPkt),
		SrcIP:    ipPkt.SrcIP,
		DstIP:    ipPkt.DstIP,
		SrcPort:  srcPort,
		DstPort:  dstPort,
		Protocol: protocol,
		conn:     conn,
	}

	return connection, nil
}


// forwardSocks5ToTun 从SOCKS5转发到TUN
func (h *Handler) forwardSocks5ToTun(conn *Connection) {
	buf := make([]byte, 65535)

	for {
		conn.mu.Lock()
		if conn.closed || conn.conn == nil {
			conn.mu.Unlock()
			break
		}
		readConn := conn.conn
		conn.mu.Unlock()

		n, err := readConn.Read(buf)
		if err != nil {
			conn.mu.Lock()
			conn.closed = true
			conn.mu.Unlock()
			break
		}

		if n == 0 {
			continue
		}

		var ipPkt []byte

		if conn.Protocol == IPProtocolUDP {
			// 对于 UDP，需要先构建 UDP 头，再封装到 IP 包中
			udpPkt := BuildUDPPacket(
				conn.DstPort, // 源端口（目标服务器端口）
				conn.SrcPort, // 目标端口（客户端端口）
				buf[:n],      // 负载
			)

			ipPkt = BuildIPPacket(
				conn.DstIP, // 源IP（目标服务器）
				conn.SrcIP, // 目标IP（客户端）
				IPProtocolUDP,
				udpPkt,
			)
		} else {
			// TCP 目前仅转发负载（简化实现）
			ipPkt = BuildIPPacket(
				conn.DstIP, // 源IP（目标服务器）
				conn.SrcIP, // 目标IP（客户端）
				conn.Protocol,
				buf[:n],
			)
		}

		// 写回TUN
		_, err = h.device.Write(ipPkt, 0)
		if err != nil {
			logger.Error(h.ctx, map[string]interface{}{
				"action":    config.ActionSocketOperate,
				"errorCode": logger.ErrCodeTransfer,
				"error":     err,
			}, "failed to write to TUN")
			break
		}
	}

	// 清理连接
	h.mu.Lock()
	delete(h.connections, conn.ID)
	h.mu.Unlock()

	// 减少连接计数
	h.connCountMu.Lock()
	h.connCount--
	h.connCountMu.Unlock()

	conn.mu.Lock()
	if closeConn, ok := conn.conn.(io.Closer); ok && closeConn != nil {
		closeConn.Close()
	}
	conn.mu.Unlock()
}

// getConnectionID 生成连接ID
func (h *Handler) getConnectionID(ipPkt *IPPacket) string {
	if ipPkt.Protocol == IPProtocolTCP {
		tcpPkt, err := ParseTCPPacket(ipPkt.Data)
		if err == nil {
			return fmt.Sprintf("%s:%d-%s:%d-tcp",
				ipPkt.SrcIP.String(), tcpPkt.SrcPort,
				ipPkt.DstIP.String(), tcpPkt.DstPort)
		}
	} else if ipPkt.Protocol == IPProtocolUDP {
		udpPkt, err := ParseUDPPacket(ipPkt.Data)
		if err == nil {
			return fmt.Sprintf("%s:%d-%s:%d-udp",
				ipPkt.SrcIP.String(), udpPkt.SrcPort,
				ipPkt.DstIP.String(), udpPkt.DstPort)
		}
	}
	return fmt.Sprintf("%s-%s-%d", ipPkt.SrcIP.String(), ipPkt.DstIP.String(), ipPkt.Protocol)
}

// shouldHandle 判断是否应该处理这个数据包
func (h *Handler) shouldHandle(ipPkt *IPPacket) bool {
	dstIP := ipPkt.DstIP

	// 过滤本地回环地址（127.0.0.0/8）
	if dstIP.IsLoopback() {
		return false
	}

	// 过滤源地址是回环地址的包
	if ipPkt.SrcIP != nil && ipPkt.SrcIP.IsLoopback() {
		return false
	}

	// 过滤广播地址（255.255.255.255）
	if dstIP.Equal(net.IPv4bcast) {
		return false
	}

	// 过滤组播地址（224.0.0.0/4）
	if len(dstIP) >= 1 && dstIP[0] >= 224 && dstIP[0] <= 239 {
		return false
	}

	// 过滤链路本地地址（169.254.0.0/16）
	if len(dstIP) >= 2 && dstIP[0] == 169 && dstIP[1] == 254 {
		return false
	}

	// 过滤私有网络地址 - 这些应该走本地路由，不走 TUN
	// 10.0.0.0/8 - 但排除 TUN 自己的地址（10.0.0.x）
	if len(dstIP) >= 2 && dstIP[0] == 10 {
		// 如果是 TUN 的网段（10.0.0.0/24），则应该处理
		// 其他 10.x.x.x 地址不处理（走本地路由）
		if dstIP[1] != 0 || dstIP[2] != 0 {
			return false
		}
	}

	// 172.16.0.0/12 - 私有网络，不走 TUN
	if len(dstIP) >= 2 && dstIP[0] == 172 && dstIP[1] >= 16 && dstIP[1] <= 31 {
		return false
	}

	// 192.168.0.0/16 - 私有网络，不走 TUN
	if len(dstIP) >= 2 && dstIP[0] == 192 && dstIP[1] == 168 {
		return false
	}

	// 过滤子网广播地址
	if len(dstIP) >= 4 && dstIP[3] == 255 {
		return false
	}

	// 检查是否是远程服务器地址（应该走直连路由，不应该进入TUN）
	routeMgr := route.GetGlobalRouteManager()
	if routeMgr != nil && routeMgr.IsRemoteServerIP(dstIP) {
		return false
	}

	return true
}

