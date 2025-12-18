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
	// 只处理TCP和UDP
	if ipPkt.Protocol != IPProtocolTCP && ipPkt.Protocol != IPProtocolUDP {
		return
	}

	// 处理DNS查询（UDP 53端口）
	if ipPkt.Protocol == IPProtocolUDP {
		udpPkt, err := ParseUDPPacket(ipPkt.Data)
		if err == nil && udpPkt.DstPort == 53 {
			// DNS查询，使用DNS处理器
			response, err := h.dnsHandler.HandleDNSQuery(ipPkt, udpPkt)
			if err == nil && response != nil {
				// 写回TUN接口
				_, _ = h.device.Write(response, 0)
			}
			return
		}
	}

	// 生成连接ID
	connID := h.getConnectionID(ipPkt)

	h.mu.RLock()
	conn, exists := h.connections[connID]
	h.mu.RUnlock()

	if !exists {
		// 检查是否是TCP SYN包（新连接）
		if ipPkt.Protocol == IPProtocolTCP {
			tcpPkt, err := ParseTCPPacket(ipPkt.Data)
			if err == nil {
				// 只处理SYN包（Flags & 0x02 == SYN）
				if (tcpPkt.Flags & 0x02) == 0 {
					return // 不是SYN包，忽略
				}
			}
		}

		// 创建新连接
		var err error
		conn, err = h.createConnection(ipPkt)
		if err != nil {
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
			// UDP处理（简化实现）
			// TODO: 实现UDP转发
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

		// 构建IP数据包
		ipPkt := BuildIPPacket(
			conn.DstIP, // 源IP（目标服务器）
			conn.SrcIP, // 目标IP（客户端）
			conn.Protocol,
			buf[:n],
		)

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

