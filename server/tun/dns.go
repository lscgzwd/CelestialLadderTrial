package tun

import (
	context2 "context"
	"encoding/binary"
	"fmt"
	"net"
	"sync"
	"time"

	"proxy/config"
	"proxy/server/doh"
	"proxy/utils/context"
	"proxy/utils/logger"
)

// DNSHandler DNS处理器
type DNSHandler struct {
	dohClient *doh.AliyunProvider
	ctx       *context.Context
	cache     *DNSCache
}

// DNSCache DNS缓存
type DNSCache struct {
	entries map[string]*CacheEntry
	mu      sync.RWMutex
}

// CacheEntry 缓存条目
type CacheEntry struct {
	IP        net.IP
	ExpiresAt time.Time
}

// NewDNSHandler 创建DNS处理器
func NewDNSHandler() *DNSHandler {
	return &DNSHandler{
		dohClient: doh.New(),
		ctx:       context.NewContext(),
		cache: &DNSCache{
			entries: make(map[string]*CacheEntry),
		},
	}
}

// HandleDNSQuery 处理DNS查询
func (h *DNSHandler) HandleDNSQuery(ipPkt *IPPacket, udpPkt *UDPPacket) ([]byte, error) {
	// 解析DNS查询包
	dnsQuery, err := parseDNSQuery(udpPkt.Data)
	if err != nil {
		return nil, fmt.Errorf("failed to parse DNS query: %w", err)
	}

	// 检查缓存
	h.cache.mu.RLock()
	if entry, exists := h.cache.entries[dnsQuery.Domain]; exists {
		if time.Now().Before(entry.ExpiresAt) {
			h.cache.mu.RUnlock()
			// 使用缓存结果
			return h.buildDNSResponse(ipPkt, udpPkt, dnsQuery, entry.IP), nil
		}
		// 缓存过期，删除
		delete(h.cache.entries, dnsQuery.Domain)
	}
	h.cache.mu.RUnlock()

	// 使用DoH解析
	ctxCancel, cancel := context2.WithTimeout(context2.Background(), 10*time.Second)
	defer cancel()

	// ECS subnet
	var subnet = config.Config.ECSSubnet
	if subnet == "" {
		subnet = "110.242.68.0/24"
	}

	rsp, err := h.dohClient.ECSQuery(ctxCancel, doh.Domain(dnsQuery.Domain), doh.Type("A"), doh.ECS(subnet))
	if err != nil {
		logger.Error(h.ctx, map[string]interface{}{
			"action":    config.ActionSocketOperate,
			"errorCode": logger.ErrCodeHandshake,
			"error":     err,
			"domain":    dnsQuery.Domain,
		}, "DoH query failed")
		// 返回NXDOMAIN响应
		return h.buildDNSErrorResponse(ipPkt, udpPkt, dnsQuery, 3), nil // NXDOMAIN
	}

	// 提取IP地址
	var ip net.IP
	for _, answer := range rsp.Answer {
		if answer.Type == 1 { // A record
			ip = net.ParseIP(answer.Data)
			if ip != nil && ip.To4() != nil {
				break
			}
		}
	}

	if ip == nil {
		// 没有找到A记录，返回NXDOMAIN
		return h.buildDNSErrorResponse(ipPkt, udpPkt, dnsQuery, 3), nil
	}

	// 缓存结果（TTL 60秒）
	h.cache.mu.Lock()
	h.cache.entries[dnsQuery.Domain] = &CacheEntry{
		IP:        ip,
		ExpiresAt: time.Now().Add(60 * time.Second),
	}
	h.cache.mu.Unlock()

	// 构建DNS响应
	return h.buildDNSResponse(ipPkt, udpPkt, dnsQuery, ip), nil
}

// DNSQuery DNS查询结构
type DNSQuery struct {
	ID     uint16
	Domain string
	Type   uint16
}

// parseDNSQuery 解析DNS查询包
func parseDNSQuery(data []byte) (*DNSQuery, error) {
	if len(data) < 12 {
		return nil, fmt.Errorf("DNS query too short")
	}

	query := &DNSQuery{
		ID: binary.BigEndian.Uint16(data[0:2]),
	}

	// 跳过头部（12字节）
	offset := 12

	// 解析域名
	domain, newOffset, err := parseDNSName(data, offset)
	if err != nil {
		return nil, err
	}
	query.Domain = domain
	offset = newOffset

	// 解析查询类型
	if len(data) < offset+4 {
		return nil, fmt.Errorf("DNS query incomplete")
	}
	query.Type = binary.BigEndian.Uint16(data[offset : offset+2])

	return query, nil
}

// parseDNSName 解析DNS名称
func parseDNSName(data []byte, offset int) (string, int, error) {
	var name string
	originalOffset := offset
	jumped := false
	maxJumps := 5
	jumpsPerformed := 0

	for {
		if jumpsPerformed > maxJumps {
			return "", 0, fmt.Errorf("too many DNS jumps")
		}

		if offset >= len(data) {
			return "", 0, fmt.Errorf("DNS name parsing out of bounds")
		}

		length := int(data[offset])
		offset++

		if length == 0 {
			break
		}

		// 检查是否是压缩指针
		if (length & 0xC0) == 0xC0 {
			if !jumped {
				originalOffset = offset + 1
			}
			jumped = true
			jumpsPerformed++

			// 读取指针
			if offset >= len(data) {
				return "", 0, fmt.Errorf("DNS pointer out of bounds")
			}
			pointer := binary.BigEndian.Uint16(data[offset-1:offset+1]) & 0x3FFF
			offset = int(pointer)
			continue
		}

		// 读取标签
		if offset+length > len(data) {
			return "", 0, fmt.Errorf("DNS label out of bounds")
		}

		if len(name) > 0 {
			name += "."
		}
		name += string(data[offset : offset+length])
		offset += length
	}

	if jumped {
		return name, originalOffset, nil
	}
	return name, offset, nil
}

// buildDNSResponse 构建DNS响应包
func (h *DNSHandler) buildDNSResponse(ipPkt *IPPacket, udpPkt *UDPPacket, query *DNSQuery, ip net.IP) []byte {
	// DNS响应包结构
	response := make([]byte, 0, 512)

	// DNS头部（12字节）
	header := make([]byte, 12)
	binary.BigEndian.PutUint16(header[0:2], query.ID) // ID
	header[2] = 0x81                                  // Flags: QR=1, Opcode=0, AA=0, TC=0, RD=1
	header[3] = 0x80                                  // Flags: RA=1, Z=0, RCODE=0
	binary.BigEndian.PutUint16(header[4:6], 1)       // QDCOUNT = 1
	binary.BigEndian.PutUint16(header[6:8], 1)       // ANCOUNT = 1
	binary.BigEndian.PutUint16(header[8:10], 0)      // NSCOUNT = 0
	binary.BigEndian.PutUint16(header[10:12], 0)    // ARCOUNT = 0
	response = append(response, header...)

	// 查询部分（从原始查询复制）
	// 这里简化处理，实际应该重新构建查询部分
	queryPart := buildDNSQueryPart(query.Domain, query.Type)
	response = append(response, queryPart...)

	// 答案部分
	answer := make([]byte, 0, 64)
	// 名称（使用压缩指针指向查询部分）
	answer = append(answer, 0xC0, 0x0C) // 指向偏移12（查询部分开始）
	// 类型 A (1)
	binary.BigEndian.PutUint16(answer[len(answer):len(answer)+2], 1)
	answer = answer[:len(answer)+2]
	// 类 IN (1)
	binary.BigEndian.PutUint16(answer[len(answer):len(answer)+2], 1)
	answer = answer[:len(answer)+2]
	// TTL (60秒)
	binary.BigEndian.PutUint32(answer[len(answer):len(answer)+4], 60)
	answer = answer[:len(answer)+4]
	// 数据长度 (4字节IPv4)
	binary.BigEndian.PutUint16(answer[len(answer):len(answer)+2], 4)
	answer = answer[:len(answer)+2]
	// IP地址
	answer = append(answer, ip.To4()...)
	response = append(response, answer...)

	// 构建UDP数据包
	udpResponse := make([]byte, 8+len(response))
	binary.BigEndian.PutUint16(udpResponse[0:2], udpPkt.DstPort) // 源端口（响应中的目标端口）
	binary.BigEndian.PutUint16(udpResponse[2:4], udpPkt.SrcPort) // 目标端口（响应中的源端口）
	binary.BigEndian.PutUint16(udpResponse[4:6], uint16(len(response)+8)) // 长度
	binary.BigEndian.PutUint16(udpResponse[6:8], 0) // 校验和（UDP可选）
	copy(udpResponse[8:], response)

	// 构建IP数据包
	ipResponse := BuildIPPacket(
		ipPkt.DstIP, // 源IP（响应中的目标IP）
		ipPkt.SrcIP, // 目标IP（响应中的源IP）
		IPProtocolUDP,
		udpResponse,
	)

	return ipResponse
}

// buildDNSErrorResponse 构建DNS错误响应
func (h *DNSHandler) buildDNSErrorResponse(ipPkt *IPPacket, udpPkt *UDPPacket, query *DNSQuery, rcode uint8) []byte {
	header := make([]byte, 12)
	binary.BigEndian.PutUint16(header[0:2], query.ID)
	header[2] = 0x81 // QR=1
	header[3] = rcode & 0x0F // RCODE
	binary.BigEndian.PutUint16(header[4:6], 1) // QDCOUNT
	binary.BigEndian.PutUint16(header[6:8], 0) // ANCOUNT
	binary.BigEndian.PutUint16(header[8:10], 0) // NSCOUNT
	binary.BigEndian.PutUint16(header[10:12], 0) // ARCOUNT

	queryPart := buildDNSQueryPart(query.Domain, query.Type)

	response := append(header, queryPart...)

	udpResponse := make([]byte, 8+len(response))
	binary.BigEndian.PutUint16(udpResponse[0:2], udpPkt.DstPort)
	binary.BigEndian.PutUint16(udpResponse[2:4], udpPkt.SrcPort)
	binary.BigEndian.PutUint16(udpResponse[4:6], uint16(len(response)+8))
	binary.BigEndian.PutUint16(udpResponse[6:8], 0)
	copy(udpResponse[8:], response)

	ipResponse := BuildIPPacket(
		ipPkt.DstIP,
		ipPkt.SrcIP,
		IPProtocolUDP,
		udpResponse,
	)

	return ipResponse
}

// buildDNSQueryPart 构建DNS查询部分
func buildDNSQueryPart(domain string, qtype uint16) []byte {
	query := make([]byte, 0, 64)

	// 域名
	parts := splitDomain(domain)
	for _, part := range parts {
		query = append(query, byte(len(part)))
		query = append(query, []byte(part)...)
	}
	query = append(query, 0) // 结束标记

	// 类型
	typeBytes := make([]byte, 2)
	binary.BigEndian.PutUint16(typeBytes, qtype)
	query = append(query, typeBytes...)

	// 类 IN (1)
	query = append(query, 0, 1)

	return query
}

// splitDomain 分割域名
func splitDomain(domain string) []string {
	parts := []string{}
	current := ""
	for _, r := range domain {
		if r == '.' {
			if current != "" {
				parts = append(parts, current)
				current = ""
			}
		} else {
			current += string(r)
		}
	}
	if current != "" {
		parts = append(parts, current)
	}
	return parts
}

