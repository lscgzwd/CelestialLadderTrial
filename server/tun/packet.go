package tun

import (
	"encoding/binary"
	"fmt"
	"net"
)

// IPProtocol IP协议类型
const (
	IPProtocolICMP = 1
	IPProtocolTCP  = 6
	IPProtocolUDP  = 17
)

// IPPacket IP数据包结构
type IPPacket struct {
	Version    uint8  // IP版本
	HeaderLen uint8  // 头部长度（4字节单位）
	TOS       uint8  // 服务类型
	TotalLen  uint16 // 总长度
	ID        uint16 // 标识
	Flags     uint8  // 标志
	FragOff   uint16 // 分片偏移
	TTL       uint8  // 生存时间
	Protocol  uint8  // 协议类型
	Checksum  uint16 // 校验和
	SrcIP     net.IP // 源IP
	DstIP     net.IP // 目标IP
	Data      []byte // 数据部分
}

// ParseIPPacket 解析IP数据包
func ParseIPPacket(data []byte) (*IPPacket, error) {
	if len(data) < 20 {
		return nil, fmt.Errorf("IP packet too short")
	}

	pkt := &IPPacket{}

	// 解析IP头
	pkt.Version = (data[0] >> 4) & 0x0F
	if pkt.Version != 4 {
		return nil, fmt.Errorf("unsupported IP version: %d", pkt.Version)
	}

	pkt.HeaderLen = (data[0] & 0x0F) * 4
	if len(data) < int(pkt.HeaderLen) {
		return nil, fmt.Errorf("IP packet shorter than header length")
	}

	pkt.TOS = data[1]
	pkt.TotalLen = binary.BigEndian.Uint16(data[2:4])
	pkt.ID = binary.BigEndian.Uint16(data[4:6])
	pkt.Flags = (data[6] >> 5) & 0x07
	pkt.FragOff = binary.BigEndian.Uint16(data[6:8]) & 0x1FFF
	pkt.TTL = data[8]
	pkt.Protocol = data[9]
	pkt.Checksum = binary.BigEndian.Uint16(data[10:12])

	// 解析IP地址
	pkt.SrcIP = make(net.IP, 4)
	copy(pkt.SrcIP, data[12:16])
	pkt.DstIP = make(net.IP, 4)
	copy(pkt.DstIP, data[16:20])

	// 数据部分
	if len(data) > int(pkt.HeaderLen) {
		pkt.Data = data[pkt.HeaderLen:]
	}

	return pkt, nil
}

// TCPPacket TCP数据包结构
type TCPPacket struct {
	SrcPort uint16
	DstPort uint16
	SeqNum  uint32
	AckNum  uint32
	Flags   uint8
	Window  uint16
	Data    []byte
}

// ParseTCPPacket 解析TCP数据包
func ParseTCPPacket(data []byte) (*TCPPacket, error) {
	if len(data) < 20 {
		return nil, fmt.Errorf("TCP packet too short")
	}

	pkt := &TCPPacket{}
	pkt.SrcPort = binary.BigEndian.Uint16(data[0:2])
	pkt.DstPort = binary.BigEndian.Uint16(data[2:4])
	pkt.SeqNum = binary.BigEndian.Uint32(data[4:8])
	pkt.AckNum = binary.BigEndian.Uint32(data[8:12])

	headerLen := (data[12] >> 4) * 4
	if len(data) < int(headerLen) {
		return nil, fmt.Errorf("TCP packet shorter than header length")
	}

	pkt.Flags = data[13]
	pkt.Window = binary.BigEndian.Uint16(data[14:16])

	if len(data) > int(headerLen) {
		pkt.Data = data[headerLen:]
	}

	return pkt, nil
}

// UDPPacket UDP数据包结构
type UDPPacket struct {
	SrcPort uint16
	DstPort uint16
	Length  uint16
	Data    []byte
}

// ParseUDPPacket 解析UDP数据包
func ParseUDPPacket(data []byte) (*UDPPacket, error) {
	if len(data) < 8 {
		return nil, fmt.Errorf("UDP packet too short")
	}

	pkt := &UDPPacket{}
	pkt.SrcPort = binary.BigEndian.Uint16(data[0:2])
	pkt.DstPort = binary.BigEndian.Uint16(data[2:4])
	pkt.Length = binary.BigEndian.Uint16(data[4:6])

	if len(data) > 8 {
		pkt.Data = data[8:]
	}

	return pkt, nil
}

// BuildIPPacket 构建IP数据包
func BuildIPPacket(srcIP, dstIP net.IP, protocol uint8, data []byte) []byte {
	headerLen := 20
	totalLen := headerLen + len(data)

	packet := make([]byte, totalLen)

	// IP头
	packet[0] = 0x45 // Version 4, Header Length 5 (20 bytes)
	packet[1] = 0x00 // TOS
	binary.BigEndian.PutUint16(packet[2:4], uint16(totalLen))
	binary.BigEndian.PutUint16(packet[4:6], 0) // ID
	packet[6] = 0x40                             // Flags, Fragment Offset
	packet[7] = 0x00
	packet[8] = 64 // TTL
	packet[9] = protocol
	binary.BigEndian.PutUint16(packet[10:12], 0) // Checksum (计算后填充)

	// IP地址
	copy(packet[12:16], srcIP.To4())
	copy(packet[16:20], dstIP.To4())

	// 数据
	copy(packet[20:], data)

	// 计算校验和
	checksum := calculateChecksum(packet[:headerLen])
	binary.BigEndian.PutUint16(packet[10:12], checksum)

	return packet
}

// calculateChecksum 计算IP校验和
func calculateChecksum(data []byte) uint16 {
	var sum uint32
	for i := 0; i < len(data); i += 2 {
		if i+1 < len(data) {
			sum += uint32(binary.BigEndian.Uint16(data[i : i+2]))
		} else {
			sum += uint32(data[i]) << 8
		}
	}
	for sum>>16 != 0 {
		sum = (sum & 0xFFFF) + (sum >> 16)
	}
	return ^uint16(sum)
}


