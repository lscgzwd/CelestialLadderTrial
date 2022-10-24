package proxy

import (
	"fmt"
	"github.com/pkg/errors"
	"io"
	"net"
	"proxy/config"
	"proxy/utils/context"
	"proxy/utils/logger"
	"strconv"
	"time"
)

// https://www.ietf.org/rfc/rfc1928.txt

// Version5 is socks5 version number.
const Version5 = 0x05

// SOCKS auth type
const (
	AuthNone     = 0x00
	AuthPassword = 0x02
)

// SOCKS request commands as defined in RFC 1928 section 4
const (
	CmdConnect      = 0x01
	CmdBind         = 0x02
	CmdUDPAssociate = 0x03
)

// SOCKS address types as defined in RFC 1928 section 4
const (
	ATypIP4    = 0x1
	ATypDomain = 0x3
	ATypIP6    = 0x4
)

type SocketServer struct {
	Type     int8
	Port     int
	UserName string
	Password string
}

func (s *SocketServer) Handshake(ctx *context.Context, conn net.Conn) (io.ReadWriter, string, error) {
	// 在函数退出前，执行defer
	// 捕捉异常后，程序不会异常退出
	defer func() {
		err := recover() // 内置函数，可以捕捉到函数异常
		if err != nil {
			// 这里是打印错误，还可以进行报警处理，例如微信，邮箱通知
			logger.Error(ctx, map[string]interface{}{
				"action":    config.ActionRequestBegin,
				"errorCode": logger.ErrCodeHandshake,
				"error":     err,
			})
		}
	}()
	// Set handshake timeout 4 seconds
	if err := conn.SetReadDeadline(time.Now().Add(time.Second * 4)); err != nil {
		return nil, "", err
	}
	defer conn.SetReadDeadline(time.Time{})

	// https://www.ietf.org/rfc/rfc1928.txt
	buf := make([]byte, 512)

	// Read hello message
	n, err := conn.Read(buf)
	if err != nil || n == 0 {
		return nil, "", fmt.Errorf("failed to read hello: %w", err)
	}
	version := buf[0]
	if version != Version5 {
		return nil, "", fmt.Errorf("unsupported socks version %v", version)
	}

	// Write hello response
	// TODO: Support Auth
	_, err = conn.Write([]byte{Version5, AuthNone})
	if err != nil {
		return nil, "", fmt.Errorf("failed to write hello response: %w", err)
	}

	// Read command message
	n, err = conn.Read(buf)
	if err != nil || n < 7 { // Shortest length is 7
		return nil, "", fmt.Errorf("failed to read command: %w", err)
	}
	cmd := buf[1]
	if cmd != CmdConnect {
		return nil, "", fmt.Errorf("unsuppoted command %v", cmd)
	}
	var addr string
	l := 2
	off := 4
	switch buf[3] {
	case ATypIP4:
		l += net.IPv4len
		addr = string(buf[off:])
	case ATypIP6:
		l += net.IPv6len
		addr = string(buf[off:])
	case ATypDomain:
		l += int(buf[4])
		off = 5
		addr = string(buf[off : off+l-2])
	default:
		return nil, "", fmt.Errorf("unknown address type %v", buf[3])
	}

	if len(buf[off:]) < l {
		return nil, "", errors.New("short command request")
	}

	port := int(buf[off+l-2])<<8 | int(buf[off+l-1])

	// Write command response
	_, err = conn.Write([]byte{Version5, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00})
	if err != nil {
		return nil, "", fmt.Errorf("failed to write command response: %w", err)
	}

	return conn, net.JoinHostPort(addr, strconv.FormatInt(int64(port), 10)), err
}
