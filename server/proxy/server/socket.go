package server

import (
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"os"
	"strings"
	"time"

	"proxy/config"
	"proxy/server/common"
	"proxy/server/route"
	"proxy/utils/context"
	"proxy/utils/logger"

	"github.com/pkg/errors"
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

func (s *SocketServer) Start(l net.Listener) {
	for {
		conn, err := l.Accept()
		if err != nil {
			// Accept 错误时 conn 可能为 nil，不要进入 goroutine
			gCtx := context.NewContext()
			logger.Error(gCtx, map[string]interface{}{
				"action":    config.ActionRequestBegin,
				"errorCode": logger.ErrCodeHandshake,
				"error":     err,
			}, "accept connection failed")
			continue
		}
		go func(conn net.Conn) {
			defer conn.Close()
			gCtx := context.NewContext()
			wConn, target, err := s.Handshake(gCtx, conn)
			if nil != err {
				logger.Error(gCtx, map[string]interface{}{
					"action":    config.ActionRequestBegin,
					"errorCode": logger.ErrCodeHandshake,
					"error":     err,
				})
				return
			}
			remote := route.GetRemote(gCtx, target)
			rConn, err := remote.Handshake(gCtx, target)
			if nil != err {
				logger.Error(gCtx, map[string]interface{}{
					"action":    config.ActionRequestBegin,
					"errorCode": logger.ErrCodeHandshake,
					"error":     err,
					"remote":    remote.Name(),
					"target":    target.String(),
				})
				_, _ = wConn.Write(common.DefaultHtml)
				return
			}
			defer func() {
				// 安全关闭 wConn
				if closer, ok := wConn.(io.Closer); ok {
					_ = closer.Close()
				}
				// 安全关闭 rConn
				if closer, ok := rConn.(io.Closer); ok {
					_ = closer.Close()
				}
			}()
			if target.Proto == 3 {
				done := make(chan error, 1)
				// relay from tcp to udp
				go func() {
					//defer rConn.SetReadDeadline(time.Now()) // wake up anthoer goroutine
					buf := make([]byte, 65535)
					for {
						n, err := rConn.Read(buf)
						if err != nil {
							done <- err
							return
						}
						_, err = target.UdpConn.WriteTo(buf[:n], target.UdpAddr)
						if err != nil {
							done <- err
							return
						}
					}
				}()

				// relay from udp to tcp
				var n int
				buf := make([]byte, 65535)
				for {
					n, _, err = target.UdpConn.ReadFrom(buf)
					if err != nil {
						break
					}
					_, err = rConn.Write(buf[:n])
					if err != nil {
						break
					}
				}
				//wConn.SetReadDeadline(time.Now()) // wake up anthoer goroutine

				// ignore timeout error.
				err1 := <-done
				if !errors.Is(err, os.ErrDeadlineExceeded) {
					return
				}
				if !errors.Is(err1, os.ErrDeadlineExceeded) {
					return
				}
			} else {
				go func() {
					_, err = io.Copy(rConn, wConn)
					if nil != err {
						if strings.Index(err.Error(), "closed") == -1 {
							logger.Error(gCtx, map[string]interface{}{
								"action":    config.ActionSocketOperate,
								"errorCode": logger.ErrCodeTransfer,
								"error":     err,
								"remote":    remote.Name(),
								"target":    target.String(),
							})
						}
					}
				}()
				_, err = io.Copy(wConn, rConn)
				if nil != err {
					if strings.Index(err.Error(), "closed") == -1 {
						logger.Error(gCtx, map[string]interface{}{
							"action":    config.ActionSocketOperate,
							"errorCode": logger.ErrCodeTransfer,
							"error":     err,
							"remote":    remote.Name(),
							"target":    target.String(),
						})
					}
				}
			}
		}(conn)
	}
}

func (s *SocketServer) Handshake(ctx *context.Context, conn net.Conn) (io.ReadWriter, *common.TargetAddr, error) {
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
		return nil, nil, err
	}
	defer conn.SetReadDeadline(time.Time{})

	// https://www.ietf.org/rfc/rfc1928.txt
	buf := make([]byte, 4096) // 增大缓冲区以容纳 HTTP 请求

	// Read hello message
	n, err := conn.Read(buf[:])
	if err != nil || n == 0 {
		return nil, nil, fmt.Errorf("failed to read hello: %w", err)
	}

	// 检测协议类型：SOCKS5 的第一个字节是 0x05，HTTP 请求以 ASCII 字母开头
	firstByte := buf[0]

	// HTTP 请求检测：CONNECT, GET, POST, PUT, DELETE, HEAD, OPTIONS, PATCH
	if firstByte == 'C' || firstByte == 'G' || firstByte == 'P' || firstByte == 'D' || firstByte == 'H' || firstByte == 'O' {
		// 尝试解析 HTTP 请求
		return s.handleHTTPProxy(ctx, conn, buf[:n])
	}

	version := firstByte
	if version != Version5 {
		return nil, nil, fmt.Errorf("unsupported socks version %v", version)
	}

	// Write hello response
	// TODO: Support Auth
	_, err = conn.Write([]byte{Version5, AuthNone})
	if err != nil {
		return nil, nil, fmt.Errorf("failed to write hello response: %w", err)
	}

	// Read command message
	n, err = conn.Read(buf[:])
	if err != nil || n < 7 { // Shortest length is 7
		return nil, nil, fmt.Errorf("failed to read command: %w", err)
	}
	cmd := buf[1]
	addr := &common.TargetAddr{}
	switch cmd {
	case CmdConnect:
		addr.Proto = 1
	case CmdUDPAssociate:
		addr.Proto = 3
		ip := conn.LocalAddr().(*net.TCPAddr).IP
		udpAddr := &net.UDPAddr{IP: ip, Port: 0}
		udpConn, err := net.ListenUDP("udp", udpAddr)
		if nil != err {
			return nil, nil, fmt.Errorf("cannot listen udp %+v", err)
		}
		udpAddr.Port = udpConn.LocalAddr().(*net.UDPAddr).Port
		addr.UdpAddr = udpAddr
		addr.UdpConn = udpConn
		res := make([]byte, 0, 22)
		if ip := ip.To4(); ip != nil {
			//IPv4, len is 4
			res = append(res, []byte{Version5, 0x00, 0x00, ATypIP4}...)
			res = append(res, ip...)
		} else {
			// IPv6, len is 16
			res = append(res, []byte{Version5, 0x00, 0x00, ATypIP6}...)
			res = append(res, ip...)
		}

		portByte := [2]byte{}
		binary.BigEndian.PutUint16(portByte[:], uint16(udpAddr.Port))
		res = append(res, portByte[:]...)
		if _, err := conn.Write(res); err != nil {
			return nil, nil, fmt.Errorf("reply accept udp err %+v", err)
		}
	default:
		return nil, nil, fmt.Errorf("unsuppoted command %v", cmd)
	}
	l := 2
	off := 4
	switch buf[3] {
	case ATypIP4:
		l += net.IPv4len
		addr.IP = make(net.IP, net.IPv4len)
	case ATypIP6:
		l += net.IPv6len
		addr.IP = make(net.IP, net.IPv6len)
	case ATypDomain:
		l += int(buf[4])
		off = 5
	default:
		return nil, nil, fmt.Errorf("unknown address type %v", buf[3])
	}

	if len(buf[off:]) < l {
		return nil, nil, errors.New("short command request")
	}
	if addr.IP != nil {
		copy(addr.IP, buf[off:])
	} else {
		addr.Name = string(buf[off : off+l-2])
	}
	addr.Port = int(buf[off+l-2])<<8 | int(buf[off+l-1])

	// Write command response
	_, err = conn.Write([]byte{Version5, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00})
	if err != nil {
		return nil, nil, fmt.Errorf("failed to write command response: %w", err)
	}

	return conn, addr, err
}

func (s *SocketServer) Name() string {
	return "SocketServer"
}

// handleHTTPProxy 处理 HTTP CONNECT 代理请求
// HTTP CONNECT 请求格式: CONNECT host:port HTTP/1.1\r\nHost: host:port\r\n...\r\n\r\n
func (s *SocketServer) handleHTTPProxy(ctx *context.Context, conn net.Conn, initialData []byte) (io.ReadWriter, *common.TargetAddr, error) {
	// 将初始数据转换为字符串进行解析
	request := string(initialData)

	// 检查是否是 CONNECT 请求
	if !strings.HasPrefix(request, "CONNECT ") {
		// 非 CONNECT 的 HTTP 请求（如 GET/POST），对于透明代理需要特殊处理
		// 这里暂时只支持 CONNECT 方法（HTTPS 代理）
		return s.handleHTTPForward(ctx, conn, initialData)
	}

	// 解析 CONNECT 请求: CONNECT host:port HTTP/1.x
	lines := strings.Split(request, "\r\n")
	if len(lines) < 1 {
		return nil, nil, fmt.Errorf("invalid HTTP CONNECT request")
	}

	// 解析第一行: CONNECT host:port HTTP/1.1
	parts := strings.Fields(lines[0])
	if len(parts) < 2 {
		return nil, nil, fmt.Errorf("invalid HTTP CONNECT request format")
	}

	hostPort := parts[1]
	host, portStr, err := net.SplitHostPort(hostPort)
	if err != nil {
		// 如果没有端口，默认 443（HTTPS）
		host = hostPort
		portStr = "443"
	}

	port := 443
	if _, err := fmt.Sscanf(portStr, "%d", &port); err != nil {
		port = 443
	}

	// 读取完整的 HTTP 头部（直到 \r\n\r\n）
	fullRequest := request
	for !strings.Contains(fullRequest, "\r\n\r\n") {
		buf := make([]byte, 4096)
		n, err := conn.Read(buf)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to read HTTP headers: %w", err)
		}
		fullRequest += string(buf[:n])
	}

	// 构建目标地址
	addr := &common.TargetAddr{
		Proto: 1, // TCP
		Port:  port,
	}

	// 检查是否是 IP 地址
	if ip := net.ParseIP(host); ip != nil {
		addr.IP = ip
	} else {
		addr.Name = host
	}

	// 发送 HTTP 200 响应，表示隧道建立成功
	response := "HTTP/1.1 200 Connection Established\r\n\r\n"
	if _, err := conn.Write([]byte(response)); err != nil {
		return nil, nil, fmt.Errorf("failed to send HTTP 200 response: %w", err)
	}

	logger.Info(ctx, map[string]interface{}{
		"action": config.ActionRequestBegin,
		"method": "HTTP_CONNECT",
		"target": hostPort,
	}, "HTTP CONNECT tunnel established")

	return conn, addr, nil
}

// handleHTTPForward 处理非 CONNECT 的 HTTP 请求（GET/POST 等）
// 这种情况需要解析请求 URL，转发到目标服务器
func (s *SocketServer) handleHTTPForward(ctx *context.Context, conn net.Conn, initialData []byte) (io.ReadWriter, *common.TargetAddr, error) {
	request := string(initialData)
	lines := strings.Split(request, "\r\n")
	if len(lines) < 1 {
		return nil, nil, fmt.Errorf("invalid HTTP request")
	}

	// 解析第一行: GET http://host/path HTTP/1.1 或 GET /path HTTP/1.1
	parts := strings.Fields(lines[0])
	if len(parts) < 2 {
		return nil, nil, fmt.Errorf("invalid HTTP request format")
	}

	method := parts[0]
	url := parts[1]

	// 解析 URL
	var host string
	var port int = 80
	var path string = "/"

	if strings.HasPrefix(url, "http://") {
		// 绝对 URL: http://host:port/path
		url = strings.TrimPrefix(url, "http://")
		slashIdx := strings.Index(url, "/")
		if slashIdx > 0 {
			host = url[:slashIdx]
			path = url[slashIdx:]
		} else {
			host = url
		}
	} else if strings.HasPrefix(url, "/") {
		// 相对 URL: /path - 需要从 Host 头获取目标
		path = url
		for _, line := range lines[1:] {
			if strings.HasPrefix(strings.ToLower(line), "host:") {
				host = strings.TrimSpace(strings.TrimPrefix(line, "Host:"))
				host = strings.TrimSpace(strings.TrimPrefix(host, "host:"))
				break
			}
		}
	} else {
		return nil, nil, fmt.Errorf("invalid URL format: %s", url)
	}

	if host == "" {
		return nil, nil, fmt.Errorf("no host found in request")
	}

	// 解析 host:port
	if h, p, err := net.SplitHostPort(host); err == nil {
		host = h
		fmt.Sscanf(p, "%d", &port)
	}

	// 构建目标地址
	addr := &common.TargetAddr{
		Proto: 1, // TCP
		Port:  port,
	}

	if ip := net.ParseIP(host); ip != nil {
		addr.IP = ip
	} else {
		addr.Name = host
	}

	// 重写请求：将绝对 URL 改为相对 URL
	newFirstLine := fmt.Sprintf("%s %s %s", method, path, parts[2])
	lines[0] = newFirstLine

	// 移除 Proxy-Connection 头，添加 Connection: close
	newLines := make([]string, 0, len(lines))
	for _, line := range lines {
		lowerLine := strings.ToLower(line)
		if strings.HasPrefix(lowerLine, "proxy-connection:") {
			continue
		}
		newLines = append(newLines, line)
	}

	// 创建带前缀数据的包装器
	modifiedRequest := []byte(strings.Join(newLines, "\r\n"))
	prefixedConn := &prefixedReadWriter{
		prefix: modifiedRequest,
		conn:   conn,
	}

	logger.Info(ctx, map[string]interface{}{
		"action": config.ActionRequestBegin,
		"method": method,
		"target": fmt.Sprintf("%s:%d%s", host, port, path),
	}, "HTTP forward request")

	return prefixedConn, addr, nil
}

// prefixedReadWriter 包装连接，在第一次读取时返回预设的前缀数据
// 实现 io.ReadWriteCloser 接口
type prefixedReadWriter struct {
	prefix []byte
	conn   net.Conn
	offset int
}

func (p *prefixedReadWriter) Read(b []byte) (int, error) {
	if p.offset < len(p.prefix) {
		n := copy(b, p.prefix[p.offset:])
		p.offset += n
		return n, nil
	}
	return p.conn.Read(b)
}

func (p *prefixedReadWriter) Write(b []byte) (int, error) {
	return p.conn.Write(b)
}

func (p *prefixedReadWriter) Close() error {
	return p.conn.Close()
}

// LocalAddr 返回本地地址（实现 net.Conn 接口）
func (p *prefixedReadWriter) LocalAddr() net.Addr {
	return p.conn.LocalAddr()
}

// RemoteAddr 返回远程地址（实现 net.Conn 接口）
func (p *prefixedReadWriter) RemoteAddr() net.Addr {
	return p.conn.RemoteAddr()
}

// SetDeadline 设置读写超时（实现 net.Conn 接口）
func (p *prefixedReadWriter) SetDeadline(t time.Time) error {
	return p.conn.SetDeadline(t)
}

// SetReadDeadline 设置读超时（实现 net.Conn 接口）
func (p *prefixedReadWriter) SetReadDeadline(t time.Time) error {
	return p.conn.SetReadDeadline(t)
}

// SetWriteDeadline 设置写超时（实现 net.Conn 接口）
func (p *prefixedReadWriter) SetWriteDeadline(t time.Time) error {
	return p.conn.SetWriteDeadline(t)
}
