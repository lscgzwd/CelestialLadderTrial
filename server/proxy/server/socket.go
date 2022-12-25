package server

import (
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"os"
	"strings"
	"time"

	"github.com/pkg/errors"
	"proxy/config"
	"proxy/server/common"
	"proxy/server/route"
	"proxy/utils/context"
	"proxy/utils/logger"
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
		go func() {
			defer conn.Close()
			gCtx := context.NewContext()
			if nil != err {
				logger.Error(gCtx, map[string]interface{}{
					"action":    config.ActionRequestBegin,
					"errorCode": logger.ErrCodeHandshake,
					"error":     err,
				})
				return
			}
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
				_ = wConn.(net.Conn).Close()
				switch rConn.(type) {
				case net.Conn:
					_ = rConn.(net.Conn).Close()
				case *common.Chacha20Stream:
					_ = rConn.(*common.Chacha20Stream).Close()
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
		}()
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
	buf := make([]byte, 512)

	// Read hello message
	n, err := conn.Read(buf[:])
	if err != nil || n == 0 {
		return nil, nil, fmt.Errorf("failed to read hello: %w", err)
	}
	version := buf[0]
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
