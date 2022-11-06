package proxy

import (
	"crypto/tls"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/pkg/errors"
	"proxy/config"
	"proxy/server/common"
	"proxy/utils/context"
	"proxy/utils/logger"
)

var tlsConfig *tls.Config

type TlsServer struct {
	Type     int8
	Port     int
	UserName string
}

func (s *TlsServer) Start(l net.Listener) {
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
	}()
}
func (s *TlsServer) Handshake(ctx *context.Context, conn net.Conn) (io.ReadWriter, *common.TargetAddr, error) {
	tlsConn := tls.Server(conn, config.TLSConfig)
	// Set handshake timeout 4 seconds
	if err := tlsConn.SetReadDeadline(time.Now().Add(time.Second * 4)); err != nil {
		return nil, nil, err
	}
	defer tlsConn.SetReadDeadline(time.Time{})

	err := tlsConn.Handshake()
	if nil != err {
		return nil, nil, err
	}
	ec, err := common.NewChacha20Stream([]byte(config.Config.User), tlsConn)
	if nil != err {
		_, _ = tlsConn.Write(common.DefaultHtml)
		return nil, nil, err
	}
	tBuf := make([]byte, 8)
	_, err = ec.Read(tBuf)
	if nil != err {
		_, _ = tlsConn.Write(common.DefaultHtml)
		return nil, nil, err
	}
	ts := binary.BigEndian.Uint64(tBuf)
	if uint64(time.Now().Unix())-ts > 10 {
		_, _ = tlsConn.Write(common.DefaultHtml)
		return nil, nil, errors.New("The time between server and client must same.")
	}

	dlBuf := make([]byte, 2)
	_, err = ec.Read(dlBuf)
	if nil != err {
		_, _ = tlsConn.Write(common.DefaultHtml)
		return nil, nil, err
	}
	dl := binary.BigEndian.Uint16(dlBuf)

	addrBuf := make([]byte, dl)
	_, err = ec.Read(addrBuf)
	if nil != err {
		_, _ = tlsConn.Write(common.DefaultHtml)
		return nil, nil, err
	}

	addr := string(addrBuf)
	i := strings.LastIndex(addr, ":")
	host := addr
	port := 80
	if i != -1 {
		var portStr string
		host, portStr, err = net.SplitHostPort(addr)
		if nil != err {
			_, _ = tlsConn.Write(common.DefaultHtml)
			return nil, nil, err
		}
		port64, err := strconv.ParseInt(portStr, 10, 64)
		if nil != err {
			_, _ = tlsConn.Write(common.DefaultHtml)
			return nil, nil, err
		}
		port = int(port64)
	}
	ip := net.ParseIP(host)
	var target = &common.TargetAddr{
		Port: port,
	}
	if nil == ip {
		target.Name = host
	} else {
		target.IP = ip
	}
	return conn, target, nil
}

type TlsRemote struct {
}

func (r *TlsRemote) Handshake(ctx *context.Context, target *common.TargetAddr) (io.ReadWriter, error) {
	conn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:%s", config.Config.Out.RemoteAddr, "443"), 10*time.Second)
	if nil != err {
		return nil, err
	}
	cc := tls.Client(conn, &tls.Config{
		ServerName:         config.Config.Out.RemoteAddr,
		ClientSessionCache: tls.NewLRUClientSessionCache(128),
		MinVersion:         tls.VersionTLS13,
		MaxVersion:         tls.VersionTLS13,
	})
	err = cc.Handshake()
	if nil != err {
		return nil, err
	}
	ec, err := common.NewChacha20Stream([]byte(config.Config.User), cc)
	if nil != err {
		return nil, err
	}
	tBuf := make([]byte, 8)
	binary.BigEndian.PutUint64(tBuf, uint64(time.Now().Unix()))
	_, err = ec.Write(tBuf)
	if nil != err {
		return nil, err
	}
	var addr = target.String()
	var l = int16(len(addr))
	// domain length limit
	if l > 253 {
		return nil, errors.New("target address's length large that 253.")
	}
	buf := make([]byte, 2)
	binary.BigEndian.PutUint16(buf, uint16(l))
	// write domain length
	_, err = ec.Write(buf)
	if nil != err {
		return nil, err
	}
	// write domain
	_, err = ec.Write([]byte(addr))
	if nil != err {
		return nil, err
	}

	return ec, err
}
