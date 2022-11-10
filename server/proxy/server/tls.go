package server

import (
	"crypto/tls"
	"encoding/binary"
	"io"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/pkg/errors"
	"proxy/config"
	"proxy/server/common"
	"proxy/server/route"
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
				})
				wConn.Write(common.DefaultHtml)
				return
			}
			go io.Copy(rConn, wConn)
			io.Copy(wConn, rConn)
		}()
	}
}
func (s *TlsServer) Handshake(ctx *context.Context, conn net.Conn) (io.ReadWriter, *common.TargetAddr, error) {
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
