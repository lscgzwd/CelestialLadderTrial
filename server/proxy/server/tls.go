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

type TlsServer struct {
	Type     int8
	Port     int
	UserName string
}

func (s *TlsServer) Start(l net.Listener) {
	// begin accept connection
	for {
		conn, err := l.Accept()
		// process connection in go routing
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
			// catch panic
			defer func() {
				err := recover() // 内置函数，可以捕捉到函数异常
				if err != nil {
					// 这里是打印错误，还可以进行报警处理，例如微信，邮箱通知
					logger.Error(gCtx, map[string]interface{}{
						"action":    config.ActionRequestBegin,
						"errorCode": logger.ErrCodeHandshake,
						"error":     err,
					})
				}
			}()
			wConn, target, err := s.Handshake(gCtx, conn)
			if nil != err {
				logger.Error(gCtx, map[string]interface{}{
					"action":    config.ActionRequestBegin,
					"errorCode": logger.ErrCodeHandshake,
					"error":     err,
					"name":      s.Name(),
				})
				return
			}
			// get remote connection by policy
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
	cc := tls.Server(conn, config.TLSConfig)
	err := cc.Handshake()
	if nil != err {
		_, _ = conn.Write(common.DefaultHtml)
		logger.Info(ctx, map[string]interface{}{
			"action":    config.ActionRequestBegin,
			"errorCode": logger.ErrCodeHandshake,
			"error":     err,
		}, "tls handshake fail")
		return nil, nil, err
	}
	sc := common.NewSniffConn(cc)
	if sc.Sniff() == common.TypeHttp {
		_, _ = cc.Write(common.DefaultHtml)
		logger.Info(ctx, map[string]interface{}{
			"action":    config.ActionRequestBegin,
			"errorCode": logger.ErrCodeHandshake,
			"error":     err,
		}, "common http request")
		return nil, nil, errors.New("common http request")
	}
	ec := common.NewChacha20Stream([]byte(config.Config.User), sc)
	tBuf := make([]byte, 8)
	_, err = ec.Read(tBuf)
	if nil != err {
		logger.Error(ctx, map[string]interface{}{
			"action":    config.ActionRequestBegin,
			"errorCode": logger.ErrCodeHandshake,
			"error":     err,
		}, "read time buf")
		_, _ = cc.Write(common.DefaultHtml)
		return nil, nil, err
	}
	ts := binary.BigEndian.Uint64(tBuf)
	if uint64(time.Now().Unix())-ts > 10 {
		_, _ = cc.Write(common.DefaultHtml)
		return nil, nil, errors.New("The time between server and client must same.")
	}

	dlBuf := make([]byte, 2)
	_, err = ec.Read(dlBuf)
	if nil != err {
		_, _ = cc.Write(common.DefaultHtml)
		return nil, nil, err
	}
	dl := binary.BigEndian.Uint16(dlBuf)

	addrBuf := make([]byte, dl)
	_, err = ec.Read(addrBuf)
	if nil != err {
		_, _ = cc.Write(common.DefaultHtml)
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
			_, _ = cc.Write(common.DefaultHtml)
			return nil, nil, err
		}
		port64, err := strconv.ParseInt(portStr, 10, 64)
		if nil != err {
			_, _ = cc.Write(common.DefaultHtml)
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
	return ec, target, nil
}

func (s *TlsServer) Name() string {
	return "TlsServer"
}
