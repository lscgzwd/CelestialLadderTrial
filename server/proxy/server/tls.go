package server

import (
	"bufio"
	"crypto/tls"
	"encoding/binary"
	"io"
	"net"
	"net/http"
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
	// TODO http basic auth
	err := http.Serve(tls.NewListener(l, config.TLSConfig), http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		gCtx := context.NewContext()
		gCtx.Set("request", request)
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
		h, ok := writer.(http.Hijacker)
		if !ok {
			logger.Error(gCtx, map[string]interface{}{
				"action":    config.ActionRequestBegin,
				"errorCode": logger.ErrCodeHandshake,
				"error":     errors.New("http hijack not support"),
			})
			writer.Write([]byte(common.Body))
			return
		}
		conn, buf, err := h.Hijack()
		if err != nil {
			logger.Error(gCtx, map[string]interface{}{
				"action":    config.ActionRequestBegin,
				"errorCode": logger.ErrCodeHandshake,
				"error":     err,
			})
			writer.Write([]byte(common.Body))
			return
		}
		defer conn.Close()
		gCtx.Set("rw", buf)
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
			buf.Write(common.DefaultHtml)
			buf.Flush()
			return
		}

		go func() {
			_, err = io.Copy(rConn, wConn)
			if nil != err {
				logger.Error(gCtx, map[string]interface{}{
					"action":    config.ActionSocketOperate,
					"errorCode": logger.ErrCodeTransfer,
					"error":     err,
				})
				buf.Write(common.DefaultHtml)
				buf.Flush()
			}
		}()
		_, err = io.Copy(wConn, rConn)
		if nil != err {
			logger.Error(gCtx, map[string]interface{}{
				"action":    config.ActionSocketOperate,
				"errorCode": logger.ErrCodeTransfer,
				"error":     err,
			})
			buf.Write(common.DefaultHtml)
			buf.Flush()
		}
	}))
	gCtx := context.NewContext()
	if nil != err {
		logger.Error(gCtx, map[string]interface{}{
			"action":    config.ActionRequestBegin,
			"errorCode": logger.ErrCodeHandshake,
			"error":     err,
		})
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
	rw, _ := ctx.Get("rw")
	buf := rw.(*bufio.ReadWriter)
	ec, err := common.NewChacha20Stream([]byte(config.Config.User), conn)
	if nil != err {
		buf.Write(common.DefaultHtml)
		buf.Flush()
		logger.Info(ctx, map[string]interface{}{
			"action":    config.ActionRequestBegin,
			"errorCode": logger.ErrCodeHandshake,
			"error":     err,
		}, "NewChacha20Stream")
		return nil, nil, err
	}
	tBuf := make([]byte, 8)
	_, err = ec.Read(tBuf)
	if nil != err {
		logger.Error(ctx, map[string]interface{}{
			"action":    config.ActionRequestBegin,
			"errorCode": logger.ErrCodeHandshake,
			"error":     err,
		}, "read time buf")
		buf.Write(common.DefaultHtml)
		buf.Flush()
		return nil, nil, err
	}
	ts := binary.BigEndian.Uint64(tBuf)
	if uint64(time.Now().Unix())-ts > 10 {
		buf.Write(common.DefaultHtml)
		buf.Flush()
		return nil, nil, errors.New("The time between server and client must same.")
	}

	dlBuf := make([]byte, 2)
	_, err = ec.Read(dlBuf)
	if nil != err {
		buf.Write(common.DefaultHtml)
		buf.Flush()
		return nil, nil, err
	}
	dl := binary.BigEndian.Uint16(dlBuf)

	addrBuf := make([]byte, dl)
	_, err = ec.Read(addrBuf)
	if nil != err {
		buf.Write(common.DefaultHtml)
		buf.Flush()
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
			buf.Write(common.DefaultHtml)
			buf.Flush()
			return nil, nil, err
		}
		port64, err := strconv.ParseInt(portStr, 10, 64)
		if nil != err {
			buf.Write(common.DefaultHtml)
			buf.Flush()
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
