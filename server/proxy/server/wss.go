package server

import (
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

	"github.com/gorilla/websocket"
)

type WSSServer struct {
	Type     int8
	Port     int
	UserName string
	Password string
}

var upgrader = websocket.Upgrader{} // use default options

func (s *WSSServer) Start(l net.Listener) {
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
		conn, err := upgrader.Upgrade(writer, request, nil)
		if err != nil {
			_, _ = writer.Write([]byte(common.Body))
			return
		}
		defer conn.Close()
		wConn, target, err := s.Handshake(gCtx, conn.UnderlyingConn())
		if nil != err {
			_ = conn.WriteMessage(websocket.TextMessage, []byte(`{"code":0, "data":[], "message":"success"}`))
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
			_ = conn.WriteMessage(websocket.TextMessage, []byte(`{"code":0, "data":[], "message":"success"}`))
			return
		}
		go io.Copy(rConn, wConn)
		io.Copy(wConn, rConn)
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
func (s *WSSServer) Handshake(ctx *context.Context, conn net.Conn) (io.ReadWriter, *common.TargetAddr, error) {
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
	ec, err := common.NewChacha20Stream([]byte(config.Config.User), conn)
	if nil != err {
		return nil, nil, err
	}
	tBuf := make([]byte, 8)
	_, err = ec.Read(tBuf)
	if nil != err {
		return nil, nil, err
	}
	ts := binary.BigEndian.Uint64(tBuf)
	if uint64(time.Now().Unix())-ts > 10 {
		return nil, nil, errors.New("The time between server and client must same.")
	}

	dlBuf := make([]byte, 2)
	_, err = ec.Read(dlBuf)
	if nil != err {
		return nil, nil, err
	}
	dl := binary.BigEndian.Uint16(dlBuf)

	addrBuf := make([]byte, dl)
	_, err = ec.Read(addrBuf)
	if nil != err {
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
			return nil, nil, err
		}
		port64, err := strconv.ParseInt(portStr, 10, 64)
		if nil != err {
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
