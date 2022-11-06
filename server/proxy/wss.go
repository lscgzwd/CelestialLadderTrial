package proxy

import (
	"crypto/tls"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/pkg/errors"
	"proxy/config"
	"proxy/server/common"
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

type WSSRemote struct {
}

func (r *WSSRemote) Handshake(ctx *context.Context, target *common.TargetAddr) (io.ReadWriter, error) {
	websocket.DefaultDialer.TLSClientConfig = &tls.Config{
		ServerName:         config.Config.Out.RemoteAddr,
		ClientSessionCache: tls.NewLRUClientSessionCache(128),
		MinVersion:         tls.VersionTLS13,
		MaxVersion:         tls.VersionTLS13,
	}
	u := url.URL{Scheme: "wss", Host: fmt.Sprintf("%s:%s", config.Config.Out.RemoteAddr, "443"), Path: "/"}
	c, _, err := websocket.DefaultDialer.Dial(u.String(), nil)
	if nil != err {
		return nil, err
	}
	ec, err := common.NewChacha20Stream([]byte(config.Config.User), c.UnderlyingConn())
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
