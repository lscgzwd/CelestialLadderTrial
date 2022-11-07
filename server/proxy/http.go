package proxy

import (
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"

	"proxy/config"
	"proxy/server/common"
	"proxy/server/route"
	"proxy/utils/context"
	"proxy/utils/logger"
)

type HttpServer struct {
	Type     int8
	Port     int
	UserName string
	Password string
}

func (s *HttpServer) Start(l net.Listener) {
	// TODO http basic auth
	err := http.Serve(l, http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		gCtx := context.NewContext()
		gCtx.Set("request", request)
		hj := writer.(http.Hijacker)
		conn, _, err := hj.Hijack()
		if err != nil {
			http.Error(writer, "cannot hijack", http.StatusInternalServerError)
			// _, _ = writer.Write(common.DefaultHtml)
			return
		}
		defer conn.Close()
		wConn, target, err := s.Handshake(gCtx, conn)
		if nil != err {
			logger.Error(gCtx, map[string]interface{}{
				"action":    config.ActionRequestBegin,
				"errorCode": logger.ErrCodeHandshake,
				"error":     err,
			})
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
func (s *HttpServer) Handshake(ctx *context.Context, conn net.Conn) (io.ReadWriter, *common.TargetAddr, error) {
	req, _ := ctx.Get("request")
	request, _ := req.(*http.Request)

	addr := request.Host
	i := strings.LastIndex(addr, ":")
	host := addr
	port := 80
	var err error
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
	if request.Method == http.MethodConnect {
		_, err := conn.Write([]byte("HTTP/1.1 200 Connection established\r\n\r\n"))
		if nil != err {
			return nil, nil, err
		}
		if port == 80 {
			port = 443
		}
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
