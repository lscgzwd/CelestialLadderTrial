package proxy

import (
	"io"
	"net"
	"net/http"

	"proxy/server/common"
	"proxy/utils/context"
)

type HttpServer struct {
	Type     int8
	Port     int
	UserName string
	Password string
}

func (s *HttpServer) Start(l net.Listener) {

}
func (s *HttpServer) Handshake(ctx *context.Context, conn net.Conn) (io.ReadWriter, *common.TargetAddr, error) {
	req, _ := ctx.Get("request")
	request, _ := req.(*http.Request)
	if request.Method == http.MethodConnect {

	}
	return nil, nil, nil
}
