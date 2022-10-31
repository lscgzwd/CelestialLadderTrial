package proxy

import (
	"io"
	"net"

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
	return nil, nil, nil
}
