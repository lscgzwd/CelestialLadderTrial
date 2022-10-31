package proxy

import (
	"crypto/tls"
	"fmt"
	"io"
	"net"

	"proxy/config"
	"proxy/server/common"
	"proxy/utils/context"
)

type TlsRemote struct {
}

func (r *TlsRemote) Handshake(ctx *context.Context, target *common.TargetAddr) (io.ReadWriter, error) {
	conn, err := net.Dial("tcp", fmt.Sprintf("%s:%s", config.Config.Out.RemoteAddr, "443"))
	cc := tls.Client(conn, &tls.Config{
		ServerName:         config.Config.Out.RemoteAddr,
		ClientSessionCache: tls.NewLRUClientSessionCache(10),
		MinVersion:         tls.VersionTLS13,
		MaxVersion:         tls.VersionTLS13,
	})
	err = cc.Handshake()
	return nil, err
}
