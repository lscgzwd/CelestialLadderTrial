package proxy

import (
	"io"
	"net"

	"proxy/server/common"
	"proxy/utils/context"
)

type DirectRemote struct {
}

func (r *DirectRemote) Handshake(ctx *context.Context, target *common.TargetAddr) (io.ReadWriter, error) {
	return net.Dial("tcp", target.String())
}
