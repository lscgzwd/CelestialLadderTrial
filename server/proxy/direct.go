package proxy

import (
	"io"
	"net"
	"time"

	"proxy/server/common"
	"proxy/utils/context"
)

type DirectRemote struct {
}

func (r *DirectRemote) Handshake(ctx *context.Context, target *common.TargetAddr) (io.ReadWriter, error) {
	return net.DialTimeout("tcp", target.String(), 10*time.Second)
}
