package proxy

import (
	"crypto/tls"
	"encoding/binary"
	"fmt"
	"io"
	"net"

	"github.com/pkg/errors"
	"proxy/config"
	"proxy/server/common"
	"proxy/utils/context"
)

type TlsRemote struct {
}

func (r *TlsRemote) Handshake(ctx *context.Context, target *common.TargetAddr) (io.ReadWriter, error) {
	conn, err := net.Dial("tcp", fmt.Sprintf("%s:%s", config.Config.Out.RemoteAddr, "443"))
	if nil != err {
		return nil, err
	}
	cc := tls.Client(conn, &tls.Config{
		ServerName:         config.Config.Out.RemoteAddr,
		ClientSessionCache: tls.NewLRUClientSessionCache(128),
		MinVersion:         tls.VersionTLS13,
		MaxVersion:         tls.VersionTLS13,
	})
	err = cc.Handshake()
	if nil != err {
		return nil, err
	}
	ec, err := common.NewChacha20Stream([]byte(config.Config.User), cc)
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
