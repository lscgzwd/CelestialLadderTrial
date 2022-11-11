package client

import (
	"crypto/tls"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"time"

	"github.com/pkg/errors"
	"proxy/config"
	"proxy/server/common"
	"proxy/utils/context"
	"proxy/utils/logger"
)

type TlsRemote struct {
}

func (r *TlsRemote) Handshake(ctx *context.Context, target *common.TargetAddr) (io.ReadWriter, error) {
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
	conn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:%s", config.Config.Out.RemoteAddr, "443"), 10*time.Second)
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
	_, err = cc.Write([]byte("GET / HTTP/1.1\r\nHost: " + config.Config.Out.RemoteAddr + "\r\nConnection: keep-alive"))
	if nil != err {
		return nil, err
	}
	ec, err := common.NewChacha20Stream([]byte(config.Config.User), cc)
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
