package client

import (
	"crypto/tls"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"time"

	"github.com/go-errors/errors"
	"proxy/config"
	"proxy/server/common"
	"proxy/utils/context"
	"proxy/utils/logger"
)

type TlsRemote struct {
}

func (r *TlsRemote) Handshake(ctx *context.Context, target *common.TargetAddr) (ec io.ReadWriter, err error) {
	// 在函数退出前，执行defer
	// 捕捉异常后，程序不会异常退出
	defer func() {
		r := recover() // 内置函数，可以捕捉到函数异常
		if r != nil {
			// 这里是打印错误，还可以进行报警处理，例如微信，邮箱通知
			logger.Error(ctx, map[string]interface{}{
				"action":    config.ActionRequestBegin,
				"errorCode": logger.ErrCodeHandshake,
				"error":     err,
			})
			err = r.(error)
			fmt.Println(string(errors.Wrap(err, 3).Stack()))
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
	ec = common.NewChacha20Stream([]byte(config.Config.User), cc)
	tBuf := make([]byte, 8)
	binary.BigEndian.PutUint64(tBuf, uint64(time.Now().Unix()))
	_, err = ec.Write(tBuf)
	if nil != err {
		return nil, err
	}
	pBuf := make([]byte, 2)
	binary.BigEndian.PutUint16(pBuf, target.Proto)
	_, err = ec.Write(pBuf)
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

func (r *TlsRemote) Name() string {
	return "TLSRemote"
}
