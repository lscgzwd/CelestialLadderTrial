package client

import (
	"io"
	"net"
	"time"

	"proxy/config"
	"proxy/server/common"
	"proxy/utils/context"
	"proxy/utils/logger"
)

type DirectRemote struct {
}

func (r *DirectRemote) Handshake(ctx *context.Context, target *common.TargetAddr) (io.ReadWriter, error) {
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
	return net.DialTimeout("tcp", target.String(), 10*time.Second)
}
func (r *DirectRemote) Name() string {
	return "DirectRemote"
}
