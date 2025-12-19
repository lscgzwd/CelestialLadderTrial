package client

import (
	"io"
	"net"

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
	
	// 使用绑定到原默认接口的 Dialer，确保不走 TUN
	dialer := common.GetOriginalInterfaceDialer()
	
	switch target.Proto {
	case 3:
		udpAddr := &net.UDPAddr{IP: target.IP, Port: target.Port}
		target.RUdpAddr = udpAddr

		// UDP 也需要绑定到原接口
		var localAddr *net.UDPAddr
		if dialer.LocalAddr != nil {
			if tcpAddr, ok := dialer.LocalAddr.(*net.TCPAddr); ok {
				localAddr = &net.UDPAddr{
					IP:   tcpAddr.IP,
					Port: 0, // 系统自动分配端口
				}
			}
		}
		
		udpConn, err := net.DialUDP("udp", localAddr, udpAddr)
		if nil != err {
			return nil, err
		}
		target.RUdpConn = udpConn
		return udpConn, nil
	default:
		return dialer.Dial("tcp", target.String())
	}
}
func (r *DirectRemote) Name() string {
	return "DirectRemote"
}
