package server

import (
	"fmt"
	"net"
	"os"

	"proxy/config"
	"proxy/server/common"
	"proxy/server/proxy/server"
	"proxy/server/systemproxy"
	"proxy/server/tun"
	"proxy/utils/context"
	"proxy/utils/logger"
)

var tunService *tun.Service

func init() {
	gCtx := context.NewContext()

	// 根据配置自动设置系统代理（HTTP/HTTPS 指向本地端口）
	if config.Config.SystemProxy.Enable {
		systemproxy.Apply(gCtx, config.Config.In.Port)
	}

	// 初始化TUN服务（如果启用）
	if config.Config.Tun.Enable {
		var err error
		tunService, err = tun.NewService()
		if err != nil {
			logger.Error(gCtx, map[string]interface{}{
				"action":    config.ActionRuntime,
				"errorCode": logger.ErrCodeHandshake,
				"error":     err,
			}, "failed to initialize TUN service")
			os.Exit(-1)
		}

		// 启动TUN服务（在goroutine中运行）
		if tunService != nil {
			go func() {
				if err := tunService.Start(); err != nil {
					logger.Error(gCtx, map[string]interface{}{
						"action":    config.ActionRuntime,
						"errorCode": logger.ErrCodeHandshake,
						"error":     err,
					}, "TUN service error")
				}
			}()
		}
	}

	// 开启本地的TCP监听（SOCKS5 / HTTP / TLS / WSS 入口）
	listener, err := net.Listen("tcp", fmt.Sprintf("0.0.0.0:%d", config.Config.In.Port))
	if err != nil {
		logger.Errorf(gCtx, map[string]interface{}{
			"action":    config.ActionSocketOperate,
			"errorCode": logger.ErrCodeListen,
			"error":     err,
		}, "can not listen on %v: %v", fmt.Sprintf("0.0.0.0:%d", config.Config.In.Port), err)
		os.Exit(-1)
	}
	s := NewServer()
	if nil == s {
		logger.Error(gCtx, map[string]interface{}{
			"action": config.ActionRuntime,
		}, "unknown server type")
		os.Exit(-1)
	}
	s.Start(listener)
}

// StopTunService 停止TUN服务（用于优雅关闭）
func StopTunService() {
	if tunService != nil {
		tunService.Stop()
	}
}

// RestoreSystemProxy 恢复系统代理配置（用于优雅关闭）
func RestoreSystemProxy(ctx *context.Context) {
	systemproxy.Restore(ctx)
}

func NewServer() common.Server {
	switch config.Config.In.Type {
	case config.ServerTypeSocket:
		return &server.SocketServer{
			Type:     config.Config.In.Type,
			Port:     config.Config.In.Port,
			UserName: "",
			Password: "",
		}
	case config.ServerTypeHttp:
		return &server.HttpServer{
			Type:     config.Config.In.Type,
			Port:     config.Config.In.Port,
			UserName: "",
			Password: "",
		}
	case config.ServerTypeTLS:
		return &server.TlsServer{
			Type:     config.Config.In.Type,
			Port:     config.Config.In.Port,
			UserName: "",
		}
	case config.ServerTypeWSS:
		return &server.WSSServer{
			Type:     config.Config.In.Type,
			Port:     config.Config.In.Port,
			UserName: "",
		}
	}
	return nil
}
