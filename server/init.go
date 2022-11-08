package server

import (
	"fmt"
	"net"
	"os"

	"proxy/config"
	"proxy/server/common"
	"proxy/server/proxy/server"
	"proxy/utils/context"
	"proxy/utils/logger"
)

func init() {
	gCtx := context.NewContext()
	// 开启本地的TCP监听
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
