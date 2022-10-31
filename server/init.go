package server

import (
	"fmt"
	"net"
	"os"

	"proxy/config"
	"proxy/server/common"
	"proxy/server/proxy"
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
	server := NewServer()
	if nil == server {
		logger.Error(gCtx, map[string]interface{}{
			"action": config.ActionRuntime,
		}, "unknown server type")
		os.Exit(-1)
	}
	server.Start(listener)
}

func NewServer() common.Server {
	switch config.Config.In.Type {
	case config.ServerTypeSocket:
		return &proxy.SocketServer{
			Type:     config.Config.In.Type,
			Port:     config.Config.In.Port,
			UserName: "",
			Password: "",
		}
	}
	return nil
}
