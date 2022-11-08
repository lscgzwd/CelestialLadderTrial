package main

import (
	"os"
	"os/signal"
	"syscall"

	"proxy/config"
	_ "proxy/server"
	"proxy/utils/context"
	"proxy/utils/logger"
)

func main() {
	gCtx := context.NewContext()
	// wait for interrupt signal to gracefully shut down the server with
	// a timeout of 10 seconds.
	quit := make(chan os.Signal, 1)
	done := make(chan bool, 1)
	// kill (no param) default send syscall.SIGTERM
	// kill -2 is syscall.SIGINT
	// kill -9 is syscall.SIGKILL but can't be caught, so don't need to add it
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-quit
		logger.Info(gCtx, map[string]interface{}{
			"action": config.ActionRuntime,
		}, "Server Shutdown...")
		done <- true
	}()
	<-done
	logger.Info(gCtx, map[string]interface{}{
		"action": config.ActionRuntime,
	}, "Server exiting")

}
