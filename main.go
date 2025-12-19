package main

import (
	"context"
	"os"
	"os/signal"
	"syscall"
	"time"

	"proxy/config"
	"proxy/server"
	_ "proxy/server"
	utilContext "proxy/utils/context"
	"proxy/utils/logger"
)

func main() {
	gCtx := utilContext.NewContext()

	// 创建一个可取消的上下文用于优雅关闭
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// 等待中断信号
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)

	// 信号处理
	go func() {
		sig := <-quit
		logger.Info(gCtx, map[string]interface{}{
			"action": config.ActionRuntime,
			"signal": sig.String(),
		}, "Received shutdown signal, gracefully shutting down...")

		// 设置关闭超时上下文
		shutdownCtx, shutdownCancel := context.WithTimeout(ctx, 30*time.Second)
		defer shutdownCancel()

		// 创建关闭完成通道
		shutdownDone := make(chan struct{})

		go func() {
			// 停止 TUN 服务
			server.StopTunService()

			// 恢复系统代理配置
			if config.Config.SystemProxy.Enable {
				server.RestoreSystemProxy(gCtx)
			}

			close(shutdownDone)
		}()

		// 等待关闭完成或超时
		select {
		case <-shutdownDone:
			logger.Info(gCtx, map[string]interface{}{
				"action": config.ActionRuntime,
			}, "Graceful shutdown completed")
		case <-shutdownCtx.Done():
			logger.Warn(gCtx, map[string]interface{}{
				"action": config.ActionRuntime,
			}, "Shutdown timeout, forcing exit")
		}

		cancel() // 通知主 goroutine 退出
	}()

	// 阻塞直到收到取消信号
	<-ctx.Done()

	logger.Info(gCtx, map[string]interface{}{
		"action": config.ActionRuntime,
	}, "Server exited")
}
