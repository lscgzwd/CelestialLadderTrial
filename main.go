/*
Copyright 2024 CelestialLadderTrial Contributors

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

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

	// 确保程序退出时恢复系统代理（即使异常退出）
	defer func() {
		if config.Config.SystemProxy.Enable {
			logger.Info(gCtx, map[string]interface{}{
				"action": config.ActionRuntime,
			}, "program exiting, restoring system proxy...")
			server.RestoreSystemProxy(gCtx)
		}
	}()

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
			defer func() {
				// 确保即使发生 panic 也会恢复系统代理
				if r := recover(); r != nil {
					logger.Error(gCtx, map[string]interface{}{
						"action": config.ActionRuntime,
						"error":  r,
					}, "panic during shutdown, attempting to restore system proxy")
				}
				
				// 无论是否启用 SystemProxy，都尝试恢复（防止配置丢失）
				if config.Config.SystemProxy.Enable {
					logger.Info(gCtx, map[string]interface{}{
						"action": config.ActionRuntime,
					}, "restoring system proxy settings...")
					server.RestoreSystemProxy(gCtx)
				}
			}()

			// 停止 TUN 服务
			server.StopTunService()

			// 恢复系统代理配置（必须在 TUN 停止后）
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
			// 超时后仍然尝试恢复系统代理
			if config.Config.SystemProxy.Enable {
				logger.Warn(gCtx, map[string]interface{}{
					"action": config.ActionRuntime,
				}, "attempting to restore system proxy before force exit")
				server.RestoreSystemProxy(gCtx)
			}
		}

		cancel() // 通知主 goroutine 退出
	}()

	// 阻塞直到收到取消信号
	<-ctx.Done()

	logger.Info(gCtx, map[string]interface{}{
		"action": config.ActionRuntime,
	}, "Server exited")
}
