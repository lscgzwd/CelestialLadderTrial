package config

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"os"
	"path"
	"strings"
	"sync"
	"time"

	"github.com/fsnotify/fsnotify"
)

var (
	configWatcher *fsnotify.Watcher
	configPath    string
	reloadMu      sync.RWMutex
	reloadCallbacks []func()
)

// StartConfigWatcher 启动配置文件监控
func StartConfigWatcher(configFile string) error {
	if configFile == "" {
		return nil
	}

	// 解析配置文件路径
	if strings.Index(configFile, "/") != 0 {
		p, err := os.Getwd()
		if nil != err {
			return fmt.Errorf("无法获取工作目录: %w", err)
		}
		configFile = path.Join(p, configFile)
	}

	configPath = configFile

	// 创建文件监控器
	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		return fmt.Errorf("创建文件监控器失败: %w", err)
	}

	configWatcher = watcher

	// 监控配置文件所在目录
	configDir := path.Dir(configFile)
	if err := watcher.Add(configDir); err != nil {
		watcher.Close()
		return fmt.Errorf("添加监控目录失败: %w", err)
	}

	// 启动监控goroutine
	go watchConfigFile()

	return nil
}

// StopConfigWatcher 停止配置文件监控
func StopConfigWatcher() {
	if configWatcher != nil {
		configWatcher.Close()
		configWatcher = nil
	}
}

// RegisterReloadCallback 注册配置重载回调
func RegisterReloadCallback(callback func()) {
	reloadMu.Lock()
	defer reloadMu.Unlock()
	reloadCallbacks = append(reloadCallbacks, callback)
}

// watchConfigFile 监控配置文件变化
func watchConfigFile() {
	debounceTimer := time.NewTimer(0)
	debounceTimer.Stop()
	var debounceDelay = 500 * time.Millisecond

	for {
		select {
		case event, ok := <-configWatcher.Events:
			if !ok {
				return
			}

			// 只处理配置文件的变化
			if event.Name != configPath {
				continue
			}

			// 文件写入或重命名
			if event.Op&fsnotify.Write == fsnotify.Write || event.Op&fsnotify.Rename == fsnotify.Rename {
				// 防抖：延迟处理
				debounceTimer.Reset(debounceDelay)
				<-debounceTimer.C

				// 重新加载配置
				if err := ReloadConfig(); err != nil {
					log.Printf("配置文件重载失败: %v", err)
				} else {
					log.Printf("配置文件重载成功")
				}
			}

		case err, ok := <-configWatcher.Errors:
			if !ok {
				return
			}
			log.Printf("配置文件监控错误: %v", err)
		}
	}
}

// ReloadConfig 重新加载配置
func ReloadConfig() error {
	reloadMu.Lock()
	defer reloadMu.Unlock()

	// 读取配置文件
	jsonFile, err := os.OpenFile(configPath, os.O_RDONLY, 0755)
	if err != nil {
		return fmt.Errorf("读取配置文件失败: %w", err)
	}
	defer jsonFile.Close()

	jsonData, err := io.ReadAll(jsonFile)
	if err != nil {
		return fmt.Errorf("读取配置文件内容失败: %w", err)
	}

	// 创建临时配置对象
	var newConfig config
	if err := json.Unmarshal(jsonData, &newConfig); err != nil {
		return fmt.Errorf("解析配置文件失败: %w", err)
	}

	// 原子性更新配置
	Config.Debug = newConfig.Debug
	Config.User = newConfig.User
	Config.ECSSubnet = newConfig.ECSSubnet
	Config.In = newConfig.In
	Config.Out = newConfig.Out
	Config.WhiteList = newConfig.WhiteList
	Config.BlackList = newConfig.BlackList
	Config.ChinaIpFile = newConfig.ChinaIpFile
	Config.GFWListFile = newConfig.GFWListFile
	Config.Tun = newConfig.Tun
	Config.Log = newConfig.Log

	// 重新加载规则引擎（通过回调函数，避免循环导入）
	// route.GetRuleEngine().ReloadRules() 将在回调中执行

	// 执行回调
	for _, callback := range reloadCallbacks {
		callback()
	}

	return nil
}

