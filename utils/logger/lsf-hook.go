package logger

import (
	"path"
	"strings"
	"time"

	rotate "github.com/lestrrat-go/file-rotatelogs"
	"github.com/rifflock/lfshook"
	"github.com/sirupsen/logrus"
	"proxy/config"
)

func newLfsHook(maxRemainCnt uint) logrus.Hook {
	ext := path.Ext(config.Config.Log.FileName)
	name := strings.TrimSuffix(path.Base(config.Config.Log.FileName), ext)
	logName := path.Join(config.Config.Log.Path, name)
	writer, err := rotate.New(
		logName+"-%y-%m-%d-%H"+ext,
		// WithLinkName为最新的日志建立软连接，以方便随着找到当前日志文件
		rotate.WithLinkName(logName+ext),

		// WithRotationTime设置日志分割的时间，这里设置为一小时分割一次
		rotate.WithRotationTime(time.Hour*6),

		// WithMaxAge和WithRotationCount二者只能设置一个，
		// WithMaxAge设置文件清理前的最长保存时间，
		// WithRotationCount设置文件清理前最多保存的个数。
		// rotate.WithMaxAge(time.Hour*24),
		rotate.WithRotationCount(maxRemainCnt),
	)

	if err != nil {
		logrus.Errorf("config local file system for logger error: %v", err)
	}

	lfsHook := lfshook.NewHook(lfshook.WriterMap{
		logrus.DebugLevel: writer,
		logrus.InfoLevel:  writer,
		logrus.WarnLevel:  writer,
		logrus.ErrorLevel: writer,
		logrus.FatalLevel: writer,
		logrus.PanicLevel: writer,
	}, DefaultFormatter())

	return lfsHook
}
