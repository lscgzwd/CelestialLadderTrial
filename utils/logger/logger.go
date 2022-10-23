package logger

import (
	"bytes"
	"io"
	"os"
	"time"

	"proxy/config"
	"proxy/utils/context"

	"github.com/sirupsen/logrus"
)

var log = logrus.New()
var logEntry *logrus.Entry

func init() {
	level, err := logrus.ParseLevel(config.Config.Log.Level)
	if err != nil {
		level = logrus.DebugLevel
	}
	log.SetLevel(level)
	var buf io.Writer
	buf = new(bytes.Buffer)
	if config.Config.Debug {
		buf = os.Stdout
	}
	log.SetOutput(buf)
	log.SetReportCaller(false)
	log.SetFormatter(DefaultFormatter())
	logEntry = log.WithTime(time.Now().In(config.CstZone))
	log.Hooks.Add(newLfsHook(28))
}

func DefaultFormatter() *JSONFormatter {
	return &JSONFormatter{
		TimestampFormat: config.TimeFormat,
		DataKey:         "extra",
		FieldMap: FieldMap{
			logrus.FieldKeyTime:  "time",
			logrus.FieldKeyLevel: "level",
			logrus.FieldKeyMsg:   "message",
			logrus.FieldKeyFunc:  "func",
			logrus.FieldKeyFile:  "file",
		},
	}
}

func getContext(ctx *context.Context, data map[string]interface{}) logrus.Fields {
	fields := logrus.Fields{}
	if ctx != nil {
		var (
			processId    = os.Getpid()
			startTime, _ = ctx.Get("startTime")
			duration     = float64(time.Now().Sub(startTime.(time.Time)).Nanoseconds()/1e4) / 100.0 // 单位毫秒,保留2位小数
			traceID      = ctx.GetString("traceID")
		)
		fields = logrus.Fields{
			"processID": processId,
			"traceID":   traceID,
			"duration":  duration,
		}
	}
	for s, i := range data {
		fields[s] = i
	}
	return fields
}

// Info 打印Info级别的日志
func Info(ctx *context.Context, data map[string]interface{}, args ...interface{}) {
	logEntry.WithTime(time.Now().In(config.CstZone)).WithFields(getContext(ctx, data)).Info(args...)
}

// Infof 打印Infof级别的日志
func Infof(ctx *context.Context, data map[string]interface{}, format string, args ...interface{}) {
	logEntry.WithTime(time.Now().In(config.CstZone)).WithFields(getContext(ctx, data)).Infof(format, args...)
}

// Debug 打印日志
func Debug(ctx *context.Context, data map[string]interface{}, args ...interface{}) {
	logEntry.WithTime(time.Now().In(config.CstZone)).WithFields(getContext(ctx, data)).Debug(args...)
}

// Warn 打印日志
func Warn(ctx *context.Context, data map[string]interface{}, args ...interface{}) {
	logEntry.WithTime(time.Now().In(config.CstZone)).WithFields(getContext(ctx, data)).Warn(args...)
}

// Warnf 打印日志
func Warnf(ctx *context.Context, data map[string]interface{}, format string, args ...interface{}) {
	logEntry.WithTime(time.Now().In(config.CstZone)).WithFields(getContext(ctx, data)).Warnf(format, args...)
}

// Error 打印日志
func Error(ctx *context.Context, data map[string]interface{}, args ...interface{}) {
	logEntry.WithTime(time.Now().In(config.CstZone)).WithFields(getContext(ctx, data)).Error(args...)
}

// Errorf 打印日志
func Errorf(ctx *context.Context, data map[string]interface{}, format string, args ...interface{}) {
	logEntry.WithTime(time.Now().In(config.CstZone)).WithFields(getContext(ctx, data)).Errorf(format, args...)
}

// Fatal 打印日志
func Fatal(ctx *context.Context, data map[string]interface{}, args ...interface{}) {
	logEntry.WithTime(time.Now().In(config.CstZone)).WithFields(getContext(ctx, data)).Fatal(args...)
}

// Trace 打印日志
func Trace(ctx *context.Context, data map[string]interface{}, args ...interface{}) {
	logEntry.WithTime(time.Now().In(config.CstZone)).WithFields(getContext(ctx, data)).Trace(args...)
}
