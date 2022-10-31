package logger

import "fmt"

const (
	ErrCodeDefault   = 10000
	ErrCodeHandshake = 10001
	ErrCodeListen    = 10002
	ErrCodeAccept    = 10003
)

var Messages = map[int]string{
	ErrCodeDefault:   "未知错误",
	ErrCodeHandshake: "握手错误",
	ErrCodeListen:    "监听端口错误",
	ErrCodeAccept:    "接受连接错误",
}

func Code2Message(code int) string {
	msg, ok := Messages[code]
	if ok {
		return msg
	} else {
		return fmt.Sprintf("未知错误：%d", code)
	}
}
