package logger

import "fmt"

const (
	ErrCodeDefault   = 10000
	ErrCodeHandshake = 10001
)

var Messages = map[int]string{
	ErrCodeDefault:   "未知错误",
	ErrCodeHandshake: "握手错误",
}

func Code2Message(code int) string {
	msg, ok := Messages[code]
	if ok {
		return msg
	} else {
		return fmt.Sprintf("未知错误：%d", code)
	}
}
