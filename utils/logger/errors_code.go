package logger

import "fmt"

var Messages = map[int]string{
	10000: "配置文件错误",
}
func Code2Message(code int) string {
	msg, ok := Messages[code]
	if ok {
		return msg
	} else {
		return fmt.Sprintf("未知错误：%d", code)
	}
}
