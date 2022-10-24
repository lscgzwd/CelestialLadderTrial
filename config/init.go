package config

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"path"
	"strings"
	"time"
)

var Config *config
var CstZone = time.FixedZone("CST", 8*3600) // 东八

const (
	ActionRuntime       = "Runtime"
	ActionRequestBegin  = "RequestBegin"
	ActionRequestEnd    = "RequestEnd"
	ActionDBOperate     = "DBOperate"
	ActionQueueOperate  = "QueueOperate"
	ActionSocketOperate = "SocketOperate"
	ActionCronOperate   = "CronOperate"
)

const (
	TimeFormat  = "2006-01-02 15:04:05"
	ProjectCode = 1001
)

func init() {
	var c string
	flag.StringVar(&c, "c", "config.json", "配置文件，默认为当前路径下的config.json")
	flag.Parse()

	if strings.Index(c, "/") != 0 {
		p, err := os.Getwd()
		if nil != err {
			panic(err)
		}
		c = path.Join(p, c)
	}
	// load json config file
	jsonFile, err := os.OpenFile(c, os.O_RDONLY, 0755)
	if nil != err {
		fmt.Printf("读取配置文件错误：%+v", err)
		os.Exit(1)
	}
	jsonData, err := io.ReadAll(jsonFile)
	if nil != err {
		fmt.Printf("读取配置文件错误：%+v", err)
		os.Exit(1)
	}
	err = json.Unmarshal(jsonData, Config)
	if nil != err {
		fmt.Printf("解析配置文件错误：%+v", err)
		os.Exit(1)
	}
}
