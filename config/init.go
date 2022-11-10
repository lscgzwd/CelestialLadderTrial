package config

import (
	"crypto/tls"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"path"
	"strings"
	"time"

	"github.com/caddyserver/certmagic"
)

var Config = new(config)
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
	_ = iota
	ServerTypeSocket
	ServerTypeHttp
	ServerTypeTLS
	ServerTypeWSS
)
const (
	_ = iota
	RemoteTypeTLS
	RemoteTypeWSS
	RemoteTypeDirect
)
const (
	TimeFormat  = "2006-01-02 15:04:05"
	ProjectCode = 1001
)

var TLSConfig = new(tls.Config)

func init() {
	var c string
	flag.StringVar(&c, "c", "config.json", "config file，default is config.json in current directory")
	flag.Parse()
	if len(c) == 0 {
		c = "config.json"
	}
	if strings.Index(c, "/") != 0 {
		p, err := os.Getwd()
		if nil != err {
			fmt.Printf("read config file with error：%+v", err)
			os.Exit(1)
		}
		c = path.Join(p, c)
	}
	// load json config file
	jsonFile, err := os.OpenFile(c, os.O_RDONLY, 0755)
	if nil != err {
		fmt.Printf("read config file with error：%+v", err)
		os.Exit(1)
	}
	jsonData, err := io.ReadAll(jsonFile)
	if nil != err {
		fmt.Printf("read config file with error：%+v", err)
		os.Exit(1)
	}
	err = json.Unmarshal(jsonData, Config)
	if nil != err {
		fmt.Printf("parse config with error：%+v", err)
		os.Exit(1)
	}
	if Config.In.Type == ServerTypeTLS {
		if len(Config.In.ServerName) < 3 {
			fmt.Printf("domain is wrong：%s", Config.In.ServerName)
			os.Exit(1)
		}
		// read and agree to your CA's legal documents
		certmagic.DefaultACME.Agreed = true
		// provide an email address
		certmagic.DefaultACME.Email = Config.In.Email
		// use the staging endpoint while we're developing
		certmagic.DefaultACME.CA = certmagic.LetsEncryptStagingCA

		TLSConfig, err = certmagic.TLS([]string{Config.In.ServerName})
		if nil != err {
			fmt.Printf("can not get cert for domain：%+v", err)
			os.Exit(1)
		}
		TLSConfig.NextProtos = append(TLSConfig.NextProtos, "http/1.1")
		//TLSConfig.ServerName = Config.In.ServerName
	}
}
