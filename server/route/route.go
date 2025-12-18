package route

import (
	context2 "context"
	"fmt"
	"log"
	"math"
	"net"
	"net/http"
	"net/url"
	"os"
	"path"
	"strconv"
	"strings"
	"time"

	"proxy/config"
	"proxy/server/common"
	"proxy/server/doh"
	"proxy/server/proxy/client"
	"proxy/utils/context"
	"proxy/utils/gfwlist"
	"proxy/utils/helper"
	"proxy/utils/logger"
)

type ipRange struct {
	Min uint32
	Max uint32
}

var cnIp = make(map[uint8][]ipRange)
var gfw *gfwlist.GFWList

func init() {
	// 注册配置重载回调
	config.RegisterReloadCallback(func() {
		// 重新加载规则引擎
		GetRuleEngine().ReloadRules()
	})
	
	var err error
	if len(config.Config.GFWListFile) == 0 {
		config.Config.GFWListFile = "gfwlist.txt"
	}
	if strings.Index(config.Config.GFWListFile, "/") != 0 {
		p, err := os.Getwd()
		if nil != err {
			fmt.Printf("read ip file for China with error：%+v", err)
			os.Exit(1)
		}
		config.Config.GFWListFile = path.Join(p, config.Config.GFWListFile)
	}
	gfw, err = gfwlist.NewGFWList("https://raw.githubusercontent.com/gfwlist/gfwlist/master/gfwlist.txt", &http.Client{}, make([]string, 0), config.Config.GFWListFile, false)
	if nil != err {
		log.Printf("#####%v", err)
		return
	}
	if len(config.Config.ChinaIpFile) > 0 {
		if strings.Index(config.Config.ChinaIpFile, "/") != 0 {
			p, err := os.Getwd()
			if nil != err {
				fmt.Printf("read ip file for China with error：%+v", err)
				os.Exit(1)
			}
			config.Config.ChinaIpFile = path.Join(p, config.Config.ChinaIpFile)
		}
		fileContent, err := os.ReadFile(config.Config.ChinaIpFile)
		if nil != err {
			fmt.Printf("read ip file for China with error：%+v", err)
			os.Exit(1)
		}
		lines := strings.Split(string(fileContent), "\n")
		for k, line := range lines {
			line = strings.Trim(line, "\r\t ")
			if len(line) > 0 {
				segs := strings.Split(line, ".")
				if len(segs) != 4 {
					fmt.Printf("ignore line：%d, wrong ipv4 format", k)
					continue
				}
				first, err := strconv.ParseUint(segs[0], 10, 64)
				if nil != err {
					fmt.Printf("ignore line：%d, wrong ipv4 format", k)
					continue
				}
				list, exist := cnIp[uint8(first)]
				if !exist {
					list = make([]ipRange, 0)
				}
				_, n, err := net.ParseCIDR(line)
				if nil != err {
					fmt.Printf("ignore line：%d, wrong ipv4 format", k)
					continue
				}
				min := helper.Ip2long(n.IP.String())
				mask, _ := n.Mask.Size() // eg: 8 16 24 32
				max := min + uint32(math.Pow(2, float64(32-mask))) - 1
				list = append(list, ipRange{
					Min: min,
					Max: max,
				})
				cnIp[uint8(first)] = list
			}
		}
	}
}

// IsCnIp determine chinese ip
func IsCnIp(ctx *context.Context, ip string) bool {
	segs := strings.Split(ip, ".")
	first, _ := strconv.ParseUint(segs[0], 10, 64)
	list, exist := cnIp[uint8(first)]
	if !exist {
		return false
	}
	min := helper.Ip2long(ip)
	for _, v := range list {
		if min >= v.Min && min <= v.Max {
			return true
		}
	}
	return false
}
func GetRemote(ctx *context.Context, target *common.TargetAddr) common.Remote {
	if config.Config.Out.Type == config.RemoteTypeDirect {
		return &client.DirectRemote{}
	}
	// check white and black list
	if IsWhite(target.String()) {
		return &client.DirectRemote{}
	} else if IsBlack(target.String()) {
		switch config.Config.Out.Type {
		case config.RemoteTypeTLS:
			return &client.TlsRemote{}
		case config.RemoteTypeWSS:
			return &client.WSSRemote{}
		default:
			return &client.DirectRemote{}
		}
	}
	// domain
	if target.IP == nil {
		var u = &url.URL{
			Scheme: "http",
			Host:   target.Host(),
			Path:   "/",
		}
		if target.Port == 443 {
			u.Scheme = "https"
		}
		// gfw list check
		if gfw.IsBlockedByGFW(&http.Request{
			Method: "GET",
			URL:    u,
			Host:   target.String(),
		}) {
			switch config.Config.Out.Type {
			case config.RemoteTypeTLS:
				return &client.TlsRemote{}
			case config.RemoteTypeWSS:
				return &client.WSSRemote{}
			default:
				return &client.DirectRemote{}
			}
		} else if strings.HasSuffix(target.Name, ".cn") {
			return &client.DirectRemote{}
		} else {
			// doh 获取域名解析
			ctxCancel, cancel := context2.WithTimeout(context2.Background(), 10*time.Second)
			defer cancel()

			c := doh.New()
			// ECS subnet
			var subnet = config.Config.ECSSubnet
			if subnet == "" {
				subnet = "110.242.68.0/24"
			}
			rsp, err := c.ECSQuery(ctxCancel, doh.Domain(target.Name), doh.TypeA, doh.ECS(subnet))
			if nil != err {
				// doh err , return direct
				logger.Error(ctx, map[string]interface{}{
					"action":    config.ActionSocketOperate,
					"errorCode": logger.ErrCodeHandshake,
					"error":     err,
				}, "ECSQuery")
				return &client.DirectRemote{}
			}
			var ip string
			for _, v := range rsp.Answer {
				// only use ipv4 type A record
				// @link https://www.alidns.com/articles/6018321800a44d0e45e90d71
				if v.Type == 1 {
					ip = v.Data
				}
			}
			if ip != "" && len(ip) > 0 {
				var ipObj = net.ParseIP(ip)
				// local network ip
				if nil == ipObj || ipObj.IsLoopback() || ipObj.IsPrivate() {
					return &client.DirectRemote{}
				}
				// chinese ip
				if IsCnIp(ctx, ip) {
					return &client.DirectRemote{}
				}
				switch config.Config.Out.Type {
				case config.RemoteTypeTLS:
					return &client.TlsRemote{}
				case config.RemoteTypeWSS:
					return &client.WSSRemote{}
				default:
					return &client.DirectRemote{}
				}
			}
			return &client.DirectRemote{}
		}
	} else {
		// local network or chinese ip
		if IsCnIp(ctx, target.IP.String()) || target.IP.IsLoopback() || target.IP.IsPrivate() {
			return &client.DirectRemote{}
		}
		switch config.Config.Out.Type {
		case config.RemoteTypeTLS:
			return &client.TlsRemote{}
		case config.RemoteTypeWSS:
			return &client.WSSRemote{}
		default:
			return &client.DirectRemote{}
		}
	}
}

// IsWhite check white list
func IsWhite(target string) bool {
	// 解析目标地址获取IP
	var ip net.IP
	if addr, err := common.NewTargetAddr(target); err == nil {
		ip = addr.IP
	}

	// 使用规则引擎检查
	engine := GetRuleEngine()
	return engine.IsWhite(target, ip)
}

// IsBlack check black list
func IsBlack(target string) bool {
	// 解析目标地址获取IP
	var ip net.IP
	if addr, err := common.NewTargetAddr(target); err == nil {
		ip = addr.IP
	}

	// 使用规则引擎检查
	engine := GetRuleEngine()
	return engine.IsBlack(target, ip)
}
