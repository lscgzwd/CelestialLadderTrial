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
	"proxy/server/proxy"
	"proxy/utils/context"
	"proxy/utils/gfwlist"
	"proxy/utils/helper"
)

type ipRange struct {
	Min uint32
	Max uint32
}

var cnIp = make(map[uint8][]ipRange)
var gfw *gfwlist.GFWList

func init() {
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
		config.Config.ChinaIpFile = path.Join(p, config.Config.ChinaIpFile)
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
func GetRemote(ctx *context.Context, target *common.TargetAddr) common.Remote {
	if config.Config.Out.Type == config.RemoteTypeDirect {
		return &proxy.DirectRemote{}
	}
	if target.IP == nil {
		var u = &url.URL{
			Scheme: "http",
			Host:   target.Host(),
			Path:   "/",
		}
		if target.Port == 443 {
			u.Scheme = "https"
		}
		if gfw.IsBlockedByGFW(&http.Request{
			Method: "GET",
			URL:    u,
			Host:   target.String(),
		}) {
			switch config.Config.Out.Type {
			case config.RemoteTypeTLS:
				return &proxy.TlsRemote{}
			case config.RemoteTypeWSS:
				return &proxy.WSSRemote{}
			default:
				return &proxy.DirectRemote{}
			}
		} else {
			// doh 获取域名解析
			ctx, cancel := context2.WithTimeout(context2.Background(), 10*time.Second)
			defer cancel()

			c := doh.New()
			// ECS subnet
			var subnet = config.Config.ECSSubnet
			if subnet == "" {
				subnet = "110.242.68.0/24"
			}
			rsp, err := c.ECSQuery(ctx, "www.aliyun.com", doh.TypeA, doh.ECS(subnet))
			if nil != err {

			}
		}
	}
	return nil
}

func IsWhite(target string) bool {
	for _, v := range config.Config.WhiteList {
		if strings.
	}
}
