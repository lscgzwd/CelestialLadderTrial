package doh

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/likexian/gokit/xip"
	"proxy/server/common"
)

type AliyunProvider struct {
	provides int
}

const (
	// DefaultProvides is default provides
	DefaultProvides = iota
)

var (
	// Upstream is DoH query upstream
	Upstream = map[int]string{
		DefaultProvides: "https://dns.alidns.com/resolve",
	}
)

// New returns a new cloudflare provider client
func New() *AliyunProvider {
	return &AliyunProvider{
		provides: DefaultProvides,
	}
}

// String returns string of provider
func (c *AliyunProvider) String() string {
	return "aliyun"
}

// SetProvides set upstream provides type, cloudflare does NOT supported
func (c *AliyunProvider) SetProvides(p int) error {
	c.provides = DefaultProvides
	return nil
}

// Query do DoH query
func (c *AliyunProvider) Query(ctx context.Context, d Domain, t Type) (*Response, error) {
	return c.ECSQuery(ctx, d, t, "")
}

// ECSQuery do DoH query with the edns0-client-subnet option
func (c *AliyunProvider) ECSQuery(ctx context.Context, d Domain, t Type, s ECS) (*Response, error) {
	name, err := d.Punycode()
	if err != nil {
		return nil, err
	}

	// 构建请求参数
	params := url.Values{}
	params.Set("name", name)
	params.Set("type", strings.TrimSpace(string(t)))

	ss := strings.TrimSpace(string(s))
	if ss != "" {
		ss, err := xip.FixSubnet(ss)
		if err != nil {
			return nil, err
		}
		params.Set("edns_client_subnet", ss)
	}

	// 创建绑定到原始接口的 HTTP 客户端，确保 DoH 查询不走 TUN
	dialer := common.GetOriginalInterfaceDialer()
	transport := &http.Transport{
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			return dialer.DialContext(ctx, network, addr)
		},
		// 不使用代理
		Proxy: nil,
	}
	httpClient := &http.Client{
		Transport: transport,
		Timeout:   10 * time.Second,
	}

	// 构建请求 URL
	reqURL := Upstream[c.provides] + "?" + params.Encode()

	// 创建请求
	req, err := http.NewRequestWithContext(ctx, "GET", reqURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/dns-json")

	// 发送请求
	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	// 读取响应
	buf, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	rr := &Response{
		Provider: c.String(),
	}
	err = json.Unmarshal(buf, rr)
	if err != nil {
		return nil, err
	}

	if rr.Status != 0 {
		return rr, fmt.Errorf("doh: aliyun: failed response code %d", rr.Status)
	}

	return rr, nil
}
