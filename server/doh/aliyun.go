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
	"sync"
	"time"

	"github.com/likexian/gokit/xip"
	"proxy/server/common"
)

type AliyunProvider struct {
	provides int
	client   *http.Client
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

	// 全局单例 DoH 提供者，复用 HTTP 客户端
	globalProvider     *AliyunProvider
	globalProviderOnce sync.Once
)

// New returns the global singleton AliyunProvider
// 使用单例模式，复用 HTTP 客户端以提高性能
func New() *AliyunProvider {
	globalProviderOnce.Do(func() {
		globalProvider = &AliyunProvider{
			provides: DefaultProvides,
			client:   createHTTPClient(),
		}
	})
	return globalProvider
}

// createHTTPClient 创建绑定到原接口的 HTTP 客户端
// 只创建一次，复用连接池
func createHTTPClient() *http.Client {
	dialer := common.GetOriginalInterfaceDialer()
	transport := &http.Transport{
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			return dialer.DialContext(ctx, network, addr)
		},
		Proxy:                 nil, // 不使用代理
		MaxIdleConns:          100,
		MaxIdleConnsPerHost:   10,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
		ForceAttemptHTTP2:     true,
	}
	return &http.Client{
		Transport: transport,
		Timeout:   10 * time.Second,
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

	// 构建缓存 key
	cacheKey := fmt.Sprintf("%s:%s:%s", name, string(t), string(s))

	// 检查缓存
	cache := GetCache()
	if cached, ok := cache.Get(cacheKey); ok {
		return cached, nil
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

	// 构建请求 URL
	reqURL := Upstream[c.provides] + "?" + params.Encode()

	// 创建请求
	req, err := http.NewRequestWithContext(ctx, "GET", reqURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/dns-json")

	// 发送请求（使用复用的 HTTP 客户端）
	resp, err := c.client.Do(req)
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

	// 从响应中获取 TTL，设置缓存
	var ttl time.Duration = 300 * time.Second // 默认 5 分钟
	if len(rr.Answer) > 0 && rr.Answer[0].TTL > 0 {
		ttl = time.Duration(rr.Answer[0].TTL) * time.Second
	}
	cache.Set(cacheKey, rr, ttl)

	return rr, nil
}
