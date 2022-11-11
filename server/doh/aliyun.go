package doh

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/likexian/gokit/xhttp"
	"github.com/likexian/gokit/xip"
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

	param := xhttp.QueryParam{
		"name": name,
		"type": strings.TrimSpace(string(t)),
	}

	ss := strings.TrimSpace(string(s))
	if ss != "" {
		ss, err := xip.FixSubnet(ss)
		if err != nil {
			return nil, err
		}
		param["edns_client_subnet"] = ss
	}

	rsp, err := xhttp.New().Get(ctx, Upstream[c.provides], param, xhttp.Header{"accept": "application/dns-json"})
	if err != nil {
		return nil, err
	}
	// bt, _ := io.ReadAll(rsp.Response.Body)
	// fmt.Printf("%s", string(bt))
	defer rsp.Close()
	buf, err := rsp.Bytes()
	if err != nil {
		return nil, err
	}
	// fmt.Printf("%s", string(buf))
	rr := &Response{
		Provider: c.String(),
	}
	err = json.Unmarshal(buf, rr)
	if err != nil {
		return nil, err
	}

	if rr.Status != 0 {
		return rr, fmt.Errorf("doh: cloudflare: failed response code %d", rr.Status)
	}

	return rr, nil
}
