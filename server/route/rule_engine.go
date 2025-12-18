package route

import (
	"fmt"
	"net"
	"strings"
	"sync"

	"proxy/config"
)

// RuleEngine 规则引擎
type RuleEngine struct {
	whiteRules []Rule
	blackRules []Rule
	mu         sync.RWMutex
}

// Rule 规则接口
type Rule interface {
	Match(target string, ip net.IP) bool
	String() string
}

// CIDRRule CIDR规则
type cidrRule struct {
	network *net.IPNet
}

func (r *cidrRule) Match(target string, ip net.IP) bool {
	if ip == nil {
		return false
	}
	return r.network.Contains(ip)
}

func (r *cidrRule) String() string {
	return r.network.String()
}

// IPRangeRule IP段范围规则
type ipRangeRule struct {
	start net.IP
	end   net.IP
}

func (r *ipRangeRule) Match(target string, ip net.IP) bool {
	if ip == nil {
		return false
	}
	ip4 := ip.To4()
	if ip4 == nil {
		return false
	}
	start4 := r.start.To4()
	end4 := r.end.To4()
	if start4 == nil || end4 == nil {
		return false
	}
	return compareIP(ip4, start4) >= 0 && compareIP(ip4, end4) <= 0
}

func (r *ipRangeRule) String() string {
	return fmt.Sprintf("%s-%s", r.start.String(), r.end.String())
}

// DomainWildcardRule 域名通配符规则
type domainWildcardRule struct {
	pattern string
}

func (r *domainWildcardRule) Match(target string, ip net.IP) bool {
	return matchDomain(target, r.pattern)
}

func (r *domainWildcardRule) String() string {
	return r.pattern
}

// ExactRule 精确匹配规则
type exactRule struct {
	value string
}

func (r *exactRule) Match(target string, ip net.IP) bool {
	return strings.Contains(target, r.value)
}

func (r *exactRule) String() string {
	return r.value
}

var globalRuleEngine *RuleEngine
var ruleEngineOnce sync.Once

// GetRuleEngine 获取全局规则引擎
func GetRuleEngine() *RuleEngine {
	ruleEngineOnce.Do(func() {
		globalRuleEngine = NewRuleEngine()
		globalRuleEngine.LoadRules()
	})
	return globalRuleEngine
}

// NewRuleEngine 创建规则引擎
func NewRuleEngine() *RuleEngine {
	return &RuleEngine{
		whiteRules: make([]Rule, 0),
		blackRules: make([]Rule, 0),
	}
}

// LoadRules 加载规则
func (e *RuleEngine) LoadRules() {
	e.mu.Lock()
	defer e.mu.Unlock()

	// 清空现有规则
	e.whiteRules = make([]Rule, 0)
	e.blackRules = make([]Rule, 0)

	// 加载白名单规则
	for _, item := range config.Config.WhiteList {
		if rule := parseRule(item); rule != nil {
			e.whiteRules = append(e.whiteRules, rule)
		}
	}

	// 加载黑名单规则
	for _, item := range config.Config.BlackList {
		if rule := parseRule(item); rule != nil {
			e.blackRules = append(e.blackRules, rule)
		}
	}
}

// ReloadRules 重新加载规则
func (e *RuleEngine) ReloadRules() {
	e.LoadRules()
}

// IsWhite 检查是否在白名单
func (e *RuleEngine) IsWhite(target string, ip net.IP) bool {
	e.mu.RLock()
	defer e.mu.RUnlock()

	for _, rule := range e.whiteRules {
		if rule.Match(target, ip) {
			return true
		}
	}
	return false
}

// IsBlack 检查是否在黑名单
func (e *RuleEngine) IsBlack(target string, ip net.IP) bool {
	e.mu.RLock()
	defer e.mu.RUnlock()

	for _, rule := range e.blackRules {
		if rule.Match(target, ip) {
			return true
		}
	}
	return false
}

// parseRule 解析规则字符串
func parseRule(ruleStr string) Rule {
	ruleStr = strings.TrimSpace(ruleStr)
	if ruleStr == "" {
		return nil
	}

	// CIDR格式: 192.168.1.0/24
	if strings.Contains(ruleStr, "/") {
		_, ipNet, err := net.ParseCIDR(ruleStr)
		if err == nil {
			return &cidrRule{network: ipNet}
		}
	}

	// IP段范围: 192.168.1.1-192.168.1.100
	if strings.Contains(ruleStr, "-") && !strings.Contains(ruleStr, "*") {
		parts := strings.Split(ruleStr, "-")
		if len(parts) == 2 {
			startIP := net.ParseIP(strings.TrimSpace(parts[0]))
			endIP := net.ParseIP(strings.TrimSpace(parts[1]))
			if startIP != nil && endIP != nil {
				return &ipRangeRule{start: startIP, end: endIP}
			}
		}
	}

	// 域名通配符: *.example.com
	if strings.Contains(ruleStr, "*") {
		return &domainWildcardRule{pattern: ruleStr}
	}

	// 精确匹配（域名或IP）
	return &exactRule{value: ruleStr}
}

// matchDomain 匹配域名（支持通配符）
func matchDomain(domain, pattern string) bool {
	// 移除端口
	if idx := strings.Index(domain, ":"); idx != -1 {
		domain = domain[:idx]
	}

	// 精确匹配
	if pattern == domain {
		return true
	}

	// 通配符匹配
	if strings.HasPrefix(pattern, "*.") {
		suffix := pattern[2:] // 去掉 "*."
		return strings.HasSuffix(domain, "."+suffix) || domain == suffix
	}

	if strings.HasSuffix(pattern, ".*") {
		prefix := pattern[:len(pattern)-2] // 去掉 ".*"
		return strings.HasPrefix(domain, prefix+".")
	}

	// 包含匹配
	return strings.Contains(domain, pattern)
}

// compareIP 比较两个IP地址
func compareIP(ip1, ip2 net.IP) int {
	for i := 0; i < len(ip1) && i < len(ip2); i++ {
		if ip1[i] < ip2[i] {
			return -1
		}
		if ip1[i] > ip2[i] {
			return 1
		}
	}
	if len(ip1) < len(ip2) {
		return -1
	}
	if len(ip1) > len(ip2) {
		return 1
	}
	return 0
}

