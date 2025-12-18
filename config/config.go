package config

type config struct {
	Debug     bool   `json:"debug"`
	User      string `json:"user"` // password, used to encode the connection, must 32 byte length
	ECSSubnet string `json:"ecs_subnet"`
	In        struct {
		Type       int8   `json:"type"`        // 1: local socks5 2: local http 3: https 4: web socket secure
		Port       int    `json:"port"`        // https 和wss 不能指定，默认443
		ServerName string `json:"server_name"` // 本机是https服务器时，使用的域名
		Email      string `json:"email"`       // used to issue cert
	} `json:"in"`
	Out struct {
		Type       int8   `json:"type"`        // 1: remote tls 2: remote wss 3: direct
		RemoteAddr string `json:"remote_addr"` // remote时，远端服务器地址，由于tls原因，仅支持域名，如:my-ti-zi.remote.cn
	}
	WhiteList   []string `json:"white_list"`
	BlackList   []string `json:"black_list"`
	ChinaIpFile string   `json:"china_ip_file"`
	GFWListFile string   `json:"gfw_list_file"`
	Tun         struct {
		Enable  bool     `json:"enable"`
		Name    string   `json:"name"`
		Address string   `json:"address"`
		Netmask string   `json:"netmask"`
		MTU     int      `json:"mtu"`
		DNS     []string `json:"dns"`
	} `json:"tun"`
	SystemProxy struct {
		Enable bool `json:"enable"` // 是否自动配置系统代理
	} `json:"system_proxy"`
	Log struct {
		Path     string `json:"path"`
		Level    string `json:"level"`
		FileName string `json:"file_name"`
	} `json:"log"`
}
