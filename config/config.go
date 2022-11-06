package config

type config struct {
	Debug     bool   `json:"debug"`
	User      string `json:"user"` // password, used to encode the connection, must 32 byte length
	ECSSubnet string `json:"ecs_subnet"`
	In        struct {
		Type       int8   `json:"type"`        // 1: local http 2: local socket5 3: https 4: web socket secure
		Port       int    `json:"port"`        // 监听的端口 小于1024的端口需要root权限启动 或者使用setcap 分配权限
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
	Log         struct {
		Path     string `json:"path"`
		Level    string `json:"level"`
		FileName string `json:"file_name"`
	} `json:"log"`
}
