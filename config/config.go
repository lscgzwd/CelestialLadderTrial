package config

type config struct {
	Debug bool `json:"debug"`
	User string `json:"user"`
	In struct {
		Type int8 `json:"type"` // 1: local http 2: local socket5 3: http 4: web socket
		Port int `json:"port"` // 监听的端口
	} `json:"in"`
	Out struct {
		Type int8 `json:"type"` // 1: remote 2: direct
		RemoteAddr string `json:"remote_addr"`
		RemotePort string `json:"remote_port"`
	}
	WhiteList []string `json:"white_list"`
	BlackList []string `json:"black_list"`
	Log struct{
		Path     string `json:"path"`
		Level    string `json:"level"`
		FileName string `json:"file_name"`
	} `json:"log"`
}
