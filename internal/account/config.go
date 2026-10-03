package account

import (
	"encoding/json"
	"errors"
	"net"
	"net/url"
	"os"
	"path/filepath"
)

type Config struct {
	Mode           string `json:"mode"`
	Address        string `json:"address"`
	Origin         string `json:"origin"`
	Database       string `json:"database"`
	KeyFile        string `json:"key_file"`
	MailMode       string `json:"mail_mode"`
	SMTPHost       string `json:"smtp_host"`
	SMTPPort       int    `json:"smtp_port"`
	MailFrom       string `json:"mail_from"`
	OIDCSecretFile string `json:"oidc_secret_file"`
	SigningKeyFile string `json:"signing_key_file"`
	AtlasOrigin    string `json:"atlas_origin"`
}

func LoadConfig(filename string) (Config, []byte, error) {
	var config Config
	content, err := os.ReadFile(filename)
	if err != nil {
		return config, nil, errors.New("无法读取配置；先运行 init-dev 或提供 -config")
	}
	if err = json.Unmarshal(content, &config); err != nil {
		return config, nil, errors.New("配置 JSON 无效")
	}
	if err = config.Validate(); err != nil {
		return config, nil, err
	}
	keys, err := os.ReadFile(config.KeyFile)
	if err != nil || len(keys) != 96 {
		return config, nil, errors.New("key_file 必须包含 96 个随机字节")
	}
	return config, keys, nil
}

func (config Config) Validate() error {
	if config.Mode != "development" && config.Mode != "test" {
		return errors.New("当前阶段仅开放 development/test；生产需要 S03/S04 和上线验收")
	}
	host, _, err := net.SplitHostPort(config.Address)
	if err != nil || net.ParseIP(host) == nil || !net.ParseIP(host).IsLoopback() {
		return errors.New("当前阶段只允许绑定回环地址")
	}
	origin, err := url.Parse(config.Origin)
	if err != nil || origin.Host != config.Address || origin.Scheme != "http" || origin.Path != "" || origin.RawQuery != "" || origin.Fragment != "" || origin.User != nil {
		return errors.New("origin 必须与回环 HTTP 监听地址一致")
	}
	if config.Database == "" || config.KeyFile == "" {
		return errors.New("database/key_file 不能为空")
	}
	if config.MailMode != "synthetic" && config.MailMode != "smtp" {
		return errors.New("mail_mode 必须显式指定 synthetic 或 smtp")
	}
	if config.MailMode == "smtp" && (config.SMTPHost == "" || config.SMTPPort < 1 || config.MailFrom == "" || os.Getenv("STARACCOUNT_SMTP_USER") == "" || os.Getenv("STARACCOUNT_SMTP_PASSWORD") == "") {
		return errors.New("SMTP 配置不完整，不能启动")
	}
	if config.OIDCSecretFile != "" || config.SigningKeyFile != "" || config.AtlasOrigin != "" {
		origin, err := url.Parse(config.AtlasOrigin)
		if err != nil || origin.Scheme != "http" || net.ParseIP(origin.Hostname()) == nil || !net.ParseIP(origin.Hostname()).IsLoopback() || origin.User != nil || origin.Path != "" || origin.RawQuery != "" || origin.Fragment != "" || config.OIDCSecretFile == "" || config.SigningKeyFile == "" {
			return errors.New("OIDC 配置不完整或星图地址无效")
		}
	}
	return nil
}

func InitDevelopment() error {
	if err := os.MkdirAll(".local", 0700); err != nil {
		return err
	}
	config := Config{Mode: "development", Address: "127.0.0.1:4100", Origin: "http://127.0.0.1:4100", Database: filepath.Join(".local", "development.db"), KeyFile: filepath.Join(".local", "development.keys"), MailMode: "synthetic"}
	if _, err := os.Stat(".local/development.json"); !os.IsNotExist(err) {
		return errors.New("配置已存在，不覆盖")
	}
	keys := randomBytes(96)
	file, err := os.OpenFile(config.KeyFile, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return err
	}
	_, err = file.Write(keys)
	closeErr := file.Close()
	if err != nil {
		return err
	}
	if closeErr != nil {
		return closeErr
	}
	content, err := json.MarshalIndent(config, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(".local/development.json", content, 0600)
}
