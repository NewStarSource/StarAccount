package account

import (
	"errors"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strings"
)

func (config Config) secure() bool       { return config.Mode == "production" }
func (config Config) publicHost() string { u, _ := url.Parse(config.Origin); return u.Host }
func validateOrigin(value string, production bool) error {
	u, err := url.Parse(value)
	if err != nil || u.Host == "" || u.Opaque != "" || u.User != nil || u.Path != "" || u.RawQuery != "" || u.Fragment != "" || u.ForceQuery || strings.HasSuffix(u.Host, ":") {
		return errors.New("origin 必须是完整且不含路径的源地址")
	}
	if production {
		if u.Scheme != "https" || u.Hostname() == "localhost" {
			return errors.New("生产 origin 必须使用 HTTPS 域名")
		}
		if ip := net.ParseIP(u.Hostname()); ip != nil {
			return errors.New("生产 origin 必须使用域名")
		}
	} else if u.Scheme != "http" || net.ParseIP(u.Hostname()) == nil || !net.ParseIP(u.Hostname()).IsLoopback() {
		return errors.New("开发 origin 必须使用回环 HTTP")
	}
	if u.Port() != "" {
		if _, err := net.LookupPort("tcp", u.Port()); err != nil {
			return errors.New("origin 端口无效")
		}
	}
	return nil
}
func validateTransport(mode, address, origin string, proxies []string) error {
	if mode != "development" && mode != "test" && mode != "production" {
		return errors.New("mode 必须为 development、test 或 production")
	}
	host, port, err := net.SplitHostPort(address)
	if err != nil || net.ParseIP(host) == nil || !net.ParseIP(host).IsLoopback() || port == "" {
		return errors.New("仅允许回环监听；生产通过本机 HTTPS 代理访问")
	}
	if _, err := net.LookupPort("tcp", port); err != nil {
		return err
	}
	if err := validateOrigin(origin, mode == "production"); err != nil {
		return err
	}
	if mode != "production" {
		u, _ := url.Parse(origin)
		if u.Host != address {
			return errors.New("开发 origin 必须匹配监听地址")
		}
	}
	for _, value := range proxies {
		prefix, err := netip.ParsePrefix(value)
		if err != nil || prefix.Bits() == 0 {
			return errors.New("trusted_proxies 必须是明确的 IP CIDR，禁止全网信任")
		}
	}
	if mode == "production" && len(proxies) == 0 {
		return errors.New("生产必须配置 trusted_proxies")
	}
	return nil
}
func trustedPeer(remote string, proxies []string) bool {
	host, _, err := net.SplitHostPort(remote)
	if err != nil {
		return false
	}
	ip, err := netip.ParseAddr(host)
	if err != nil {
		return false
	}
	for _, value := range proxies {
		prefix, err := netip.ParsePrefix(value)
		if err == nil && prefix.Contains(ip.Unmap()) {
			return true
		}
	}
	return false
}

// Production accepts a single client address written by the local TLS proxy.
// The proxy must overwrite forwarded headers; arbitrary chains fail closed.
func (app *App) transport(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if app.config.secure() {
			if !trustedPeer(r.RemoteAddr, app.config.TrustedProxies) || r.Header.Get("X-Forwarded-Proto") != "https" || len(r.Header.Values("X-Forwarded-Proto")) != 1 || len(r.Header.Values("X-Forwarded-For")) != 1 {
				http.Error(w, "HTTPS proxy required", http.StatusBadRequest)
				return
			}
			ip, err := netip.ParseAddr(r.Header.Get("X-Forwarded-For"))
			if err != nil || ip.IsUnspecified() {
				http.Error(w, "Invalid client address", http.StatusBadRequest)
				return
			}
			r = r.Clone(r.Context())
			r.RemoteAddr = net.JoinHostPort(ip.Unmap().String(), "0")
			r.URL.Scheme = "https"
			r.URL.Host = r.Host
			w.Header().Set("Strict-Transport-Security", "max-age=31536000")
		}
		// No downstream component should reinterpret unchecked forwarding metadata.
		r.Header.Del("Forwarded")
		r.Header.Del("X-Forwarded-Host")
		r.Header.Del("X-Forwarded-For")
		r.Header.Del("X-Forwarded-Proto")
		next.ServeHTTP(w, r)
	})
}
