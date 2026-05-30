package core

import (
	"context"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"golang.org/x/net/proxy"
)

const DefaultHTTPTimeout = 15 * time.Second

type ProxyConfig struct {
	Enabled  bool
	Type     string // "http", "socks5", "tor"
	Address  string // e.g. "127.0.0.1:9050"
	Username string
	Password string
}

// globalProxyCfg is set by ApplyGlobalProxy so that ApplyDoH can inspect the
// active proxy type and avoid breaking socks5/Tor routing.
var globalProxyCfg ProxyConfig

func ApplyGlobalProxy(cfg ProxyConfig) error {
	globalProxyCfg = cfg
	if !cfg.Enabled {
		return nil
	}
	transport := &http.Transport{
		Proxy: http.ProxyFromEnvironment,
		DialContext: (&net.Dialer{
			Timeout:   30 * time.Second,
			KeepAlive: 30 * time.Second,
		}).DialContext,
		ForceAttemptHTTP2:     true,
		MaxIdleConns:          100,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
	}

	switch cfg.Type {
	case "http":
		proxyURL, err := url.Parse(cfg.Address)
		if err != nil {
			proxyURL = &url.URL{
				Scheme: "http",
				Host:   cfg.Address,
			}
		}
		if cfg.Username != "" {
			if cfg.Password != "" {
				proxyURL.User = url.UserPassword(cfg.Username, cfg.Password)
			} else {
				proxyURL.User = url.User(cfg.Username)
			}
		}
		transport.Proxy = http.ProxyURL(proxyURL)
	case "socks5", "tor":
		addr := cfg.Address
		if addr == "" && cfg.Type == "tor" {
			addr = "127.0.0.1:9050"
		}
		if strings.HasPrefix(addr, "socks5://") {
			addr = strings.TrimPrefix(addr, "socks5://")
		}
		var auth *proxy.Auth
		if cfg.Username != "" {
			auth = &proxy.Auth{
				User:     cfg.Username,
				Password: cfg.Password,
			}
		}
		dialer, err := proxy.SOCKS5("tcp", addr, auth, proxy.Direct)
		if err == nil {
			if contextDialer, ok := dialer.(proxy.ContextDialer); ok {
				transport.DialContext = contextDialer.DialContext
			} else {
				transport.DialContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
					return dialer.Dial(network, addr)
				}
			}
		} else {
			return err
		}
	}
	http.DefaultTransport = transport
	return nil
}

// NewHTTPClient returns an http.Client whose transport injects browser-like
// headers from the global UA pool. It uses http.DefaultTransport as the base
// at request time, so any proxy applied via ApplyGlobalProxy is respected.
func NewHTTPClient(timeout time.Duration) *http.Client {
	if timeout <= 0 {
		timeout = DefaultHTTPTimeout
	}
	return &http.Client{
		Timeout:   timeout,
		Transport: NewHeaderTransport(GetGlobalPool(), nil),
	}
}

// SetDefaultHeaders sets the User-Agent on req from the global pool.
// The RoundTripper installed by NewHTTPClient also handles this, but modules
// that build requests manually can call SetDefaultHeaders before Do().
func SetDefaultHeaders(req *http.Request) {
	if req == nil {
		return
	}
	req.Header.Set("User-Agent", GetGlobalPool().GetUA())
}
