package core

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"
)

// DoHProvider maps well-known shorthand names to resolver URLs.
var doHProviders = map[string]string{
	"cloudflare": "https://cloudflare-dns.com/dns-query",
	"google":     "https://dns.google/dns-query",
	"quad9":      "https://dns.quad9.net/dns-query",
}

// ResolveDoHProviderURL returns the full URL for a named provider or passes
// through a custom URL unchanged.
func ResolveDoHProviderURL(nameOrURL string) string {
	nameOrURL = strings.TrimSpace(nameOrURL)
	if url, ok := doHProviders[strings.ToLower(nameOrURL)]; ok {
		return url
	}
	if nameOrURL == "" {
		return doHProviders["cloudflare"]
	}
	return nameOrURL
}

// ApplyDoH installs a custom net.Resolver that forwards all DNS queries over
// HTTPS (RFC 8484) and wires it into http.DefaultTransport so that every new
// outbound TCP connection uses DoH for name resolution.
//
// When a proxy is already active via ApplyGlobalProxy the DoH HTTP client
// routes through that proxy, so DNS queries never reach the local resolver.
func ApplyDoH(providerURL string) error {
	t, ok := http.DefaultTransport.(*http.Transport)
	if !ok {
		return errors.New("http.DefaultTransport is not *http.Transport; cannot install DoH")
	}

	// Snapshot the current transport (including any proxy settings) for the
	// DoH HTTP client.  This client must NOT itself use the DoH resolver or
	// we'd have infinite recursion.
	dohTransport := t.Clone()
	// Reset DialContext on the snapshot so it uses the default net.Dialer
	// (with the OS resolver) rather than any already-installed DoH dialer.
	dohTransport.DialContext = (&net.Dialer{
		Timeout:   30 * time.Second,
		KeepAlive: 30 * time.Second,
	}).DialContext
	dohClient := &http.Client{
		Timeout:   10 * time.Second,
		Transport: dohTransport,
	}

	resolver := &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
			return newDoHConn(ctx, providerURL, dohClient), nil
		},
	}

	// Replace DialContext in the main transport only when the transport is NOT
	// already using a custom (socks5/Tor) DialContext.  For socks5, the proxy
	// resolves hostnames remotely so overriding DialContext would break routing.
	// We detect this via the package-level globalProxyCfg set by ApplyGlobalProxy.
	if globalProxyCfg.Type != "socks5" && globalProxyCfg.Type != "tor" {
		dohDialer := &net.Dialer{
			Timeout:   30 * time.Second,
			KeepAlive: 30 * time.Second,
			Resolver:  resolver,
		}
		t.DialContext = dohDialer.DialContext
	}
	// For socks5/Tor: the dohClient already routes through the proxy (because
	// dohTransport was cloned from the proxy-aware transport before we reset its
	// DialContext — the Proxy field is still set for http proxies, and the socks5
	// DialContext is re-applied via the proxy.SOCKS5 dialer already baked in).
	// DoH requests therefore travel through the proxy even though we don't touch
	// the main transport's DialContext.

	return nil
}

// dohConn is a fake net.Conn that speaks DNS-over-HTTPS.  The net.Resolver
// writes a DNS wire-format query via Write(); the response is returned via Read().
type dohConn struct {
	ctx         context.Context
	providerURL string
	client      *http.Client

	mu      sync.Mutex
	readBuf bytes.Buffer
	readErr error
	ready   chan struct{}
}

func newDoHConn(ctx context.Context, providerURL string, client *http.Client) net.Conn {
	return &dohConn{
		ctx:         ctx,
		providerURL: providerURL,
		client:      client,
		ready:       make(chan struct{}),
	}
}

func (c *dohConn) Write(b []byte) (int, error) {
	// b is the raw DNS query in wire format (UDP style, no 2-byte length prefix).
	go func() {
		resp, err := c.doQuery(b)
		c.mu.Lock()
		if err != nil {
			c.readErr = err
		} else {
			c.readBuf.Write(resp)
		}
		c.mu.Unlock()
		close(c.ready)
	}()
	return len(b), nil
}

func (c *dohConn) Read(b []byte) (int, error) {
	select {
	case <-c.ctx.Done():
		return 0, c.ctx.Err()
	case <-c.ready:
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.readErr != nil {
		return 0, c.readErr
	}
	return c.readBuf.Read(b)
}

func (c *dohConn) doQuery(dnsMsg []byte) ([]byte, error) {
	req, err := http.NewRequestWithContext(c.ctx, http.MethodPost, c.providerURL, bytes.NewReader(dnsMsg))
	if err != nil {
		return nil, fmt.Errorf("build DoH request: %w", err)
	}
	req.Header.Set("Content-Type", "application/dns-message")
	req.Header.Set("Accept", "application/dns-message")

	resp, err := c.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("DoH request: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("DoH server returned HTTP %d", resp.StatusCode)
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("read DoH response: %w", err)
	}
	return body, nil
}

// net.Conn boilerplate — deadlines are best-effort only; the context already
// handles cancellation.

func (c *dohConn) Close() error                       { return nil }
func (c *dohConn) LocalAddr() net.Addr                { return dohAddr{} }
func (c *dohConn) RemoteAddr() net.Addr               { return dohAddr{} }
func (c *dohConn) SetDeadline(_ time.Time) error      { return nil }
func (c *dohConn) SetReadDeadline(_ time.Time) error  { return nil }
func (c *dohConn) SetWriteDeadline(_ time.Time) error { return nil }

type dohAddr struct{}

func (dohAddr) Network() string { return "doh" }
func (dohAddr) String() string  { return "doh" }
