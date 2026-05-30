package core

import (
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"
)

// Mock SOCKS5 Server
func startMockSOCKS5Server(t *testing.T) string {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go func() {
		for {
			conn, err := l.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				buf := make([]byte, 262)
				_, err := io.ReadFull(c, buf[:2])
				if err != nil {
					return
				}
				if buf[0] != 0x05 {
					return
				}

				numMethods := int(buf[1])
				io.ReadFull(c, buf[:numMethods])

				// send auth method (no auth)
				c.Write([]byte{0x05, 0x00})

				// read request
				_, err = io.ReadFull(c, buf[:4])
				if err != nil {
					return
				}
				if buf[1] != 0x01 {
					return
				}

				// address type
				switch buf[3] {
				case 0x01: // ipv4
					io.ReadFull(c, buf[:6]) // 4 ip + 2 port
				case 0x03: // domain name
					io.ReadFull(c, buf[:1])
					domainLen := int(buf[0])
					io.ReadFull(c, buf[:domainLen+2])
				case 0x04: // ipv6
					io.ReadFull(c, buf[:18])
				}

				// send success
				c.Write([]byte{0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0})

				// now acts as an http server
				// read http request
				reqBuf := make([]byte, 1024)
				c.Read(reqBuf)

				// send http response
				c.Write([]byte("HTTP/1.1 200 OK\r\nContent-Length: 11\r\n\r\nHello SOCKS"))
			}(conn)
		}
	}()
	return l.Addr().String()
}

func TestHTTPClient_ProxySOCKS5(t *testing.T) {
	origTransport := http.DefaultTransport
	defer func() { http.DefaultTransport = origTransport }()

	addr := startMockSOCKS5Server(t)
	cfg := ProxyConfig{
		Enabled: true,
		Type:    "socks5",
		Address: addr,
	}
	if err := ApplyGlobalProxy(cfg); err != nil {
		t.Fatal(err)
	}

	client := NewHTTPClient(2 * time.Second)
	resp, err := client.Get("http://example.com")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	if string(body) != "Hello SOCKS" {
		t.Errorf("Expected Hello SOCKS, got %s", body)
	}
}

func TestHTTPClient_ProxyHTTP(t *testing.T) {
	origTransport := http.DefaultTransport
	defer func() { http.DefaultTransport = origTransport }()

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "Hello HTTP Proxy")
	}))
	defer ts.Close()

	u, _ := url.Parse(ts.URL)
	cfg := ProxyConfig{
		Enabled: true,
		Type:    "http",
		Address: u.Host,
	}
	if err := ApplyGlobalProxy(cfg); err != nil {
		t.Fatal(err)
	}

	client := NewHTTPClient(2 * time.Second)
	resp, err := client.Get("http://example.com")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	if string(body) != "Hello HTTP Proxy" {
		t.Errorf("Expected Hello HTTP Proxy, got %s", body)
	}
}

func TestHTTPClient_TorShorthand(t *testing.T) {
	origTransport := http.DefaultTransport
	defer func() { http.DefaultTransport = origTransport }()

	cfg := ProxyConfig{
		Enabled: true,
		Type:    "tor",
	}
	// Verify it builds dialer correctly
	if err := ApplyGlobalProxy(cfg); err != nil {
		t.Fatal(err)
	}
}

func TestHTTPClient_NoProxy(t *testing.T) {
	origTransport := http.DefaultTransport
	defer func() { http.DefaultTransport = origTransport }()

	cfg := ProxyConfig{Enabled: false}
	ApplyGlobalProxy(cfg)

	client := NewHTTPClient(2 * time.Second)
	// NewHTTPClient always installs a headerTransport; transport must not be nil.
	if client.Transport == nil {
		t.Error("Expected non-nil transport (headerTransport), got nil")
	}
}

func TestHTTPClient_DNSLeak(t *testing.T) {
	origTransport := http.DefaultTransport
	defer func() { http.DefaultTransport = origTransport }()

	// Start a SOCKS5 server that tracks if it receives a domain name (type 0x03)
	receivedDomain := false
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go func() {
		defer l.Close()
		conn, err := l.Accept()
		if err != nil {
			return
		}
		defer conn.Close()

		buf := make([]byte, 262)
		io.ReadFull(conn, buf[:2])
		io.ReadFull(conn, buf[:int(buf[1])])
		conn.Write([]byte{0x05, 0x00})
		io.ReadFull(conn, buf[:4])
		
		if buf[3] == 0x03 {
			receivedDomain = true
		}
		
		switch buf[3] {
		case 0x01: io.ReadFull(conn, buf[:6])
		case 0x03:
			io.ReadFull(conn, buf[:1])
			io.ReadFull(conn, buf[:int(buf[0])+2])
		case 0x04: io.ReadFull(conn, buf[:18])
		}
		conn.Write([]byte{0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
		conn.Read(make([]byte, 1024))
		conn.Write([]byte("HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n"))
	}()

	cfg := ProxyConfig{
		Enabled: true,
		Type:    "socks5",
		Address: l.Addr().String(),
	}
	ApplyGlobalProxy(cfg)

	client := NewHTTPClient(2 * time.Second)
	// We use a non-existent fake domain to ensure it doesn't resolve locally
	resp, err := client.Get("http://fake.domain.that.doesnt.exist.internal")
	if err == nil {
		resp.Body.Close()
	}
	
	if !receivedDomain {
		t.Error("Expected SOCKS5 server to receive domain name directly (verifying DNS leak protection), but it did not")
	}
}

func BenchmarkHTTPClientNoProxy(b *testing.B) {
	for i := 0; i < b.N; i++ {
		_ = NewHTTPClient(10 * time.Second)
	}
}

func BenchmarkHTTPClientWithProxy(b *testing.B) {
	origTransport := http.DefaultTransport
	defer func() { http.DefaultTransport = origTransport }()

	cfg := ProxyConfig{
		Enabled: true,
		Type:    "http",
		Address: "127.0.0.1:8080",
	}
	ApplyGlobalProxy(cfg)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = NewHTTPClient(10 * time.Second)
	}
}
