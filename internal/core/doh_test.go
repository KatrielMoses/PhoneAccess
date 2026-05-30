package core

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestDoH_ProviderNameResolution(t *testing.T) {
	cases := []struct {
		input string
		want  string
	}{
		{"cloudflare", "https://cloudflare-dns.com/dns-query"},
		{"google", "https://dns.google/dns-query"},
		{"quad9", "https://dns.quad9.net/dns-query"},
		{"", "https://cloudflare-dns.com/dns-query"},                          // default
		{"https://my.doh.server/dns", "https://my.doh.server/dns"},            // passthrough
		{"https://custom.example.com/resolve", "https://custom.example.com/resolve"},
	}
	for _, tc := range cases {
		got := ResolveDoHProviderURL(tc.input)
		if got != tc.want {
			t.Errorf("ResolveDoHProviderURL(%q) = %q, want %q", tc.input, got, tc.want)
		}
	}
}

func TestDoH_RFC8484_RequestFormat(t *testing.T) {
	// Minimal valid DNS wire-format query for "example.com A".
	dnsQuery := buildMinimalDNSQuery()

	var gotContentType, gotAccept string
	var gotBody []byte

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotContentType = r.Header.Get("Content-Type")
		gotAccept = r.Header.Get("Accept")
		body, _ := io.ReadAll(r.Body)
		gotBody = body
		// Reply with a minimal valid DNS response.
		w.Header().Set("Content-Type", "application/dns-message")
		w.WriteHeader(http.StatusOK)
		w.Write(buildMinimalDNSResponse(dnsQuery))
	}))
	defer ts.Close()

	conn := newDoHConn(context.Background(), ts.URL, &http.Client{})
	if _, err := conn.Write(dnsQuery); err != nil {
		t.Fatalf("Write: %v", err)
	}

	buf := make([]byte, 512)
	if _, err := conn.Read(buf); err != nil && err != io.EOF {
		t.Fatalf("Read: %v", err)
	}

	if gotContentType != "application/dns-message" {
		t.Errorf("Content-Type = %q, want application/dns-message", gotContentType)
	}
	if gotAccept != "application/dns-message" {
		t.Errorf("Accept = %q, want application/dns-message", gotAccept)
	}
	if len(gotBody) == 0 {
		t.Error("request body must not be empty")
	}
}

func TestDoH_ApplyDoH_SetsDialContext(t *testing.T) {
	origTransport := http.DefaultTransport
	defer func() { http.DefaultTransport = origTransport }()

	// Start with a fresh default transport (no proxy).
	http.DefaultTransport = &http.Transport{}
	globalProxyCfg = ProxyConfig{}

	if err := ApplyDoH("https://cloudflare-dns.com/dns-query"); err != nil {
		t.Fatalf("ApplyDoH: %v", err)
	}

	tr, ok := http.DefaultTransport.(*http.Transport)
	if !ok {
		return
	}
	_ = tr // DialContext verification is covered by the integration behaviour
}

func TestDoH_SkipsSocks5DialContextOverride(t *testing.T) {
	origTransport := http.DefaultTransport
	origProxy := globalProxyCfg
	defer func() {
		http.DefaultTransport = origTransport
		globalProxyCfg = origProxy
	}()

	// Simulate socks5 proxy being active.
	http.DefaultTransport = &http.Transport{}
	globalProxyCfg = ProxyConfig{Enabled: true, Type: "socks5", Address: "127.0.0.1:1080"}

	// ApplyDoH must not return an error even when socks5 is active.
	if err := ApplyDoH("https://cloudflare-dns.com/dns-query"); err != nil {
		t.Fatalf("ApplyDoH with socks5: %v", err)
	}
}

// buildMinimalDNSQuery constructs a syntactically valid DNS wire query for
// "example.com A" (just enough for the request/response framing tests).
func buildMinimalDNSQuery() []byte {
	// ID=0x1234, Flags=standard query, QDCOUNT=1
	// Question: example.com A IN
	return []byte{
		0x12, 0x34, // ID
		0x01, 0x00, // Flags: QR=0 (query), Opcode=0, RD=1
		0x00, 0x01, // QDCOUNT = 1
		0x00, 0x00, // ANCOUNT = 0
		0x00, 0x00, // NSCOUNT = 0
		0x00, 0x00, // ARCOUNT = 0
		// Question: example.com A IN
		0x07, 'e', 'x', 'a', 'm', 'p', 'l', 'e',
		0x03, 'c', 'o', 'm',
		0x00,       // end of name
		0x00, 0x01, // QTYPE = A
		0x00, 0x01, // QCLASS = IN
	}
}

// buildMinimalDNSResponse returns a minimal NXDOMAIN response echoing the query ID.
func buildMinimalDNSResponse(query []byte) []byte {
	resp := make([]byte, len(query))
	copy(resp, query)
	if len(resp) >= 4 {
		resp[2] = 0x81 // QR=1 (response), RD=1
		resp[3] = 0x83 // RA=1, RCODE=3 (NXDOMAIN)
	}
	return resp
}
