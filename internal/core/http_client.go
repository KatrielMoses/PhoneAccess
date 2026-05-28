package core

import (
	"net/http"
	"time"
)

const DefaultHTTPTimeout = 15 * time.Second
const UserAgent = "PhoneAccess/0.1.0 (+https://github.com/KatrielMoses/PhoneAccess)"

func NewHTTPClient(timeout time.Duration) *http.Client {
	if timeout <= 0 {
		timeout = DefaultHTTPTimeout
	}
	return &http.Client{Timeout: timeout}
}

func SetDefaultHeaders(req *http.Request) {
	if req == nil {
		return
	}
	req.Header.Set("User-Agent", UserAgent)
}
