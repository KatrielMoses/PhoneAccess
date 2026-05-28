package finance

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"strings"

	"github.com/KatrielMoses/PhoneAccess/internal/core"
)

type batchService struct {
	Name      string
	URL       string
	Method    string
	Body      string
	Headers   map[string]string
	RespCheck func(body []byte, code int) (found bool, hint string)
}

func (m *Module) checkBatch(ctx context.Context, number *core.PhoneNumber) []ServiceHit {
	services := batchServices()
	results := make([]ServiceHit, 0, len(services))
	for _, svc := range services {
		hit := m.checkSingle(ctx, svc, number)
		results = append(results, hit)
	}
	return results
}

func (m *Module) checkSingle(ctx context.Context, svc batchService, number *core.PhoneNumber) ServiceHit {
	endpoint := replacePlaceholders(svc.URL, number)
	parsed, err := url.Parse(endpoint)
	if err != nil {
		return ServiceHit{Service: svc.Name, Found: false}
	}

	if m.batchLimiter != nil {
		if err := m.batchLimiter.Wait(ctx, parsed.Hostname()); err != nil {
			return ServiceHit{Service: svc.Name, Found: false}
		}
	}

	requestCtx, cancel := context.WithTimeout(ctx, core.DefaultHTTPTimeout)
	defer cancel()

	method := strings.ToUpper(svc.Method)
	if method == "" {
		method = http.MethodGet
	}

	var reqBody io.Reader
	if method == http.MethodPost && svc.Body != "" {
		reqBody = bytes.NewReader([]byte(replacePlaceholders(svc.Body, number)))
	}

	req, err := http.NewRequestWithContext(requestCtx, method, endpoint, reqBody)
	if err != nil {
		return ServiceHit{Service: svc.Name, Found: false}
	}
	core.SetDefaultHeaders(req)

	if method == http.MethodPost {
		if req.Header.Get("Content-Type") == "" {
			req.Header.Set("Content-Type", "application/json")
		}
	}
	req.Header.Set("Accept", "application/json, text/html, */*")

	for key, value := range svc.Headers {
		req.Header.Set(key, value)
	}

	resp, err := m.httpClient.Do(req)
	if err != nil {
		return ServiceHit{Service: svc.Name, Found: false}
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 500 {
		return ServiceHit{Service: svc.Name, Found: false}
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, maxBodySize))
	if err != nil {
		return ServiceHit{Service: svc.Name, Found: false}
	}

	if svc.RespCheck != nil {
		found, hint := svc.RespCheck(body, resp.StatusCode)
		return ServiceHit{Service: svc.Name, Found: found, NameHint: hint}
	}

	return ServiceHit{Service: svc.Name, Found: false}
}

func replacePlaceholders(template string, number *core.PhoneNumber) string {
	result := strings.ReplaceAll(template, "{E164}", url.QueryEscape(phoneE164(number)))
	result = strings.ReplaceAll(result, "{DIGITS}", phoneDigits(number))
	return result
}

func batchJSONCheck(body []byte, code int) (bool, string) {
	var data map[string]any
	if err := json.Unmarshal(body, &data); err != nil {
		return false, ""
	}
	for _, field := range []string{"registered", "exists", "found", "available", "taken", "success", "valid", "status", "associated"} {
		if val, ok := data[field]; ok {
			switch v := val.(type) {
			case bool:
				if v {
					return true, ""
				}
				return false, ""
			case float64:
				if v > 0 {
					return true, ""
				}
				return false, ""
			case string:
				lower := strings.ToLower(v)
				if lower == "true" || lower == "yes" || lower == "registered" || lower == "taken" || lower == "exists" {
					return true, ""
				}
				if lower == "false" || lower == "no" || lower == "unregistered" || lower == "available" || lower == "not_found" {
					return false, ""
				}
			}
		}
	}
	return false, ""
}

func batchServices() []batchService {
	return []batchService{
		{
			Name:   "PayPal",
			Method: http.MethodPost,
			URL:    "https://www.paypal.com/auth/validatecaptcha",
			Body:   "phone={DIGITS}",
			Headers: map[string]string{
				"Content-Type": "application/x-www-form-urlencoded",
			},
			RespCheck: func(body []byte, code int) (bool, string) {
				lower := strings.ToLower(string(body))
				if strings.Contains(lower, "already exists") || strings.Contains(lower, "already used") || strings.Contains(lower, "associated") {
					return true, ""
				}
				return false, ""
			},
		},
		{
			Name:   "CashApp",
			Method: http.MethodPost,
			URL:    "https://cash.app/api/v1/customer/request_phone_otp",
			Body:   `{"phone_number":"{DIGITS}"}`,
			RespCheck: func(body []byte, code int) (bool, string) {
				lower := strings.ToLower(string(body))
				if strings.Contains(lower, "existing") || strings.Contains(lower, "already") {
					return true, ""
				}
				return false, ""
			},
		},
		{
			Name:      "Revolut",
			Method:    http.MethodGet,
			URL:       "https://www.revolut.com/api/signup/check-phone?phone={E164}",
			RespCheck: batchJSONCheck,
		},
		{
			Name:      "Monzo",
			Method:    http.MethodGet,
			URL:       "https://api.monzo.com/registration/check-phone?phone={E164}",
			RespCheck: batchJSONCheck,
		},
		{
			Name:      "Wise",
			Method:    http.MethodGet,
			URL:       "https://wise.com/gateway/v2/profiles/check-phone?phone={E164}",
			RespCheck: batchJSONCheck,
		},
		{
			Name:   "N26",
			Method: http.MethodPost,
			URL:    "https://api.tech26.de/api/signup/check/phone",
			Body:   `{"phoneNumber":"{E164}"}`,
			RespCheck: func(body []byte, code int) (bool, string) {
				lower := strings.ToLower(string(body))
				if strings.Contains(lower, "exists") || strings.Contains(lower, "registered") || strings.Contains(lower, "taken") {
					return true, ""
				}
				return false, ""
			},
		},
		{
			Name:      "Chime",
			Method:    http.MethodGet,
			URL:       "https://www.chime.com/api/signup/check-phone?phone={DIGITS}",
			RespCheck: batchJSONCheck,
		},
		{
			Name:      "Robinhood",
			Method:    http.MethodGet,
			URL:       "https://api.robinhood.com/midlands/phone_number/{DIGITS}/exists/",
			RespCheck: batchJSONCheck,
		},
		{
			Name:   "Stripe",
			Method: http.MethodPost,
			URL:    "https://api.stripe.com/v1/phone/check",
			Body:   "phone={DIGITS}",
			Headers: map[string]string{
				"Content-Type": "application/x-www-form-urlencoded",
			},
			RespCheck: batchJSONCheck,
		},
		{
			Name:      "Square",
			Method:    http.MethodGet,
			URL:       "https://squareup.com/register/api/check-phone?phone={DIGITS}",
			RespCheck: batchJSONCheck,
		},
		{
			Name:      "Klarna",
			Method:    http.MethodGet,
			URL:       "https://api.klarna.com/checkout/v3/check-phone?phone={DIGITS}",
			RespCheck: batchJSONCheck,
		},
		{
			Name:      "Affirm",
			Method:    http.MethodGet,
			URL:       "https://www.affirm.com/api/v1/check-phone?phone={DIGITS}",
			RespCheck: batchJSONCheck,
		},
		{
			Name:      "Afterpay",
			Method:    http.MethodGet,
			URL:       "https://api.afterpay.com/v2/check-phone?phone={DIGITS}",
			RespCheck: batchJSONCheck,
		},
		{
			Name:      "Gemini",
			Method:    http.MethodGet,
			URL:       "https://api.gemini.com/v1/check-phone?phone={DIGITS}",
			RespCheck: batchJSONCheck,
		},
		{
			Name:      "Nubank",
			Method:    http.MethodGet,
			URL:       "https://api.nubank.com.br/api/check-phone?phone={DIGITS}",
			RespCheck: batchJSONCheck,
		},
		{
			Name:      "Flutterwave",
			Method:    http.MethodGet,
			URL:       "https://api.flutterwave.com/v3/check-phone?phone={DIGITS}",
			RespCheck: batchJSONCheck,
		},
	}
}