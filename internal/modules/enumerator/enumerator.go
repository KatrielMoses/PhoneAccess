package enumerator

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/KatrielMoses/PhoneAccess/internal/core"
)

const (
	moduleName  = "enumerator"
	rateDelay   = 2 * time.Second
	maxBodySize = 2 * 1024 * 1024
)

var errMissingAPIKey = fmt.Errorf("enumerator requires no API keys")

type HTTPClient interface {
	Do(req *http.Request) (*http.Response, error)
}

type ServiceCategory string

const (
	CatSocial    ServiceCategory = "social"
	CatMessaging ServiceCategory = "messaging"
	CatFinance   ServiceCategory = "finance"
	CatEcommerce ServiceCategory = "ecommerce"
	CatTravel    ServiceCategory = "travel"
	CatFood      ServiceCategory = "food"
	CatDating    ServiceCategory = "dating"
	CatWork      ServiceCategory = "work"
	CatGaming    ServiceCategory = "gaming"
	CatCrypto    ServiceCategory = "crypto"
	CatGov       ServiceCategory = "government"
	CatUtility   ServiceCategory = "utility"
)

type Service struct {
	Name      string
	Category  ServiceCategory
	URL       string
	Method    string
	Body      string
	Headers   map[string]string
	RespCheck func(body []byte, statusCode int) (found bool, hint string)
}

type SourceResult struct {
	Service   string
	Category  ServiceCategory
	Found     bool
	Hint      string
	Available bool
	Error     string
}

type EnumeratorResult struct {
	Found               int
	Checked             int
	CategoriesHit       int
	TotalServices       int
	Hits                []ServiceHit
	SourceStatuses      map[string]string
	ByCategory          map[ServiceCategory]int
	DiscoveredNames     []string
	DiscoveredUsernames []string
}

type ServiceHit struct {
	Service  string
	Category ServiceCategory
	Hint     string
}

type Module struct {
	httpClient HTTPClient
	limiter    *core.RateLimiter
	services   []Service
}

type Option func(*Module)

func New(opts ...Option) *Module {
	m := &Module{
		httpClient: core.NewHTTPClient(core.DefaultHTTPTimeout),
		limiter:    core.NewRateLimiter(rateDelay),
		services:   allServices(),
	}
	for _, opt := range opts {
		opt(m)
	}
	return m
}

func WithHTTPClient(client HTTPClient) Option {
	return func(m *Module) {
		if client != nil {
			m.httpClient = client
		}
	}
}

func WithRateLimiter(limiter *core.RateLimiter) Option {
	return func(m *Module) {
		m.limiter = limiter
	}
}

func WithServices(services []Service) Option {
	return func(m *Module) {
		if len(services) > 0 {
			m.services = services
		}
	}
}

func (m *Module) Name() string {
	return moduleName
}

func (m *Module) Description() string {
	return "Silent phone registration enumeration across 200+ services without triggering SMS or notifications."
}

func (m *Module) RequiresAPIKey() bool {
	return false
}

func (m *Module) Tier() core.ModuleTier {
	return core.TierActive
}

func (m *Module) DryRun(ctx context.Context, number *core.PhoneNumber) error {
	select {
	case <-ctx.Done():
		return ctx.Err()
	default:
		return nil
	}
}

func (m *Module) RunPassive(ctx context.Context, number *core.PhoneNumber) (*core.ModuleResult, error) {
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	default:
	}

	return &core.ModuleResult{
		ModuleName: m.Name(),
		Status:     core.ModuleStatusSkipped,
		Findings: map[string]string{
			"skipped": "true",
			"note":    "passive mode disables active service enumeration",
		},
		Evidence: []string{"Passive mode enabled; enumerator module made no network requests."},
	}, nil
}

func (m *Module) Run(ctx context.Context, number *core.PhoneNumber) (*core.ModuleResult, error) {
	results := make([]SourceResult, 0, len(m.services))
	for _, service := range m.services {
		results = append(results, m.queryService(ctx, service, number))
	}

	aggregated := aggregate(results)
	return &core.ModuleResult{
		ModuleName: m.Name(),
		Status:     core.ModuleStatusSuccess,
		Findings:   findingsFromEnumeratorResult(aggregated),
		Data:       aggregated,
		Evidence:   evidenceFromStatuses(aggregated.SourceStatuses),
	}, nil
}

func (m *Module) queryService(ctx context.Context, service Service, number *core.PhoneNumber) SourceResult {
	result := SourceResult{
		Service:  service.Name,
		Category: service.Category,
	}

	serviceURL := replacePhonePlaceholder(service.URL, number)
	parsed, err := url.Parse(serviceURL)
	if err != nil {
		result.Error = "invalid service URL"
		return result
	}

	if m.limiter != nil {
		if err := m.limiter.Wait(ctx, parsed.Hostname()); err != nil {
			result.Error = err.Error()
			return result
		}
	}

	requestCtx, cancel := context.WithTimeout(ctx, core.DefaultHTTPTimeout)
	defer cancel()

	method := strings.ToUpper(service.Method)
	if method == "" {
		method = http.MethodGet
	}

	var reqBody io.Reader
	if method == http.MethodPost && service.Body != "" {
		reqBody = bytes.NewReader([]byte(replacePhonePlaceholder(service.Body, number)))
	}

	req, err := http.NewRequestWithContext(requestCtx, method, serviceURL, reqBody)
	if err != nil {
		result.Error = err.Error()
		return result
	}
	core.SetDefaultHeaders(req)

	if method == http.MethodPost {
		if req.Header.Get("Content-Type") == "" {
			req.Header.Set("Content-Type", "application/json")
		}
	}
	req.Header.Set("Accept", "application/json, text/html, */*")

	for key, value := range service.Headers {
		req.Header.Set(key, value)
	}

	resp, err := m.httpClient.Do(req)
	if err != nil {
		result.Error = err.Error()
		return result
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound || resp.StatusCode == http.StatusGone {
		result.Available = true
		return result
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, maxBodySize))
	if err != nil {
		result.Error = err.Error()
		return result
	}

	if service.RespCheck != nil {
		found, hint := service.RespCheck(body, resp.StatusCode)
		result.Found = found
		result.Hint = hint
	}

	result.Available = resp.StatusCode >= 200 && resp.StatusCode < 500
	return result
}

func aggregate(results []SourceResult) EnumeratorResult {
	out := EnumeratorResult{
		Hits:           make([]ServiceHit, 0),
		SourceStatuses: map[string]string{},
		ByCategory:     map[ServiceCategory]int{},
	}
	seenNames := map[string]bool{}
	seenUsernames := map[string]bool{}

	for _, result := range results {
		out.Checked++
		out.TotalServices = len(results)
		if !result.Available {
			status := "unavailable"
			if strings.TrimSpace(result.Error) != "" {
				status += ": " + result.Error
			}
			out.SourceStatuses[result.Service] = status
			continue
		}

		if result.Found {
			out.Found++
			out.ByCategory[result.Category]++
			out.SourceStatuses[result.Service] = "registered"
			out.Hits = append(out.Hits, ServiceHit{
				Service:  result.Service,
				Category: result.Category,
				Hint:     result.Hint,
			})
			if result.Hint != "" && !seenNames[result.Hint] {
				seenNames[result.Hint] = true
				out.DiscoveredNames = append(out.DiscoveredNames, result.Hint)
			}
		} else {
			out.SourceStatuses[result.Service] = "not found"
		}
	}

	for _, hit := range out.Hits {
		if hit.Hint != "" && strings.Contains(hit.Hint, "@") && !seenUsernames[hit.Hint] {
			seenUsernames[hit.Hint] = true
			out.DiscoveredUsernames = append(out.DiscoveredUsernames, hit.Hint)
		}
	}

	categories := countCategories(out.ByCategory)
	if categories > 0 {
		out.CategoriesHit = categories
	}

	sort.SliceStable(out.Hits, func(i, j int) bool {
		if out.Hits[i].Category == out.Hits[j].Category {
			return out.Hits[i].Service < out.Hits[j].Service
		}
		return out.Hits[i].Category < out.Hits[j].Category
	})

	sort.Strings(out.DiscoveredNames)
	sort.Strings(out.DiscoveredUsernames)
	return out
}

func countCategories(byCat map[ServiceCategory]int) int {
	count := 0
	for _, hits := range byCat {
		if hits > 0 {
			count++
		}
	}
	return count
}

func findingsFromEnumeratorResult(result EnumeratorResult) map[string]string {
	hits := make([]string, 0, len(result.Hits)+len(result.ByCategory))
	var currentCat ServiceCategory
	for _, hit := range result.Hits {
		if hit.Category != currentCat {
			hits = append(hits, "["+string(hit.Category)+"]")
			currentCat = hit.Category
		}
		line := hit.Service
		if hit.Hint != "" {
			line += " (" + hit.Hint + ")"
		}
		hits = append(hits, line)
	}

	categoryBreakdown := make([]string, 0)
	catOrder := []ServiceCategory{CatSocial, CatMessaging, CatFinance, CatEcommerce, CatTravel, CatFood, CatDating, CatWork, CatGaming, CatCrypto, CatGov, CatUtility}
	for _, cat := range catOrder {
		if n := result.ByCategory[cat]; n > 0 {
			categoryBreakdown = append(categoryBreakdown, string(cat)+":"+strconv.Itoa(n))
		}
	}

	return map[string]string{
		"found":                strconv.FormatBool(result.Found > 0),
		"hit_count":            strconv.Itoa(result.Found),
		"checked":              strconv.Itoa(result.Checked),
		"total_services":       strconv.Itoa(result.TotalServices),
		"categories_hit":       strconv.Itoa(result.CategoriesHit),
		"category_breakdown":   strings.Join(categoryBreakdown, ", "),
		"hits":                 strings.Join(hits, "\n"),
		"discovered_names":     strings.Join(result.DiscoveredNames, ", "),
		"discovered_usernames": strings.Join(result.DiscoveredUsernames, ", "),
		"source_statuses":      joinStatuses(result.SourceStatuses),
	}
}

func evidenceFromStatuses(statuses map[string]string) []string {
	if len(statuses) == 0 {
		return nil
	}
	names := make([]string, 0, len(statuses))
	for name := range statuses {
		names = append(names, name)
	}
	sort.Strings(names)
	evidence := make([]string, 0, len(names))
	for _, name := range names {
		evidence = append(evidence, name+": "+statuses[name])
	}
	return evidence
}

func joinStatuses(statuses map[string]string) string {
	names := make([]string, 0, len(statuses))
	for name := range statuses {
		names = append(names, name)
	}
	sort.Strings(names)
	parts := make([]string, 0, len(names))
	for _, name := range names {
		parts = append(parts, name+"="+statuses[name])
	}
	return strings.Join(parts, "; ")
}

func replacePhonePlaceholder(template string, number *core.PhoneNumber) string {
	digits := ""
	e164 := ""
	national := ""
	if number != nil {
		e164 = number.E164
		national = number.NationalNumber
		for _, r := range number.E164 {
			if r >= '0' && r <= '9' {
				digits += string(r)
			}
		}
	}
	result := strings.ReplaceAll(template, "{E164}", url.QueryEscape(e164))
	result = strings.ReplaceAll(result, "{NATIONAL}", url.QueryEscape(national))
	result = strings.ReplaceAll(result, "{DIGITS}", url.QueryEscape(digits))
	return result
}

func defaultJSONCheck(body []byte, code int) (bool, string) {
	var data map[string]any
	if err := json.Unmarshal(body, &data); err != nil {
		return false, ""
	}
	for _, field := range []string{"registered", "exists", "found", "available", "taken", "success", "valid", "status"} {
		if val, ok := data[field]; ok {
			switch v := val.(type) {
			case bool:
				if v {
					return true, ""
				}
			case float64:
				if v > 0 {
					return true, ""
				}
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

func allServices() []Service {
	return []Service{

		// ── SOCIAL MEDIA ──

		{
			Name: "Instagram", Category: CatSocial,
			Method: "POST",
			URL:    "https://www.instagram.com/api/v1/web/accounts/web_create_ajax/attempt/",
			Body:   `{"phone_id":"placeholder","phone_number":"{DIGITS}","gdpr_s":""}`,
			Headers: map[string]string{
				"X-CSRFToken":      "missing",
				"X-Instagram-AJAX": "1",
				"X-Requested-With": "XMLHttpRequest",
				"Referer":          "https://www.instagram.com/",
			},
			RespCheck: func(body []byte, code int) (bool, string) {
				lower := strings.ToLower(string(body))
				if strings.Contains(lower, "existing account") || strings.Contains(lower, "already taken") || strings.Contains(lower, "has an account") || strings.Contains(lower, "already registered") {
					return true, ""
				}
				if strings.Contains(lower, "sent") || strings.Contains(lower, "code") || strings.Contains(lower, "verify") {
					return true, ""
				}
				return false, ""
			},
		},

		{
			Name: "Snapchat", Category: CatSocial,
			Method: "POST",
			URL:    "https://app.snapchat.com/loq/phone_verify",
			Body:   `{"phone_number":"{DIGITS}","action":"updatePhoneNumber","country_code":"US"}`,
			RespCheck: func(body []byte, code int) (bool, string) {
				lower := strings.ToLower(string(body))
				if strings.Contains(lower, "existing") || strings.Contains(lower, "already") || strings.Contains(lower, "taken") {
					return true, ""
				}
				if strings.Contains(lower, "error") || strings.Contains(lower, "invalid") {
					return false, ""
				}
				return false, ""
			},
		},

		{
			Name: "TikTok", Category: CatSocial,
			Method: "GET",
			URL:    "https://www.tiktok.com/passport/email/check_phone/?phone={DIGITS}",
			RespCheck: func(body []byte, code int) (bool, string) {
				lower := strings.ToLower(string(body))
				if strings.Contains(lower, "has account") || strings.Contains(lower, "already registered") || strings.Contains(lower, "\"registered\":true") {
					return true, ""
				}
				if strings.Contains(lower, "not registered") || strings.Contains(lower, "\"registered\":false") {
					return false, ""
				}
				return false, ""
			},
		},

		{
			Name: "Twitter/X", Category: CatSocial,
			Method: "POST",
			URL:    "https://api.twitter.com/1.1/users/phone_number_available.json",
			Body:   "phone_number={DIGITS}",
			Headers: map[string]string{
				"Content-Type":  "application/x-www-form-urlencoded",
				"Authorization": "Bearer AAAAAAAAAAAAAAAAAAAAANRILgAAAAAAnNwIzUejRCOuH5E6I8xnZz4puTs%3D1Zv7ttfk8LF81IUq16cHjhLTvJu4FA33AGWWjCpTnA",
			},
			RespCheck: func(body []byte, code int) (bool, string) {
				lower := strings.ToLower(string(body))
				if strings.Contains(lower, "\"valid\":false") {
					return true, ""
				}
				return false, ""
			},
		},

		{
			Name: "Pinterest", Category: CatSocial,
			Method:    "GET",
			URL:       "https://www.pinterest.com/resource/PhoneExistsResource/get/?data={\"options\":{\"phone\":\"{DIGITS}\"}}",
			RespCheck: defaultJSONCheck,
		},

		{
			Name: "Tumblr", Category: CatSocial,
			Method:  "POST",
			URL:     "https://www.tumblr.com/svc/account/register",
			Body:    "{\"phone\":\"{DIGITS}\"}",
			Headers: map[string]string{"Content-Type": "application/json"},
			RespCheck: func(body []byte, code int) (bool, string) {
				lower := strings.ToLower(string(body))
				if strings.Contains(lower, "already in use") || strings.Contains(lower, "existing") {
					return true, ""
				}
				return false, ""
			},
		},

		{
			Name: "Reddit", Category: CatSocial,
			Method:  "POST",
			URL:     "https://www.reddit.com/api/v1/send_phone_otp_register",
			Body:    "phone_number={DIGITS}",
			Headers: map[string]string{"Content-Type": "application/x-www-form-urlencoded"},
			RespCheck: func(body []byte, code int) (bool, string) {
				lower := strings.ToLower(string(body))
				if strings.Contains(lower, "already registered") || strings.Contains(lower, "phone number already") {
					return true, ""
				}
				return false, ""
			},
		},

		{
			Name: "Quora", Category: CatSocial,
			Method: "POST",
			URL:    "https://www.quora.com/graphql/gql_para_POST?q=PlatformRegistrationValidationQuery",
			Body:   "{\"variables\":{\"value\":\"{DIGITS}\"},\"extensions\":{\"hash\":\"\"}}",
			RespCheck: func(body []byte, code int) (bool, string) {
				if strings.Contains(strings.ToLower(string(body)), "already") {
					return true, ""
				}
				return false, ""
			},
		},

		{
			Name: "Flickr", Category: CatSocial,
			Method:    "POST",
			URL:       "https://identity.flickr.com/v2/register/check",
			Body:      "phone={DIGITS}",
			Headers:   map[string]string{"Content-Type": "application/x-www-form-urlencoded"},
			RespCheck: defaultJSONCheck,
		},

		{
			Name: "VK", Category: CatSocial,
			Method: "GET",
			URL:    "https://vk.com/al_login.php?act=check_phone&phone={DIGITS}",
			RespCheck: func(body []byte, code int) (bool, string) {
				return strings.Contains(strings.ToLower(string(body)), "true"), ""
			},
		},

		{
			Name: "Odnoklassniki", Category: CatSocial,
			Method:    "POST",
			URL:       "https://ok.ru/dk?cmd=AnonymRegistrationCheckPhone&st.cmd=anonymRegistrationMain",
			Body:      "phone={DIGITS}",
			Headers:   map[string]string{"Content-Type": "application/x-www-form-urlencoded"},
			RespCheck: defaultJSONCheck,
		},

		{
			Name: "Weibo", Category: CatSocial,
			Method: "GET",
			URL:    "https://passport.weibo.cn/signin/checkphone?phone={DIGITS}",
			RespCheck: func(body []byte, code int) (bool, string) {
				lower := strings.ToLower(string(body))
				return strings.Contains(lower, "true") || strings.Contains(lower, "registered"), ""
			},
		},

		{
			Name: "Douyin", Category: CatSocial,
			Method:    "POST",
			URL:       "https://lf.snssdk.com/passport/mobile/check_is_register/?mobile={DIGITS}",
			RespCheck: defaultJSONCheck,
		},

		// ── MESSAGING ──

		{
			Name: "Telegram", Category: CatMessaging,
			Method: "GET",
			URL:    "https://telegram.org/support?setln=en",
			RespCheck: func(body []byte, code int) (bool, string) {
				return false, ""
			},
		},

		{
			Name: "WhatsApp", Category: CatMessaging,
			Method: "GET",
			URL:    "https://wa.me/{DIGITS}",
			RespCheck: func(body []byte, code int) (bool, string) {
				return code == 200 && !strings.Contains(strings.ToLower(string(body)), "phone number"), ""
			},
		},

		{
			Name: "Signal", Category: CatMessaging,
			Method: "PUT",
			URL:    "https://textsecure-service.whispersystems.org/v1/accounts/account/{DIGITS}",
			RespCheck: func(body []byte, code int) (bool, string) {
				return code == 200, ""
			},
		},

		{
			Name: "Viber", Category: CatMessaging,
			Method: "GET",
			URL:    "https://chatsdk.viber.com/pa/account/check_phone_registered?phone={DIGITS}",
			RespCheck: func(body []byte, code int) (bool, string) {
				lower := strings.ToLower(string(body))
				if strings.Contains(lower, "true") || strings.Contains(lower, "registered") {
					return true, ""
				}
				return false, ""
			},
		},

		{
			Name: "Line", Category: CatMessaging,
			Method:    "GET",
			URL:       "https://legy-jp.line.naver.jp/SQR3/login/mobile/checkPhone?phone={DIGITS}",
			RespCheck: defaultJSONCheck,
		},

		{
			Name: "KakaoTalk", Category: CatMessaging,
			Method:    "POST",
			URL:       "https://accounts.kakao.com/weblogin/check/phone",
			Body:      "phone_number={DIGITS}",
			Headers:   map[string]string{"Content-Type": "application/x-www-form-urlencoded"},
			RespCheck: defaultJSONCheck,
		},

		{
			Name: "WeChat", Category: CatMessaging,
			Method:    "GET",
			URL:       "https://web.wechat.com/cgi-bin/mmwebwx-bin/webwxcheckphone?phone={DIGITS}",
			RespCheck: defaultJSONCheck,
		},

		{
			Name: "Discord", Category: CatMessaging,
			Method: "POST",
			URL:    "https://discord.com/api/v9/auth/register",
			Body:   `{"phone":"{DIGITS}","consent":true}`,
			RespCheck: func(body []byte, code int) (bool, string) {
				lower := strings.ToLower(string(body))
				if strings.Contains(lower, "already registered") || strings.Contains(lower, "phone already") {
					return true, ""
				}
				return false, ""
			},
		},

		{
			Name: "Skype", Category: CatMessaging,
			Method: "GET",
			URL:    "https://login.live.com/GetCredentialType.srf",
			RespCheck: func(body []byte, code int) (bool, string) {
				return false, ""
			},
		},

		{
			Name: "Threema", Category: CatMessaging,
			Method:    "GET",
			URL:       "https://api.threema.ch/identity/phone/{DIGITS}",
			RespCheck: defaultJSONCheck,
		},

		{
			Name: "Wire", Category: CatMessaging,
			Method: "HEAD",
			URL:    "https://prod-nginz-https.wire.com/users/handles/{DIGITS}",
			RespCheck: func(body []byte, code int) (bool, string) {
				return code == 200 || code == 204, ""
			},
		},

		// ── FINANCE / BANKING ──

		{
			Name: "Venmo", Category: CatFinance,
			Method: "GET",
			URL:    "https://venmo.com/api/v5/users?phone={DIGITS}",
			RespCheck: func(body []byte, code int) (bool, string) {
				lower := strings.ToLower(string(body))
				if strings.Contains(lower, "username") || strings.Contains(lower, "display_name") {
					return true, ""
				}
				if strings.Contains(lower, "not found") {
					return false, ""
				}
				return false, ""
			},
		},

		{
			Name: "PayPal", Category: CatFinance,
			Method:  "POST",
			URL:     "https://www.paypal.com/auth/validatecaptcha",
			Body:    "phone={DIGITS}",
			Headers: map[string]string{"Content-Type": "application/x-www-form-urlencoded"},
			RespCheck: func(body []byte, code int) (bool, string) {
				lower := strings.ToLower(string(body))
				if strings.Contains(lower, "already exists") || strings.Contains(lower, "already used") {
					return true, ""
				}
				return false, ""
			},
		},

		{
			Name: "CashApp", Category: CatFinance,
			Method: "POST",
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
			Name: "Revolut", Category: CatFinance,
			Method:    "GET",
			URL:       "https://www.revolut.com/api/signup/check-phone?phone={E164}",
			RespCheck: defaultJSONCheck,
		},

		{
			Name: "Monzo", Category: CatFinance,
			Method:    "GET",
			URL:       "https://api.monzo.com/registration/check-phone?phone={E164}",
			RespCheck: defaultJSONCheck,
		},

		{
			Name: "Wise", Category: CatFinance,
			Method:    "GET",
			URL:       "https://wise.com/gateway/v2/profiles/check-phone?phone={E164}",
			RespCheck: defaultJSONCheck,
		},

		{
			Name: "N26", Category: CatFinance,
			Method:    "POST",
			URL:       "https://api.tech26.de/api/signup/check/phone",
			Body:      `{"phoneNumber":"{E164}"}`,
			RespCheck: defaultJSONCheck,
		},

		{
			Name: "Chime", Category: CatFinance,
			Method: "GET",
			URL:    "https://www.chime.com/api/signup/check-phone?phone={DIGITS}",
			RespCheck: func(body []byte, code int) (bool, string) {
				return code < 400 && len(body) > 5, ""
			},
		},

		{
			Name: "Current", Category: CatFinance,
			Method:    "POST",
			URL:       "https://api.current.com/identity/v1/check-phone",
			Body:      `{"phone":"{DIGITS}"}`,
			RespCheck: defaultJSONCheck,
		},

		{
			Name: "Robinhood", Category: CatFinance,
			Method:    "GET",
			URL:       "https://api.robinhood.com/midlands/phone_number/{DIGITS}/exists/",
			RespCheck: defaultJSONCheck,
		},

		{
			Name: "Coinbase", Category: CatCrypto,
			Method: "POST",
			URL:    "https://api.coinbase.com/v2/phone/search",
			Body:   `{"phone_number":"{DIGITS}"}`,
			RespCheck: func(body []byte, code int) (bool, string) {
				lower := strings.ToLower(string(body))
				if strings.Contains(lower, "already") || strings.Contains(lower, "exists") || strings.Contains(lower, "taken") {
					return true, ""
				}
				if strings.Contains(lower, "not found") || strings.Contains(lower, "invalid") {
					return false, ""
				}
				return false, ""
			},
		},

		{
			Name: "Binance", Category: CatCrypto,
			Method:    "POST",
			URL:       "https://www.binance.com/bapi/accounts/v1/public/accounts/check-phone",
			Body:      `{"phone":"{DIGITS}"}`,
			RespCheck: defaultJSONCheck,
		},

		{
			Name: "Kraken", Category: CatCrypto,
			Method:    "GET",
			URL:       "https://api.kraken.com/0/private/CheckPhone?phone={DIGITS}",
			RespCheck: defaultJSONCheck,
		},

		{
			Name: "Blockchain.com", Category: CatCrypto,
			Method:    "POST",
			URL:       "https://api.blockchain.com/v3/exchange/account/check-phone",
			Body:      `{"phone":"{DIGITS}"}`,
			RespCheck: defaultJSONCheck,
		},

		{
			Name: "Crypto.com", Category: CatCrypto,
			Method:    "GET",
			URL:       "https://api.crypto.com/v2/public/check-phone?phone={DIGITS}",
			RespCheck: defaultJSONCheck,
		},

		{
			Name: "Stripe", Category: CatFinance,
			Method:    "POST",
			URL:       "https://api.stripe.com/v1/phone/check",
			Body:      "phone={DIGITS}",
			Headers:   map[string]string{"Content-Type": "application/x-www-form-urlencoded"},
			RespCheck: defaultJSONCheck,
		},

		{
			Name: "Square", Category: CatFinance,
			Method:    "GET",
			URL:       "https://squareup.com/register/api/check-phone?phone={DIGITS}",
			RespCheck: defaultJSONCheck,
		},

		// ── E-COMMERCE ──

		{
			Name: "Amazon", Category: CatEcommerce,
			Method: "POST",
			URL:    "https://www.amazon.com/ap/register",
			Body:   `{"phoneNumber":"{DIGITS}","countryCode":"US"}`,
			Headers: map[string]string{
				"X-Amz-Target": "com.amazon.identity.auth.ap.PhoneNumberValidationService.validatePhoneNumber",
				"Content-Type": "application/json",
			},
			RespCheck: func(body []byte, code int) (bool, string) {
				lower := strings.ToLower(string(body))
				if strings.Contains(lower, "already in use") || strings.Contains(lower, "existing") || strings.Contains(lower, "already registered") {
					return true, ""
				}
				if strings.Contains(lower, "valid") {
					return false, ""
				}
				return false, ""
			},
		},

		{
			Name: "eBay", Category: CatEcommerce,
			Method: "GET",
			URL:    "https://signup.ebay.com/pa/cr?ldtk=PhoneCheck",
			RespCheck: func(body []byte, code int) (bool, string) {
				return false, ""
			},
		},

		{
			Name: "Shopify", Category: CatEcommerce,
			Method:    "GET",
			URL:       "https://accounts.shopify.com/lookup/phone/{DIGITS}",
			RespCheck: defaultJSONCheck,
		},

		{
			Name: "Etsy", Category: CatEcommerce,
			Method:    "POST",
			URL:       "https://www.etsy.com/api/v3/ajax/bespoke/member/register/check-phone",
			Body:      `{"phone":"{DIGITS}"}`,
			RespCheck: defaultJSONCheck,
		},

		{
			Name: "Alibaba", Category: CatEcommerce,
			Method:    "GET",
			URL:       "https://passport.alibaba.com/check/phone_exist.json?phone={DIGITS}",
			RespCheck: defaultJSONCheck,
		},

		{
			Name: "AliExpress", Category: CatEcommerce,
			Method:    "GET",
			URL:       "https://passport.aliexpress.com/newlogin/checkPhone.do?phone={DIGITS}",
			RespCheck: defaultJSONCheck,
		},

		{
			Name: "Walmart", Category: CatEcommerce,
			Method:    "POST",
			URL:       "https://www.walmart.com/account/electrode/api/phone/check",
			Body:      `{"phone":"{DIGITS}"}`,
			RespCheck: defaultJSONCheck,
		},

		{
			Name: "Target", Category: CatEcommerce,
			Method:    "GET",
			URL:       "https://www.target.com/account/creation/check-phone?phone={DIGITS}",
			RespCheck: defaultJSONCheck,
		},

		{
			Name: "BestBuy", Category: CatEcommerce,
			Method:    "GET",
			URL:       "https://www.bestbuy.com/identity/signin/checkPhone?phone={DIGITS}",
			RespCheck: defaultJSONCheck,
		},

		{
			Name: "Wayfair", Category: CatEcommerce,
			Method:    "GET",
			URL:       "https://www.wayfair.com/v/account/check_phone?phone={DIGITS}",
			RespCheck: defaultJSONCheck,
		},

		{
			Name: "ASOS", Category: CatEcommerce,
			Method:    "GET",
			URL:       "https://www.asos.com/api/checkout/check-phone?phone={DIGITS}",
			RespCheck: defaultJSONCheck,
		},

		{
			Name: "Zara", Category: CatEcommerce,
			Method:    "GET",
			URL:       "https://www.zara.com/us/en/register/check-phone?phone={DIGITS}",
			RespCheck: defaultJSONCheck,
		},

		{
			Name: "Zalando", Category: CatEcommerce,
			Method:    "POST",
			URL:       "https://www.zalando.de/api/check-phone",
			Body:      `{"phone":"{DIGITS}"}`,
			RespCheck: defaultJSONCheck,
		},

		{
			Name: "JD.com", Category: CatEcommerce,
			Method:    "GET",
			URL:       "https://passport.jd.com/uc/checkPhone?phone={DIGITS}",
			RespCheck: defaultJSONCheck,
		},

		// ── TRAVEL / RIDE-SHARING ──

		{
			Name: "Uber", Category: CatTravel,
			Method: "POST",
			URL:    "https://auth.uber.com/v2/api/check-phone",
			Body:   `{"phoneNumber":"{DIGITS}"}`,
			RespCheck: func(body []byte, code int) (bool, string) {
				lower := strings.ToLower(string(body))
				if strings.Contains(lower, "existing") || strings.Contains(lower, "already") {
					return true, ""
				}
				if strings.Contains(lower, "available") || strings.Contains(lower, "new") {
					return false, ""
				}
				return false, ""
			},
		},

		{
			Name: "Lyft", Category: CatTravel,
			Method: "POST",
			URL:    "https://www.lyft.com/api/phone/check",
			Body:   `{"phone":"{DIGITS}"}`,
			RespCheck: func(body []byte, code int) (bool, string) {
				lower := strings.ToLower(string(body))
				if strings.Contains(lower, "exists") || strings.Contains(lower, "already") {
					return true, ""
				}
				return false, ""
			},
		},

		{
			Name: "Bolt", Category: CatTravel,
			Method:    "POST",
			URL:       "https://user.bolt.eu/en/isRegistered",
			Body:      `{"phone":"{DIGITS}"}`,
			RespCheck: defaultJSONCheck,
		},

		{
			Name: "Didi", Category: CatTravel,
			Method:    "GET",
			URL:       "https://passport.didiglobal.com/passport/checkphone?phone={DIGITS}",
			RespCheck: defaultJSONCheck,
		},

		{
			Name: "Grab", Category: CatTravel,
			Method:    "GET",
			URL:       "https://p.grab.com/api/passenger/v2/check-phone?phone={DIGITS}",
			RespCheck: defaultJSONCheck,
		},

		{
			Name: "Airbnb", Category: CatTravel,
			Method:  "POST",
			URL:     "https://www.airbnb.com/api/v2/phone_number_details",
			Body:    `{"phone_number":"{DIGITS}"}`,
			Headers: map[string]string{"X-Airbnb-API-Key": "d306zoyjsyarp7ifhu67rjxn52tv0t20"},
			RespCheck: func(body []byte, code int) (bool, string) {
				lower := strings.ToLower(string(body))
				if strings.Contains(lower, "exists") || strings.Contains(lower, "account") || strings.Contains(lower, "user_id") {
					return true, ""
				}
				if strings.Contains(lower, "not found") || strings.Contains(lower, "available") {
					return false, ""
				}
				return false, ""
			},
		},

		{
			Name: "Booking.com", Category: CatTravel,
			Method:    "GET",
			URL:       "https://account.booking.com/register/check-phone?phone={DIGITS}",
			RespCheck: defaultJSONCheck,
		},

		{
			Name: "Expedia", Category: CatTravel,
			Method:    "GET",
			URL:       "https://www.expedia.com/user/check-phone?phone={DIGITS}",
			RespCheck: defaultJSONCheck,
		},

		{
			Name: "TripAdvisor", Category: CatTravel,
			Method:    "GET",
			URL:       "https://www.tripadvisor.com/account/checkPhone?phone={DIGITS}",
			RespCheck: defaultJSONCheck,
		},

		{
			Name: "Kayak", Category: CatTravel,
			Method:    "GET",
			URL:       "https://www.kayak.com/account/check-phone?phone={DIGITS}",
			RespCheck: defaultJSONCheck,
		},

		{
			Name: "Skyscanner", Category: CatTravel,
			Method:    "GET",
			URL:       "https://www.skyscanner.net/identity/check-phone?phone={DIGITS}",
			RespCheck: defaultJSONCheck,
		},

		// ── FOOD DELIVERY ──

		{
			Name: "DoorDash", Category: CatFood,
			Method: "POST",
			URL:    "https://api.doordash.com/v2/phone_number/validate",
			Body:   `{"phone_number":"{DIGITS}"}`,
			RespCheck: func(body []byte, code int) (bool, string) {
				lower := strings.ToLower(string(body))
				if strings.Contains(lower, "existing") || strings.Contains(lower, "taken") {
					return true, ""
				}
				return false, ""
			},
		},

		{
			Name: "UberEats", Category: CatFood,
			Method:    "POST",
			URL:       "https://www.ubereats.com/api/checkPhoneExistsV1",
			Body:      `{"phone":"{DIGITS}"}`,
			RespCheck: defaultJSONCheck,
		},

		{
			Name: "Grubhub", Category: CatFood,
			Method:    "GET",
			URL:       "https://api.grubhub.com/v3/check_phone?phone={DIGITS}",
			RespCheck: defaultJSONCheck,
		},

		{
			Name: "Deliveroo", Category: CatFood,
			Method:    "POST",
			URL:       "https://api.deliveroo.com/api/v1/check-phone",
			Body:      `{"phone":"{E164}"}`,
			RespCheck: defaultJSONCheck,
		},

		{
			Name: "Postmates", Category: CatFood,
			Method:    "GET",
			URL:       "https://postmates.com/api/v1/check_phone?phone={DIGITS}",
			RespCheck: defaultJSONCheck,
		},

		{
			Name: "JustEat", Category: CatFood,
			Method:    "GET",
			URL:       "https://www.just-eat.co.uk/api/account/check-phone?phone={DIGITS}",
			RespCheck: defaultJSONCheck,
		},

		{
			Name: "Zomato", Category: CatFood,
			Method:    "GET",
			URL:       "https://www.zomato.com/webroutes/user/checkPhone?phone={DIGITS}",
			RespCheck: defaultJSONCheck,
		},

		{
			Name: "Swiggy", Category: CatFood,
			Method:    "GET",
			URL:       "https://www.swiggy.com/dapi/account/check-phone?phone={DIGITS}",
			RespCheck: defaultJSONCheck,
		},

		{
			Name: "Instacart", Category: CatFood,
			Method:    "POST",
			URL:       "https://api.instacart.com/v2/check_phone",
			Body:      `{"phone":"{DIGITS}"}`,
			RespCheck: defaultJSONCheck,
		},

		// ── DATING ──

		{
			Name: "Tinder", Category: CatDating,
			Method: "POST",
			URL:    "https://api.gotinder.com/v2/auth/sms/send",
			Body:   `{"phone_number":"{DIGITS}"}`,
			Headers: map[string]string{
				"X-Auth-Token": "d3b9b1e0-6b9e-4b8a-9b8a-6b9e4b8a9b8a",
				"platform":     "android",
			},
			RespCheck: func(body []byte, code int) (bool, string) {
				lower := strings.ToLower(string(body))
				if strings.Contains(lower, "already") || strings.Contains(lower, "existing") || strings.Contains(lower, "login") {
					return true, ""
				}
				return false, ""
			},
		},

		{
			Name: "Bumble", Category: CatDating,
			Method:    "POST",
			URL:       "https://bumble.com/api/v2/auth/check-phone",
			Body:      `{"phone":"{DIGITS}"}`,
			RespCheck: defaultJSONCheck,
		},

		{
			Name: "Hinge", Category: CatDating,
			Method:    "GET",
			URL:       "https://api.hinge.co/v2/auth/check-phone?phone={DIGITS}",
			RespCheck: defaultJSONCheck,
		},

		{
			Name: "OkCupid", Category: CatDating,
			Method:    "GET",
			URL:       "https://www.okcupid.com/1/apitun/account/check-phone?phone={DIGITS}",
			RespCheck: defaultJSONCheck,
		},

		{
			Name: "Match.com", Category: CatDating,
			Method:    "GET",
			URL:       "https://www.match.com/registration/check-phone?phone={DIGITS}",
			RespCheck: defaultJSONCheck,
		},

		{
			Name: "PlentyOfFish", Category: CatDating,
			Method:    "GET",
			URL:       "https://www.pof.com/register/check-phone?phone={DIGITS}",
			RespCheck: defaultJSONCheck,
		},

		{
			Name: "Badoo", Category: CatDating,
			Method:    "POST",
			URL:       "https://badoo.com/api/v1/check-phone",
			Body:      `{"phone":"{DIGITS}"}`,
			RespCheck: defaultJSONCheck,
		},

		{
			Name: "Grindr", Category: CatDating,
			Method:    "POST",
			URL:       "https://api.grindr.com/v3/check-phone",
			Body:      `{"phone":"{DIGITS}"}`,
			RespCheck: defaultJSONCheck,
		},

		{
			Name: "Happn", Category: CatDating,
			Method:    "GET",
			URL:       "https://api.happn.fr/api/v2/check-phone?phone={DIGITS}",
			RespCheck: defaultJSONCheck,
		},

		{
			Name: "HER", Category: CatDating,
			Method:    "GET",
			URL:       "https://api.weareher.com/v2/auth/check-phone?phone={DIGITS}",
			RespCheck: defaultJSONCheck,
		},

		{
			Name: "Hily", Category: CatDating,
			Method:    "GET",
			URL:       "https://api.hily.com/v2/auth/check-phone?phone={DIGITS}",
			RespCheck: defaultJSONCheck,
		},

		// ── PROFESSIONAL / WORK ──

		{
			Name: "LinkedIn", Category: CatWork,
			Method: "POST",
			URL:    "https://www.linkedin.com/checkpoint/lg/phone-verify",
			Body:   `{"phoneNumber":"{DIGITS}"}`,
			Headers: map[string]string{
				"Csrf-Token":                "ajax:1234567890",
				"X-RestLi-Protocol-Version": "2.0.0",
			},
			RespCheck: func(body []byte, code int) (bool, string) {
				lower := strings.ToLower(string(body))
				if strings.Contains(lower, "existing") || strings.Contains(lower, "already") || strings.Contains(lower, "member") {
					return true, ""
				}
				return false, ""
			},
		},

		{
			Name: "GitHub", Category: CatWork,
			Method: "GET",
			URL:    "https://github.com/signup_check/phone?value={DIGITS}",
			RespCheck: func(body []byte, code int) (bool, string) {
				lower := strings.ToLower(string(body))
				if strings.Contains(lower, "already taken") || strings.Contains(lower, "not available") {
					return true, ""
				}
				return false, ""
			},
		},

		{
			Name: "GitLab", Category: CatWork,
			Method:    "GET",
			URL:       "https://gitlab.com/users/sign_up/check-phone?phone={DIGITS}",
			RespCheck: defaultJSONCheck,
		},

		{
			Name: "Upwork", Category: CatWork,
			Method:    "GET",
			URL:       "https://www.upwork.com/ab/account-security/check-phone?phone={DIGITS}",
			RespCheck: defaultJSONCheck,
		},

		{
			Name: "Fiverr", Category: CatWork,
			Method:    "GET",
			URL:       "https://www.fiverr.com/api/users/check_phone?phone={DIGITS}",
			RespCheck: defaultJSONCheck,
		},

		{
			Name: "Freelancer", Category: CatWork,
			Method:    "GET",
			URL:       "https://www.freelancer.com/api/users/0.1/check-phone?phone={DIGITS}",
			RespCheck: defaultJSONCheck,
		},

		{
			Name: "Toptal", Category: CatWork,
			Method:    "GET",
			URL:       "https://www.toptal.com/api/v1/check-phone?phone={DIGITS}",
			RespCheck: defaultJSONCheck,
		},

		{
			Name: "Indeed", Category: CatWork,
			Method:    "GET",
			URL:       "https://www.indeed.com/account/check-phone?phone={DIGITS}",
			RespCheck: defaultJSONCheck,
		},

		{
			Name: "Glassdoor", Category: CatWork,
			Method:    "GET",
			URL:       "https://www.glassdoor.com/api/check-phone?phone={DIGITS}",
			RespCheck: defaultJSONCheck,
		},

		{
			Name: "ZipRecruiter", Category: CatWork,
			Method:    "GET",
			URL:       "https://www.ziprecruiter.com/api/check-phone?phone={DIGITS}",
			RespCheck: defaultJSONCheck,
		},

		{
			Name: "AngelList", Category: CatWork,
			Method:    "GET",
			URL:       "https://api.angel.co/1/check-phone?phone={DIGITS}",
			RespCheck: defaultJSONCheck,
		},

		{
			Name: "StackOverflow", Category: CatWork,
			Method:    "GET",
			URL:       "https://stackoverflow.com/users/phone-check?phone={DIGITS}",
			RespCheck: defaultJSONCheck,
		},

		// ── GAMING ──

		{
			Name: "Steam", Category: CatGaming,
			Method: "POST",
			URL:    "https://store.steampowered.com/phone/validate",
			Body:   `{"phone_number":"{DIGITS}"}`,
			RespCheck: func(body []byte, code int) (bool, string) {
				lower := strings.ToLower(string(body))
				if strings.Contains(lower, "already") || strings.Contains(lower, "exists") || strings.Contains(lower, "taken") {
					return true, ""
				}
				if strings.Contains(lower, "available") || strings.Contains(lower, "ok") {
					return false, ""
				}
				return false, ""
			},
		},

		{
			Name: "Epic Games", Category: CatGaming,
			Method:    "GET",
			URL:       "https://www.epicgames.com/id/api/phone/check?phone={DIGITS}",
			RespCheck: defaultJSONCheck,
		},

		{
			Name: "PlayStation Network", Category: CatGaming,
			Method:    "GET",
			URL:       "https://accounts.api.playstation.com/api/v1/accounts/phone/check?phone={DIGITS}",
			RespCheck: defaultJSONCheck,
		},

		{
			Name: "Xbox Live", Category: CatGaming,
			Method: "GET",
			URL:    "https://login.live.com/oauth20_phone.srf",
			RespCheck: func(body []byte, code int) (bool, string) {
				return false, ""
			},
		},

		{
			Name: "Nintendo", Category: CatGaming,
			Method:    "GET",
			URL:       "https://accounts.nintendo.com/check_phone?phone={DIGITS}",
			RespCheck: defaultJSONCheck,
		},

		{
			Name: "Riot Games", Category: CatGaming,
			Method:    "GET",
			URL:       "https://auth.riotgames.com/api/v1/account/check-phone?phone={DIGITS}",
			RespCheck: defaultJSONCheck,
		},

		{
			Name: "Blizzard", Category: CatGaming,
			Method:    "GET",
			URL:       "https://account.battle.net/api/check-phone?phone={DIGITS}",
			RespCheck: defaultJSONCheck,
		},

		{
			Name: "Ubisoft", Category: CatGaming,
			Method:    "GET",
			URL:       "https://connect.ubisoft.com/account/check-phone?phone={DIGITS}",
			RespCheck: defaultJSONCheck,
		},

		{
			Name: "Roblox", Category: CatGaming,
			Method:    "POST",
			URL:       "https://auth.roblox.com/v2/phone/check",
			Body:      `{"phone":"{DIGITS}"}`,
			RespCheck: defaultJSONCheck,
		},

		{
			Name: "Minecraft", Category: CatGaming,
			Method:    "GET",
			URL:       "https://api.minecraftservices.com/account/check-phone?phone={DIGITS}",
			RespCheck: defaultJSONCheck,
		},

		// ── CRYPTO / WEB3 ──

		{
			Name: "MetaMask", Category: CatCrypto,
			Method:    "GET",
			URL:       "https://api.metamask.io/v1/check-phone?phone={DIGITS}",
			RespCheck: defaultJSONCheck,
		},

		{
			Name: "TrustWallet", Category: CatCrypto,
			Method:    "GET",
			URL:       "https://api.trustwallet.com/v1/check-phone?phone={DIGITS}",
			RespCheck: defaultJSONCheck,
		},

		{
			Name: "Gemini", Category: CatCrypto,
			Method:    "GET",
			URL:       "https://api.gemini.com/v1/check-phone?phone={DIGITS}",
			RespCheck: defaultJSONCheck,
		},

		{
			Name: "Kucoin", Category: CatCrypto,
			Method:    "POST",
			URL:       "https://api.kucoin.com/api/v1/check-phone",
			Body:      `{"phone":"{DIGITS}"}`,
			RespCheck: defaultJSONCheck,
		},

		{
			Name: "Bitfinex", Category: CatCrypto,
			Method:    "GET",
			URL:       "https://api.bitfinex.com/v2/check-phone?phone={DIGITS}",
			RespCheck: defaultJSONCheck,
		},

		{
			Name: "Bitstamp", Category: CatCrypto,
			Method:    "GET",
			URL:       "https://www.bitstamp.net/api/v2/check-phone?phone={DIGITS}",
			RespCheck: defaultJSONCheck,
		},

		{
			Name: "FTX", Category: CatCrypto,
			Method:    "GET",
			URL:       "https://ftx.com/api/check-phone?phone={DIGITS}",
			RespCheck: defaultJSONCheck,
		},

		{
			Name: "OKX", Category: CatCrypto,
			Method:    "GET",
			URL:       "https://www.okx.com/api/v1/check-phone?phone={DIGITS}",
			RespCheck: defaultJSONCheck,
		},

		{
			Name: "Bybit", Category: CatCrypto,
			Method:    "GET",
			URL:       "https://api.bybit.com/v2/check-phone?phone={DIGITS}",
			RespCheck: defaultJSONCheck,
		},

		{
			Name: "Paxful", Category: CatCrypto,
			Method:    "GET",
			URL:       "https://paxful.com/api/check-phone?phone={DIGITS}",
			RespCheck: defaultJSONCheck,
		},

		{
			Name: "LocalBitcoins", Category: CatCrypto,
			Method:    "GET",
			URL:       "https://localbitcoins.com/api/check-phone?phone={DIGITS}",
			RespCheck: defaultJSONCheck,
		},

		// ── UTILITY / TELECOM ──

		{
			Name: "Google Voice", Category: CatUtility,
			Method:    "GET",
			URL:       "https://voice.google.com/u/0/setup/checkphone?phone={DIGITS}",
			RespCheck: defaultJSONCheck,
		},

		{
			Name: "Twilio", Category: CatUtility,
			Method: "GET",
			URL:    "https://lookups.twilio.com/v2/PhoneNumbers/{E164}",
			RespCheck: func(body []byte, code int) (bool, string) {
				return code < 400, ""
			},
		},

		{
			Name: "Burner", Category: CatUtility,
			Method:    "GET",
			URL:       "https://app.burnerapp.com/api/check-phone?phone={DIGITS}",
			RespCheck: defaultJSONCheck,
		},

		{
			Name: "TextNow", Category: CatUtility,
			Method:    "GET",
			URL:       "https://www.textnow.com/api/v2/check-phone?phone={DIGITS}",
			RespCheck: defaultJSONCheck,
		},

		{
			Name: "Hushed", Category: CatUtility,
			Method:    "GET",
			URL:       "https://hushed.com/api/check-phone?phone={DIGITS}",
			RespCheck: defaultJSONCheck,
		},

		{
			Name: "Talkatone", Category: CatUtility,
			Method:    "GET",
			URL:       "https://talkatone.com/api/check-phone?phone={DIGITS}",
			RespCheck: defaultJSONCheck,
		},

		{
			Name: "Dingtone", Category: CatUtility,
			Method:    "GET",
			URL:       "https://www.dingtone.me/api/check-phone?phone={DIGITS}",
			RespCheck: defaultJSONCheck,
		},

		{
			Name: "2ndLine", Category: CatUtility,
			Method:    "GET",
			URL:       "https://www.2ndline.co/api/check-phone?phone={DIGITS}",
			RespCheck: defaultJSONCheck,
		},

		{
			Name: "VirtualSIM", Category: CatUtility,
			Method:    "GET",
			URL:       "https://virtualsimapp.com/api/check-phone?phone={DIGITS}",
			RespCheck: defaultJSONCheck,
		},

		{
			Name: "MySudo", Category: CatUtility,
			Method:    "GET",
			URL:       "https://mysudo.com/api/check-phone?phone={DIGITS}",
			RespCheck: defaultJSONCheck,
		},

		{
			Name: "Phoner", Category: CatUtility,
			Method:    "GET",
			URL:       "https://phonerapp.com/api/check-phone?phone={DIGITS}",
			RespCheck: defaultJSONCheck,
		},

		// ── MEDIA / ENTERTAINMENT ──

		{
			Name: "Spotify", Category: CatSocial,
			Method: "GET",
			URL:    "https://www.spotify.com/api/signup/validate",
			RespCheck: func(body []byte, code int) (bool, string) {
				return false, ""
			},
		},

		{
			Name: "Netflix", Category: CatSocial,
			Method:    "GET",
			URL:       "https://www.netflix.com/api/phone/check?phone={DIGITS}",
			RespCheck: defaultJSONCheck,
		},

		{
			Name: "Hulu", Category: CatSocial,
			Method:    "GET",
			URL:       "https://www.hulu.com/api/check-phone?phone={DIGITS}",
			RespCheck: defaultJSONCheck,
		},

		{
			Name: "Disney+", Category: CatSocial,
			Method:    "GET",
			URL:       "https://www.disneyplus.com/api/check-phone?phone={DIGITS}",
			RespCheck: defaultJSONCheck,
		},

		{
			Name: "HBO Max", Category: CatSocial,
			Method:    "GET",
			URL:       "https://www.hbomax.com/api/check-phone?phone={DIGITS}",
			RespCheck: defaultJSONCheck,
		},

		{
			Name: "YouTube", Category: CatSocial,
			Method: "GET",
			URL:    "https://accounts.google.com/signup/v2/webcreateaccount",
			RespCheck: func(body []byte, code int) (bool, string) {
				return false, ""
			},
		},

		{
			Name: "Twitch", Category: CatSocial,
			Method:  "POST",
			URL:     "https://gql.twitch.tv/gql",
			Body:    `[{"operationName":"CheckPhoneNumberAvailable","variables":{"phoneNumber":"{DIGITS}"},"extensions":{"persistedQuery":{"version":1,"sha256Hash":""}}}]`,
			Headers: map[string]string{"Client-Id": "kimne78kx3ncx6brgo4mv6wki5h1ko"},
			RespCheck: func(body []byte, code int) (bool, string) {
				lower := strings.ToLower(string(body))
				if strings.Contains(lower, "false") || strings.Contains(lower, "unavailable") {
					return true, ""
				}
				return false, ""
			},
		},

		{
			Name: "SoundCloud", Category: CatSocial,
			Method:    "GET",
			URL:       "https://api-auth.soundcloud.com/connect/check-phone?phone={DIGITS}",
			RespCheck: defaultJSONCheck,
		},

		{
			Name: "Deezer", Category: CatSocial,
			Method:    "GET",
			URL:       "https://www.deezer.com/ajax/action/check-phone?phone={DIGITS}",
			RespCheck: defaultJSONCheck,
		},

		{
			Name: "Tidal", Category: CatSocial,
			Method:    "GET",
			URL:       "https://api.tidal.com/v1/check-phone?phone={DIGITS}",
			RespCheck: defaultJSONCheck,
		},

		{
			Name: "Pandora", Category: CatSocial,
			Method:    "GET",
			URL:       "https://www.pandora.com/api/v1/check-phone?phone={DIGITS}",
			RespCheck: defaultJSONCheck,
		},

		{
			Name: "Bandsintown", Category: CatSocial,
			Method:    "GET",
			URL:       "https://www.bandsintown.com/account/check-phone?phone={DIGITS}",
			RespCheck: defaultJSONCheck,
		},

		// ── FITNESS / HEALTH ──

		{
			Name: "Strava", Category: CatSocial,
			Method:    "GET",
			URL:       "https://www.strava.com/api/v3/check-phone?phone={DIGITS}",
			RespCheck: defaultJSONCheck,
		},

		{
			Name: "MyFitnessPal", Category: CatSocial,
			Method:    "GET",
			URL:       "https://www.myfitnesspal.com/api/check-phone?phone={DIGITS}",
			RespCheck: defaultJSONCheck,
		},

		{
			Name: "Fitbit", Category: CatSocial,
			Method:    "GET",
			URL:       "https://api.fitbit.com/1/check-phone?phone={DIGITS}",
			RespCheck: defaultJSONCheck,
		},

		{
			Name: "Peloton", Category: CatSocial,
			Method:    "GET",
			URL:       "https://api.onepeloton.com/api/check-phone?phone={DIGITS}",
			RespCheck: defaultJSONCheck,
		},

		{
			Name: "Nike Run Club", Category: CatSocial,
			Method:    "GET",
			URL:       "https://api.nike.com/check-phone?phone={DIGITS}",
			RespCheck: defaultJSONCheck,
		},

		// ── EDUCATION ──

		{
			Name: "Duolingo", Category: CatSocial,
			Method:    "GET",
			URL:       "https://www.duolingo.com/2018-05-03/users/check-phone?phone={DIGITS}",
			RespCheck: defaultJSONCheck,
		},

		{
			Name: "Coursera", Category: CatWork,
			Method:    "GET",
			URL:       "https://api.coursera.org/api/check-phone?phone={DIGITS}",
			RespCheck: defaultJSONCheck,
		},

		{
			Name: "Udemy", Category: CatWork,
			Method:    "GET",
			URL:       "https://www.udemy.com/api-2.0/check-phone?phone={DIGITS}",
			RespCheck: defaultJSONCheck,
		},

		{
			Name: "Khan Academy", Category: CatWork,
			Method:    "GET",
			URL:       "https://www.khanacademy.org/api/internal/check-phone?phone={DIGITS}",
			RespCheck: defaultJSONCheck,
		},

		{
			Name: "edX", Category: CatWork,
			Method:    "GET",
			URL:       "https://api.edx.org/check-phone?phone={DIGITS}",
			RespCheck: defaultJSONCheck,
		},

		// ── CLOUD / PRODUCTIVITY ──

		{
			Name: "Dropbox", Category: CatWork,
			Method:    "GET",
			URL:       "https://www.dropbox.com/register/check-phone?phone={DIGITS}",
			RespCheck: defaultJSONCheck,
		},

		{
			Name: "Box", Category: CatWork,
			Method:    "GET",
			URL:       "https://account.box.com/api/check-phone?phone={DIGITS}",
			RespCheck: defaultJSONCheck,
		},

		{
			Name: "OneDrive", Category: CatWork,
			Method:    "GET",
			URL:       "https://signup.live.com/API/CheckPhone?phone={DIGITS}",
			RespCheck: defaultJSONCheck,
		},

		{
			Name: "Mega", Category: CatWork,
			Method:    "GET",
			URL:       "https://mega.nz/api/check-phone?phone={DIGITS}",
			RespCheck: defaultJSONCheck,
		},

		{
			Name: "Trello", Category: CatWork,
			Method:    "GET",
			URL:       "https://id.trello.com/1.0/check-phone?phone={DIGITS}",
			RespCheck: defaultJSONCheck,
		},

		{
			Name: "Asana", Category: CatWork,
			Method:    "GET",
			URL:       "https://app.asana.com/api/1.0/check-phone?phone={DIGITS}",
			RespCheck: defaultJSONCheck,
		},

		{
			Name: "Notion", Category: CatWork,
			Method:    "GET",
			URL:       "https://www.notion.so/api/v3/check-phone?phone={DIGITS}",
			RespCheck: defaultJSONCheck,
		},

		{
			Name: "Slack", Category: CatWork,
			Method:    "POST",
			URL:       "https://slack.com/api/auth.checkPhone",
			Body:      "phone={DIGITS}",
			Headers:   map[string]string{"Content-Type": "application/x-www-form-urlencoded"},
			RespCheck: defaultJSONCheck,
		},

		{
			Name: "Zoom", Category: CatWork,
			Method:    "GET",
			URL:       "https://zoom.us/signup/check-phone?phone={DIGITS}",
			RespCheck: defaultJSONCheck,
		},

		{
			Name: "Microsoft Teams", Category: CatWork,
			Method:    "GET",
			URL:       "https://teams.microsoft.com/api/check-phone?phone={DIGITS}",
			RespCheck: defaultJSONCheck,
		},

		// ── GOVERNMENT / PUBLIC SERVICES ──

		{
			Name: "USPS", Category: CatGov,
			Method: "GET",
			URL:    "https://reg.usps.com/entreg/RegistrationAction.do",
			RespCheck: func(body []byte, code int) (bool, string) {
				return false, ""
			},
		},

		{
			Name: "IRS", Category: CatGov,
			Method:    "GET",
			URL:       "https://sa.www4.irs.gov/eauth/registration/check-phone?phone={DIGITS}",
			RespCheck: defaultJSONCheck,
		},

		{
			Name: "SSA", Category: CatGov,
			Method:    "GET",
			URL:       "https://secure.ssa.gov/RIL/check-phone?phone={DIGITS}",
			RespCheck: defaultJSONCheck,
		},

		{
			Name: "DMV Online", Category: CatGov,
			Method:    "GET",
			URL:       "https://www.dmv.virginia.gov/dmvnet/account/check-phone?phone={DIGITS}",
			RespCheck: defaultJSONCheck,
		},

		{
			Name: "Healthcare.gov", Category: CatGov,
			Method:    "GET",
			URL:       "https://www.healthcare.gov/api/check-phone?phone={DIGITS}",
			RespCheck: defaultJSONCheck,
		},

		// ── HOME / REAL ESTATE ──

		{
			Name: "Zillow", Category: CatSocial,
			Method:    "GET",
			URL:       "https://www.zillow.com/api/check-phone?phone={DIGITS}",
			RespCheck: defaultJSONCheck,
		},

		{
			Name: "Realtor.com", Category: CatSocial,
			Method:    "GET",
			URL:       "https://www.realtor.com/api/check-phone?phone={DIGITS}",
			RespCheck: defaultJSONCheck,
		},

		{
			Name: "Trulia", Category: CatSocial,
			Method:    "GET",
			URL:       "https://www.trulia.com/api/check-phone?phone={DIGITS}",
			RespCheck: defaultJSONCheck,
		},

		{
			Name: "Redfin", Category: CatSocial,
			Method:    "GET",
			URL:       "https://www.redfin.com/api/check-phone?phone={DIGITS}",
			RespCheck: defaultJSONCheck,
		},

		{
			Name: "Apartments.com", Category: CatSocial,
			Method:    "GET",
			URL:       "https://www.apartments.com/api/check-phone?phone={DIGITS}",
			RespCheck: defaultJSONCheck,
		},

		{
			Name: "Craigslist", Category: CatSocial,
			Method:    "GET",
			URL:       "https://accounts.craigslist.org/login/check_phone?phone={DIGITS}",
			RespCheck: defaultJSONCheck,
		},

		// ── AUTOMOTIVE ──

		{
			Name: "CarMax", Category: CatEcommerce,
			Method:    "GET",
			URL:       "https://www.carmax.com/api/check-phone?phone={DIGITS}",
			RespCheck: defaultJSONCheck,
		},

		{
			Name: "Carvana", Category: CatEcommerce,
			Method:    "GET",
			URL:       "https://www.carvana.com/api/check-phone?phone={DIGITS}",
			RespCheck: defaultJSONCheck,
		},

		{
			Name: "AutoTrader", Category: CatEcommerce,
			Method:    "GET",
			URL:       "https://www.autotrader.com/api/check-phone?phone={DIGITS}",
			RespCheck: defaultJSONCheck,
		},

		// ── INSURANCE ──

		{
			Name: "Geico", Category: CatFinance,
			Method:    "GET",
			URL:       "https://www.geico.com/api/check-phone?phone={DIGITS}",
			RespCheck: defaultJSONCheck,
		},

		{
			Name: "Progressive", Category: CatFinance,
			Method:    "GET",
			URL:       "https://www.progressive.com/api/check-phone?phone={DIGITS}",
			RespCheck: defaultJSONCheck,
		},

		{
			Name: "StateFarm", Category: CatFinance,
			Method:    "GET",
			URL:       "https://www.statefarm.com/api/check-phone?phone={DIGITS}",
			RespCheck: defaultJSONCheck,
		},

		{
			Name: "Allstate", Category: CatFinance,
			Method:    "GET",
			URL:       "https://www.allstate.com/api/check-phone?phone={DIGITS}",
			RespCheck: defaultJSONCheck,
		},

		{
			Name: "LibertyMutual", Category: CatFinance,
			Method:    "GET",
			URL:       "https://www.libertymutual.com/api/check-phone?phone={DIGITS}",
			RespCheck: defaultJSONCheck,
		},

		// ── TELECOM CARRIERS ──

		{
			Name: "Verizon", Category: CatUtility,
			Method:    "GET",
			URL:       "https://www.verizon.com/signup/check-phone?phone={DIGITS}",
			RespCheck: defaultJSONCheck,
		},

		{
			Name: "AT&T", Category: CatUtility,
			Method:    "GET",
			URL:       "https://www.att.com/signup/check-phone?phone={DIGITS}",
			RespCheck: defaultJSONCheck,
		},

		{
			Name: "T-Mobile", Category: CatUtility,
			Method:    "GET",
			URL:       "https://www.t-mobile.com/signup/check-phone?phone={DIGITS}",
			RespCheck: defaultJSONCheck,
		},

		{
			Name: "Sprint", Category: CatUtility,
			Method:    "GET",
			URL:       "https://www.sprint.com/signup/check-phone?phone={DIGITS}",
			RespCheck: defaultJSONCheck,
		},

		{
			Name: "Mint Mobile", Category: CatUtility,
			Method:    "GET",
			URL:       "https://www.mintmobile.com/api/check-phone?phone={DIGITS}",
			RespCheck: defaultJSONCheck,
		},

		{
			Name: "Visible", Category: CatUtility,
			Method:    "GET",
			URL:       "https://www.visible.com/api/check-phone?phone={DIGITS}",
			RespCheck: defaultJSONCheck,
		},

		// ── RETAIL / LOYALTY ──

		{
			Name: "Costco", Category: CatEcommerce,
			Method:    "GET",
			URL:       "https://www.costco.com/api/check-phone?phone={DIGITS}",
			RespCheck: defaultJSONCheck,
		},

		{
			Name: "Walgreens", Category: CatEcommerce,
			Method:    "GET",
			URL:       "https://www.walgreens.com/api/check-phone?phone={DIGITS}",
			RespCheck: defaultJSONCheck,
		},

		{
			Name: "CVS", Category: CatEcommerce,
			Method:    "GET",
			URL:       "https://www.cvs.com/api/check-phone?phone={DIGITS}",
			RespCheck: defaultJSONCheck,
		},

		{
			Name: "Kroger", Category: CatEcommerce,
			Method:    "GET",
			URL:       "https://www.kroger.com/api/check-phone?phone={DIGITS}",
			RespCheck: defaultJSONCheck,
		},

		{
			Name: "Safeway", Category: CatEcommerce,
			Method:    "GET",
			URL:       "https://www.safeway.com/api/check-phone?phone={DIGITS}",
			RespCheck: defaultJSONCheck,
		},

		{
			Name: "Whole Foods", Category: CatEcommerce,
			Method:    "GET",
			URL:       "https://www.wholefoodsmarket.com/api/check-phone?phone={DIGITS}",
			RespCheck: defaultJSONCheck,
		},

		{
			Name: "Home Depot", Category: CatEcommerce,
			Method:    "GET",
			URL:       "https://www.homedepot.com/api/check-phone?phone={DIGITS}",
			RespCheck: defaultJSONCheck,
		},

		{
			Name: "Lowe's", Category: CatEcommerce,
			Method:    "GET",
			URL:       "https://www.lowes.com/api/check-phone?phone={DIGITS}",
			RespCheck: defaultJSONCheck,
		},

		{
			Name: "IKEA", Category: CatEcommerce,
			Method:    "GET",
			URL:       "https://www.ikea.com/us/en/api/check-phone?phone={DIGITS}",
			RespCheck: defaultJSONCheck,
		},

		{
			Name: "Nike", Category: CatEcommerce,
			Method:    "GET",
			URL:       "https://api.nike.com/cic/check-phone?phone={DIGITS}",
			RespCheck: defaultJSONCheck,
		},

		{
			Name: "Adidas", Category: CatEcommerce,
			Method:    "GET",
			URL:       "https://www.adidas.com/api/check-phone?phone={DIGITS}",
			RespCheck: defaultJSONCheck,
		},

		{
			Name: "Sephora", Category: CatEcommerce,
			Method:    "GET",
			URL:       "https://www.sephora.com/api/check-phone?phone={DIGITS}",
			RespCheck: defaultJSONCheck,
		},

		{
			Name: "Ulta", Category: CatEcommerce,
			Method:    "GET",
			URL:       "https://www.ulta.com/api/check-phone?phone={DIGITS}",
			RespCheck: defaultJSONCheck,
		},

		{
			Name: "Groupon", Category: CatEcommerce,
			Method:    "GET",
			URL:       "https://www.groupon.com/api/check-phone?phone={DIGITS}",
			RespCheck: defaultJSONCheck,
		},

		{
			Name: "LivingSocial", Category: CatEcommerce,
			Method:    "GET",
			URL:       "https://www.livingsocial.com/api/check-phone?phone={DIGITS}",
			RespCheck: defaultJSONCheck,
		},

		{
			Name: "Rakuten", Category: CatEcommerce,
			Method:    "GET",
			URL:       "https://www.rakuten.com/api/check-phone?phone={DIGITS}",
			RespCheck: defaultJSONCheck,
		},

		{
			Name: "Honey", Category: CatEcommerce,
			Method:    "GET",
			URL:       "https://www.joinhoney.com/api/check-phone?phone={DIGITS}",
			RespCheck: defaultJSONCheck,
		},

		{
			Name: "Yelp", Category: CatSocial,
			Method:    "POST",
			URL:       "https://www.yelp.com/api/phone/check",
			Body:      `{"phone":"{DIGITS}"}`,
			RespCheck: defaultJSONCheck,
		},

		{
			Name: "Foursquare", Category: CatSocial,
			Method:    "GET",
			URL:       "https://foursquare.com/api/check-phone?phone={DIGITS}",
			RespCheck: defaultJSONCheck,
		},

		{
			Name: "Nextdoor", Category: CatSocial,
			Method:    "GET",
			URL:       "https://nextdoor.com/api/check-phone?phone={DIGITS}",
			RespCheck: defaultJSONCheck,
		},

		{
			Name: "Meetup", Category: CatSocial,
			Method:    "GET",
			URL:       "https://www.meetup.com/api/check-phone?phone={DIGITS}",
			RespCheck: defaultJSONCheck,
		},

		{
			Name: "Eventbrite", Category: CatSocial,
			Method:    "GET",
			URL:       "https://www.eventbrite.com/api/v3/check-phone?phone={DIGITS}",
			RespCheck: defaultJSONCheck,
		},

		{
			Name: "Ticketmaster", Category: CatSocial,
			Method:    "GET",
			URL:       "https://www.ticketmaster.com/api/check-phone?phone={DIGITS}",
			RespCheck: defaultJSONCheck,
		},

		{
			Name: "StubHub", Category: CatSocial,
			Method:    "GET",
			URL:       "https://www.stubhub.com/api/check-phone?phone={DIGITS}",
			RespCheck: defaultJSONCheck,
		},

		{
			Name: "SeatGeek", Category: CatSocial,
			Method:    "GET",
			URL:       "https://seatgeek.com/api/check-phone?phone={DIGITS}",
			RespCheck: defaultJSONCheck,
		},

		// ── NEWS / MEDIA ──

		{
			Name: "Medium", Category: CatSocial,
			Method:    "GET",
			URL:       "https://medium.com/api/check-phone?phone={DIGITS}",
			RespCheck: defaultJSONCheck,
		},

		{
			Name: "Substack", Category: CatSocial,
			Method:    "GET",
			URL:       "https://substack.com/api/check-phone?phone={DIGITS}",
			RespCheck: defaultJSONCheck,
		},

		{
			Name: "Patreon", Category: CatSocial,
			Method:    "GET",
			URL:       "https://www.patreon.com/api/check-phone?phone={DIGITS}",
			RespCheck: defaultJSONCheck,
		},

		{
			Name: "OnlyFans", Category: CatSocial,
			Method:    "GET",
			URL:       "https://onlyfans.com/api2/v2/users/phone/check?phone={DIGITS}",
			RespCheck: defaultJSONCheck,
		},

		{
			Name: "BuyMeACoffee", Category: CatSocial,
			Method:    "GET",
			URL:       "https://www.buymeacoffee.com/api/check-phone?phone={DIGITS}",
			RespCheck: defaultJSONCheck,
		},

		{
			Name: "Ko-fi", Category: CatSocial,
			Method:    "GET",
			URL:       "https://ko-fi.com/api/check-phone?phone={DIGITS}",
			RespCheck: defaultJSONCheck,
		},

		// ── ASIAN SERVICES ──

		{
			Name: "Weibo", Category: CatSocial,
			Method:    "GET",
			URL:       "https://passport.weibo.cn/signup/checkphone?phone={DIGITS}",
			RespCheck: defaultJSONCheck,
		},

		{
			Name: "QQ", Category: CatMessaging,
			Method:    "GET",
			URL:       "https://ti.qq.com/open_qq/checkPhone?phone={DIGITS}",
			RespCheck: defaultJSONCheck,
		},

		{
			Name: "Baidu", Category: CatSocial,
			Method:    "GET",
			URL:       "https://passport.baidu.com/v2/api/check-phone?phone={DIGITS}",
			RespCheck: defaultJSONCheck,
		},

		{
			Name: "Taobao", Category: CatEcommerce,
			Method:    "GET",
			URL:       "https://login.taobao.com/member/check_phone.do?phone={DIGITS}",
			RespCheck: defaultJSONCheck,
		},

		{
			Name: "Xiaohongshu", Category: CatSocial,
			Method:    "GET",
			URL:       "https://www.xiaohongshu.com/api/check-phone?phone={DIGITS}",
			RespCheck: defaultJSONCheck,
		},

		{
			Name: "Zhihu", Category: CatSocial,
			Method:    "GET",
			URL:       "https://www.zhihu.com/api/v3/check-phone?phone={DIGITS}",
			RespCheck: defaultJSONCheck,
		},

		{
			Name: "Bilibili", Category: CatSocial,
			Method:    "GET",
			URL:       "https://passport.bilibili.com/web/check-phone?phone={DIGITS}",
			RespCheck: defaultJSONCheck,
		},

		{
			Name: "Line", Category: CatMessaging,
			Method:    "GET",
			URL:       "https://access.line.me/dialog/phone/check?phone={DIGITS}",
			RespCheck: defaultJSONCheck,
		},

		{
			Name: "Naver", Category: CatSocial,
			Method:    "GET",
			URL:       "https://nid.naver.com/check-phone?phone={DIGITS}",
			RespCheck: defaultJSONCheck,
		},

		{
			Name: "Daum", Category: CatSocial,
			Method:    "GET",
			URL:       "https://logins.daum.net/accounts/check-phone?phone={DIGITS}",
			RespCheck: defaultJSONCheck,
		},

		{
			Name: "Rakuten", Category: CatEcommerce,
			Method:    "GET",
			URL:       "https://grp01.id.rakuten.co.jp/rms/nid/checkPhone?phone={DIGITS}",
			RespCheck: defaultJSONCheck,
		},

		{
			Name: "Flipkart", Category: CatEcommerce,
			Method:    "GET",
			URL:       "https://www.flipkart.com/api/4/check-phone?phone={DIGITS}",
			RespCheck: defaultJSONCheck,
		},

		{
			Name: "Paytm", Category: CatFinance,
			Method:    "GET",
			URL:       "https://accounts.paytm.com/v2/api/check-phone?phone={DIGITS}",
			RespCheck: defaultJSONCheck,
		},

		{
			Name: "PhonePe", Category: CatFinance,
			Method:    "GET",
			URL:       "https://www.phonepe.com/api/check-phone?phone={DIGITS}",
			RespCheck: defaultJSONCheck,
		},

		{
			Name: "Ola", Category: CatTravel,
			Method:    "GET",
			URL:       "https://www.olacabs.com/api/check-phone?phone={DIGITS}",
			RespCheck: defaultJSONCheck,
		},

		{
			Name: "Oyo", Category: CatTravel,
			Method:    "GET",
			URL:       "https://www.oyorooms.com/api/check-phone?phone={DIGITS}",
			RespCheck: defaultJSONCheck,
		},

		{
			Name: "MakeMyTrip", Category: CatTravel,
			Method:    "GET",
			URL:       "https://www.makemytrip.com/api/check-phone?phone={DIGITS}",
			RespCheck: defaultJSONCheck,
		},

		{
			Name: "Goibibo", Category: CatTravel,
			Method:    "GET",
			URL:       "https://www.goibibo.com/api/check-phone?phone={DIGITS}",
			RespCheck: defaultJSONCheck,
		},

		// ── EUROPEAN SERVICES ──

		{
			Name: "Vodafone", Category: CatUtility,
			Method:    "GET",
			URL:       "https://www.vodafone.com/api/check-phone?phone={DIGITS}",
			RespCheck: defaultJSONCheck,
		},

		{
			Name: "Orange", Category: CatUtility,
			Method:    "GET",
			URL:       "https://www.orange.com/api/check-phone?phone={DIGITS}",
			RespCheck: defaultJSONCheck,
		},

		{
			Name: "Deutsche Telekom", Category: CatUtility,
			Method:    "GET",
			URL:       "https://www.telekom.com/api/check-phone?phone={DIGITS}",
			RespCheck: defaultJSONCheck,
		},

		{
			Name: "Telefonica", Category: CatUtility,
			Method:    "GET",
			URL:       "https://www.telefonica.com/api/check-phone?phone={DIGITS}",
			RespCheck: defaultJSONCheck,
		},

		{
			Name: "Vivino", Category: CatEcommerce,
			Method:    "GET",
			URL:       "https://www.vivino.com/api/check-phone?phone={DIGITS}",
			RespCheck: defaultJSONCheck,
		},

		{
			Name: "Klarna", Category: CatFinance,
			Method:    "GET",
			URL:       "https://api.klarna.com/checkout/v3/check-phone?phone={DIGITS}",
			RespCheck: defaultJSONCheck,
		},

		{
			Name: "Afterpay", Category: CatFinance,
			Method:    "GET",
			URL:       "https://api.afterpay.com/v2/check-phone?phone={DIGITS}",
			RespCheck: defaultJSONCheck,
		},

		{
			Name: "Affirm", Category: CatFinance,
			Method:    "GET",
			URL:       "https://www.affirm.com/api/v1/check-phone?phone={DIGITS}",
			RespCheck: defaultJSONCheck,
		},

		// ── MIDDLE EAST SERVICES ──

		{
			Name: "Careem", Category: CatTravel,
			Method:    "GET",
			URL:       "https://api.careem.com/v1/check-phone?phone={DIGITS}",
			RespCheck: defaultJSONCheck,
		},

		{
			Name: "Noon", Category: CatEcommerce,
			Method:    "GET",
			URL:       "https://www.noon.com/api/check-phone?phone={DIGITS}",
			RespCheck: defaultJSONCheck,
		},

		{
			Name: "Talabat", Category: CatFood,
			Method:    "GET",
			URL:       "https://www.talabat.com/api/check-phone?phone={DIGITS}",
			RespCheck: defaultJSONCheck,
		},

		// ── LATIN AMERICAN SERVICES ──

		{
			Name: "MercadoLibre", Category: CatEcommerce,
			Method:    "GET",
			URL:       "https://api.mercadolibre.com/check-phone?phone={DIGITS}",
			RespCheck: defaultJSONCheck,
		},

		{
			Name: "Rappi", Category: CatFood,
			Method:    "GET",
			URL:       "https://www.rappi.com/api/check-phone?phone={DIGITS}",
			RespCheck: defaultJSONCheck,
		},

		{
			Name: "PedidosYa", Category: CatFood,
			Method:    "GET",
			URL:       "https://www.pedidosya.com/api/check-phone?phone={DIGITS}",
			RespCheck: defaultJSONCheck,
		},

		{
			Name: "iFood", Category: CatFood,
			Method:    "GET",
			URL:       "https://www.ifood.com.br/api/check-phone?phone={DIGITS}",
			RespCheck: defaultJSONCheck,
		},

		{
			Name: "Nubank", Category: CatFinance,
			Method:    "GET",
			URL:       "https://api.nubank.com.br/api/check-phone?phone={DIGITS}",
			RespCheck: defaultJSONCheck,
		},

		{
			Name: "PicPay", Category: CatFinance,
			Method:    "GET",
			URL:       "https://www.picpay.com/api/check-phone?phone={DIGITS}",
			RespCheck: defaultJSONCheck,
		},

		{
			Name: "99", Category: CatTravel,
			Method:    "GET",
			URL:       "https://99app.com/api/check-phone?phone={DIGITS}",
			RespCheck: defaultJSONCheck,
		},

		{
			Name: "Cabify", Category: CatTravel,
			Method:    "GET",
			URL:       "https://cabify.com/api/check-phone?phone={DIGITS}",
			RespCheck: defaultJSONCheck,
		},

		{
			Name: "Cornershop", Category: CatFood,
			Method:    "GET",
			URL:       "https://cornershopapp.com/api/check-phone?phone={DIGITS}",
			RespCheck: defaultJSONCheck,
		},

		// ── AFRICAN SERVICES ──

		{
			Name: "Jumia", Category: CatEcommerce,
			Method:    "GET",
			URL:       "https://www.jumia.com.ng/api/check-phone?phone={DIGITS}",
			RespCheck: defaultJSONCheck,
		},

		{
			Name: "Konga", Category: CatEcommerce,
			Method:    "GET",
			URL:       "https://www.konga.com/api/check-phone?phone={DIGITS}",
			RespCheck: defaultJSONCheck,
		},

		{
			Name: "Flutterwave", Category: CatFinance,
			Method:    "GET",
			URL:       "https://api.flutterwave.com/v3/check-phone?phone={DIGITS}",
			RespCheck: defaultJSONCheck,
		},

		{
			Name: "Paystack", Category: CatFinance,
			Method:    "GET",
			URL:       "https://api.paystack.co/check-phone?phone={DIGITS}",
			RespCheck: defaultJSONCheck,
		},

		{
			Name: "Opay", Category: CatFinance,
			Method:    "GET",
			URL:       "https://www.opay.com/api/check-phone?phone={DIGITS}",
			RespCheck: defaultJSONCheck,
		},

		{
			Name: "PalmPay", Category: CatFinance,
			Method:    "GET",
			URL:       "https://palmpay.com/api/check-phone?phone={DIGITS}",
			RespCheck: defaultJSONCheck,
		},

		{
			Name: "Bolt Food", Category: CatFood,
			Method:    "GET",
			URL:       "https://food.bolt.eu/api/check-phone?phone={DIGITS}",
			RespCheck: defaultJSONCheck,
		},

		// ── ADDITIONAL GLOBAL SERVICES ──

		{
			Name: "Temu", Category: CatEcommerce,
			Method:    "GET",
			URL:       "https://www.temu.com/api/check-phone?phone={DIGITS}",
			RespCheck: defaultJSONCheck,
		},

		{
			Name: "Shein", Category: CatEcommerce,
			Method:    "GET",
			URL:       "https://www.shein.com/api/check-phone?phone={DIGITS}",
			RespCheck: defaultJSONCheck,
		},

		{
			Name: "Wish", Category: CatEcommerce,
			Method:    "GET",
			URL:       "https://www.wish.com/api/check-phone?phone={DIGITS}",
			RespCheck: defaultJSONCheck,
		},

		{
			Name: "Shopee", Category: CatEcommerce,
			Method:    "GET",
			URL:       "https://shopee.com/api/check-phone?phone={DIGITS}",
			RespCheck: defaultJSONCheck,
		},

		{
			Name: "Lazada", Category: CatEcommerce,
			Method:    "GET",
			URL:       "https://www.lazada.com/api/check-phone?phone={DIGITS}",
			RespCheck: defaultJSONCheck,
		},

		{
			Name: "Coupang", Category: CatEcommerce,
			Method:    "GET",
			URL:       "https://www.coupang.com/api/check-phone?phone={DIGITS}",
			RespCheck: defaultJSONCheck,
		},

		{
			Name: "Vinted", Category: CatEcommerce,
			Method:    "GET",
			URL:       "https://www.vinted.com/api/check-phone?phone={DIGITS}",
			RespCheck: defaultJSONCheck,
		},

		{
			Name: "Depop", Category: CatEcommerce,
			Method:    "GET",
			URL:       "https://www.depop.com/api/check-phone?phone={DIGITS}",
			RespCheck: defaultJSONCheck,
		},

		{
			Name: "Poshmark", Category: CatEcommerce,
			Method:    "GET",
			URL:       "https://poshmark.com/api/check-phone?phone={DIGITS}",
			RespCheck: defaultJSONCheck,
		},

		{
			Name: "OfferUp", Category: CatEcommerce,
			Method:    "GET",
			URL:       "https://offerup.com/api/check-phone?phone={DIGITS}",
			RespCheck: defaultJSONCheck,
		},

		{
			Name: "Mercari", Category: CatEcommerce,
			Method:    "GET",
			URL:       "https://www.mercari.com/api/check-phone?phone={DIGITS}",
			RespCheck: defaultJSONCheck,
		},

		{
			Name: "GoFundMe", Category: CatSocial,
			Method:    "GET",
			URL:       "https://www.gofundme.com/api/check-phone?phone={DIGITS}",
			RespCheck: defaultJSONCheck,
		},

		{
			Name: "Kickstarter", Category: CatSocial,
			Method:    "GET",
			URL:       "https://www.kickstarter.com/api/check-phone?phone={DIGITS}",
			RespCheck: defaultJSONCheck,
		},

		{
			Name: "Indiegogo", Category: CatSocial,
			Method:    "GET",
			URL:       "https://www.indiegogo.com/api/check-phone?phone={DIGITS}",
			RespCheck: defaultJSONCheck,
		},
	}
}

func (m *Module) ProxyAware() bool { return true }
