package finance

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"

	"github.com/KatrielMoses/PhoneAccess/internal/core"
)

type venmoUser struct {
	Username        string `json:"username"`
	DisplayName     string `json:"display_name"`
	ProfilePhotoURL string `json:"profile_picture_url"`
	Privacy         string `json:"privacy"`
	About           string `json:"about"`
}

type venmoResponse struct {
	Data []venmoUser `json:"data"`
}

func (m *Module) checkVenmo(ctx context.Context, number *core.PhoneNumber) *VenmoProfile {
	endpoint := fmt.Sprintf("https://venmo.com/api/v5/users?phone=%s", digitsOnly(number))
	parsed, err := url.Parse(endpoint)
	if err != nil {
		return nil
	}

	if m.venmoLimiter != nil {
		if err := m.venmoLimiter.Wait(ctx, parsed.Hostname()); err != nil {
			return nil
		}
	}

	requestCtx, cancel := context.WithTimeout(ctx, core.DefaultHTTPTimeout)
	defer cancel()

	req, err := http.NewRequestWithContext(requestCtx, http.MethodGet, endpoint, nil)
	if err != nil {
		return nil
	}
	core.SetDefaultHeaders(req)
	req.Header.Set("Accept", "application/json")

	resp, err := m.httpClient.Do(req)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, maxBodySize))
	if err != nil {
		return nil
	}

	var parsedResp venmoResponse
	if err := json.Unmarshal(body, &parsedResp); err != nil {
		return nil
	}

	if len(parsedResp.Data) == 0 {
		return &VenmoProfile{Found: false}
	}

	user := parsedResp.Data[0]
	profile := &VenmoProfile{
		Found:           true,
		DisplayName:     strings.TrimSpace(user.DisplayName),
		Username:        strings.TrimSpace(user.Username),
		ProfilePhotoURL: strings.TrimSpace(user.ProfilePhotoURL),
		Privacy:         strings.TrimSpace(user.Privacy),
		LastTransaction: user.About,
	}

	if profile.DisplayName == "" && profile.Username == "" {
		profile.Found = false
	}

	return profile
}

func digitsOnly(number *core.PhoneNumber) string {
	e164 := number.E164
	if e164 == "" {
		e164 = number.RawInput
	}
	var builder strings.Builder
	for _, r := range e164 {
		if r >= '0' && r <= '9' {
			builder.WriteRune(r)
		}
	}
	return builder.String()
}

func phoneE164(number *core.PhoneNumber) string {
	if number == nil {
		return ""
	}
	if number.E164 != "" {
		return number.E164
	}
	return number.RawInput
}

func phoneDigits(number *core.PhoneNumber) string {
	return url.QueryEscape(digitsOnly(number))
}