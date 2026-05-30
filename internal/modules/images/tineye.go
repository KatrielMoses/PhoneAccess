package images

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"github.com/KatrielMoses/PhoneAccess/internal/core"
)

const tineyeEndpoint = "https://api.tineye.com/rest/search/"

type tineyeClient struct {
	keyLoader   func() string
	rateLimiter *core.RateLimiter
	httpClient  *http.Client
}

func newTinEyeClient(keyLoader func() string, limiter *core.RateLimiter) *tineyeClient {
	return &tineyeClient{
		keyLoader:   keyLoader,
		rateLimiter: limiter,
		httpClient:  core.NewHTTPClient(30 * time.Second),
	}
}

// tineyeResponse mirrors the TinEye REST API JSON envelope.
type tineyeResponse struct {
	Status  string `json:"status"`
	Code    int    `json:"code"`
	Message string `json:"message,omitempty"`
	Results struct {
		TotalResults int             `json:"total_results"`
		Matches      []tineyeMatch   `json:"matches"`
	} `json:"results"`
}

type tineyeMatch struct {
	Domain    string          `json:"domain"`
	ImageURL  string          `json:"image_url"`
	Score     float64         `json:"score"`
	Width     int             `json:"width"`
	Height    int             `json:"height"`
	Backlinks []tineyeBacklink `json:"backlinks"`
}

type tineyeBacklink struct {
	URL       string `json:"url"`
	CrawlDate string `json:"crawl_date"`
}

// Search submits the file at photoPath to TinEye and returns the structured result.
func (c *tineyeClient) Search(ctx context.Context, photoPath string) (core.TinEyeResult, error) {
	key := c.keyLoader()
	if key == "" {
		return core.TinEyeResult{}, fmt.Errorf("missing %s", keyName)
	}

	if c.rateLimiter != nil {
		if err := c.rateLimiter.Wait(ctx, "tineye"); err != nil {
			return core.TinEyeResult{}, err
		}
	}

	body, contentType, err := buildMultipartBody(photoPath)
	if err != nil {
		return core.TinEyeResult{}, fmt.Errorf("build request: %w", err)
	}

	endpoint := fmt.Sprintf("%s?api_key=%s", tineyeEndpoint, key)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, body)
	if err != nil {
		return core.TinEyeResult{}, err
	}
	req.Header.Set("Content-Type", contentType)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return core.TinEyeResult{}, fmt.Errorf("tineye request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden {
		return core.TinEyeResult{}, fmt.Errorf("tineye auth error: %d", resp.StatusCode)
	}

	data, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return core.TinEyeResult{}, fmt.Errorf("read response: %w", err)
	}

	var tineyeResp tineyeResponse
	if err := json.Unmarshal(data, &tineyeResp); err != nil {
		return core.TinEyeResult{}, fmt.Errorf("parse response: %w", err)
	}

	return convertTinEyeResponse(tineyeResp), nil
}

func convertTinEyeResponse(resp tineyeResponse) core.TinEyeResult {
	result := core.TinEyeResult{
		MatchCount: resp.Results.TotalResults,
	}
	for _, m := range resp.Results.Matches {
		match := core.TinEyeMatch{
			Domain:   m.Domain,
			ImageURL: m.ImageURL,
			Score:    m.Score,
		}
		// Use the first backlink for URL and crawl date.
		if len(m.Backlinks) > 0 {
			bl := m.Backlinks[0]
			match.URL = bl.URL
			match.CrawlDate, _ = time.Parse("2006-01-02", bl.CrawlDate)
		}
		result.Matches = append(result.Matches, match)
	}
	return result
}

func buildMultipartBody(photoPath string) (*bytes.Buffer, string, error) {
	f, err := os.Open(photoPath)
	if err != nil {
		return nil, "", err
	}
	defer f.Close()

	var buf bytes.Buffer
	w := multipart.NewWriter(&buf)
	part, err := w.CreateFormFile("image", filepath.Base(photoPath))
	if err != nil {
		return nil, "", err
	}
	if _, err := io.Copy(part, f); err != nil {
		return nil, "", err
	}
	if err := w.Close(); err != nil {
		return nil, "", err
	}
	return &buf, w.FormDataContentType(), nil
}
