package images

import (
	"net/url"
	"os"
	"strings"

	"github.com/KatrielMoses/PhoneAccess/internal/core"
)

const (
	googleLensBase = "https://lens.google.com/uploadbyurl?url="
	yandexBase     = "https://yandex.com/images/search?rpt=imageview&url="
	bingBase       = "https://www.bing.com/images/search?view=detailv2&q=imgurl:"
	tineyeWebBase  = "https://tineye.com/search?url="
)

// buildReverseURLs generates analyst-ready reverse image search URLs for the photo.
// When photoPath is a public CDN URL, it is embedded directly.
// When it is a local filesystem path, the base search URLs are returned without
// an image parameter — the analyst must upload manually.
func buildReverseURLs(photoPath string) core.ReverseSearchURLs {
	if photoPath == "" {
		return core.ReverseSearchURLs{}
	}

	if isURL(photoPath) {
		enc := url.QueryEscape(photoPath)
		return core.ReverseSearchURLs{
			GoogleLens: googleLensBase + enc,
			Yandex:     yandexBase + enc,
			Bing:       bingBase + enc,
			TinEyeWeb:  tineyeWebBase + enc,
		}
	}

	// Local file — return base URLs so the analyst can upload manually.
	return core.ReverseSearchURLs{
		GoogleLens: "https://lens.google.com/",
		Yandex:     "https://yandex.com/images/",
		Bing:       "https://www.bing.com/images/",
		TinEyeWeb:  "https://tineye.com/",
	}
}

// isURL returns true if s looks like a public HTTP(S) URL rather than a local path.
func isURL(s string) bool {
	if strings.HasPrefix(s, "http://") || strings.HasPrefix(s, "https://") {
		return true
	}
	// Also accept paths that don't exist on the local filesystem but look like URLs.
	if _, err := os.Stat(s); err == nil {
		return false // exists locally
	}
	u, err := url.Parse(s)
	return err == nil && u.Scheme != "" && u.Host != ""
}
