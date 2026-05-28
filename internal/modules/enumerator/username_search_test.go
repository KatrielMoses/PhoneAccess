package enumerator

import (
	"context"
	"net/http"
	"testing"

	"github.com/KatrielMoses/PhoneAccess/internal/core"
)

func TestServicesReturnsCopy(t *testing.T) {
	services := Services()
	if len(services) == 0 {
		t.Fatalf("Services returned no services")
	}
	services[0].Name = "Mutated"
	fresh := Services()
	if fresh[0].Name == "Mutated" {
		t.Fatalf("Services should return a copy, but mutation leaked")
	}
}

func TestSearchUsernameProfilesUsesProvidedServices(t *testing.T) {
	services := []Service{
		{Name: "SiteA", URL: "https://api.sitea.example/check/{DIGITS}"},
		{Name: "SiteB", URL: "https://api.siteb.example/check/{DIGITS}"},
	}
	client := &mockHTTPClient{
		responses: map[string]*http.Response{
			"https://sitea.example/alice": mockResponse(200, "<html>profile</html>"),
		},
	}

	hits, err := SearchUsernameProfiles(context.Background(), client, services, "alice", core.NewRateLimiter(0))
	if err != nil {
		t.Fatalf("SearchUsernameProfiles failed: %v", err)
	}
	if len(hits) != 1 {
		t.Fatalf("hits = %#v, want one verified profile", hits)
	}
	if hits[0].Platform != "SiteA" {
		t.Fatalf("platform = %q, want SiteA", hits[0].Platform)
	}
}
