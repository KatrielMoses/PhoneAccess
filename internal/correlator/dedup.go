package correlator

import (
	"sort"
	"strings"
	"time"

	"github.com/xrash/smetrics"
)

type claimCluster struct {
	Field     string
	Norm      string
	Precision string
	Claims    []PIIClaim
}

func clusterClaims(claims []PIIClaim) []claimCluster {
	clusters := []claimCluster{}
	for _, claim := range claims {
		normValue, precision := NormalizeValue(claim.Field, claim.Value)
		if normValue == "" {
			continue
		}
		if claim.Field == FieldRegion {
			claim.Field = FieldAddress
		}
		if precision != "" && claim.Precision == "" {
			claim.Precision = precision
		}
		added := false
		for i := range clusters {
			if clusters[i].Field != claim.Field {
				continue
			}
			if claim.Field == FieldDOB && clusters[i].Precision != claim.Precision {
				continue
			}
			if sameCluster(claim.Field, clusters[i].Norm, normValue) {
				clusters[i].Claims = append(clusters[i].Claims, claim)
				added = true
				break
			}
		}
		if !added {
			clusters = append(clusters, claimCluster{Field: claim.Field, Norm: normValue, Precision: claim.Precision, Claims: []PIIClaim{claim}})
		}
	}
	return clusters
}

func sameCluster(field, left, right string) bool {
	if left == right {
		return true
	}
	switch field {
	case FieldName:
		return smetrics.JaroWinkler(left, right, 0.7, 4) >= 0.88
	case FieldAddress:
		return sameAddress(left, right)
	default:
		return false
	}
}

func sameAddress(left, right string) bool {
	leftPost, rightPost := postcode(left), postcode(right)
	if leftPost == "" || rightPost == "" || leftPost != rightPost {
		return false
	}
	return tokenOverlap(left, right) > 0.70
}

func tokenOverlap(left, right string) float64 {
	leftTokens := tokenSet(left)
	rightTokens := tokenSet(right)
	if len(leftTokens) == 0 || len(rightTokens) == 0 {
		return 0
	}
	intersection := 0
	for token := range leftTokens {
		if rightTokens[token] {
			intersection++
		}
	}
	smaller := len(leftTokens)
	if len(rightTokens) < smaller {
		smaller = len(rightTokens)
	}
	return float64(intersection) / float64(smaller)
}

func tokenSet(value string) map[string]bool {
	out := map[string]bool{}
	for _, token := range strings.Fields(value) {
		if len(token) < 2 {
			continue
		}
		out[token] = true
	}
	return out
}

func displayValue(claims []PIIClaim) string {
	if len(claims) == 0 {
		return ""
	}
	best := claims[0]
	for _, claim := range claims[1:] {
		if claim.Weight > best.Weight || (claim.Weight == best.Weight && len([]rune(claim.Value)) > len([]rune(best.Value))) {
			best = claim
		}
	}
	return strings.TrimSpace(best.Value)
}

func rawVariants(claims []PIIClaim) []string {
	seen := map[string]bool{}
	var out []string
	for _, claim := range claims {
		value := strings.TrimSpace(claim.Value)
		if value == "" || seen[value] {
			continue
		}
		seen[value] = true
		out = append(out, value)
	}
	sort.Strings(out)
	return out
}

func lastSeen(claims []PIIClaim) time.Time {
	var latest time.Time
	for _, claim := range claims {
		t := claim.FetchedAt
		if claim.VerifiedAt != nil && !claim.VerifiedAt.IsZero() {
			t = *claim.VerifiedAt
		}
		if t.After(latest) {
			latest = t
		}
	}
	return latest
}
