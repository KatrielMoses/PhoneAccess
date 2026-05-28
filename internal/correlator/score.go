package correlator

import (
	"math"
	"sort"
	"strconv"
	"strings"
	"time"
)

const (
	HighConfidenceThreshold   = 0.85
	MediumConfidenceThreshold = 0.65
	LowConfidenceThreshold    = 0.45
	conflictPenalty           = 0.30
)

func candidatesFromClusters(clusters []claimCluster, now time.Time) []FieldCandidate {
	out := make([]FieldCandidate, 0, len(clusters))
	for _, cluster := range clusters {
		claims := cluster.Claims
		if len(claims) == 0 {
			continue
		}
		confidence, stale, decayNote := combineClaims(cluster.Field, claims, now)
		candidate := FieldCandidate{
			Field:           cluster.Field,
			NormalizedValue: cluster.Norm,
			DisplayValue:    displayValue(claims),
			RawVariants:     rawVariants(claims),
			Sources:         uniqueSources(claims),
			Confidence:      roundConfidence(confidence),
			LastSeen:        lastSeen(claims),
			Precision:       cluster.Precision,
			Stale:           stale,
			DecayNote:       decayNote,
		}
		candidate.ConfidenceLabel = ConfidenceLabel(candidate.Confidence)
		candidate.Suppressed = candidate.Confidence < LowConfidenceThreshold
		out = append(out, candidate)
	}
	return out
}

func combineClaims(field string, claims []PIIClaim, now time.Time) (float64, bool, string) {
	weightsBySource := map[string]float64{}
	var oldestYears float64
	stale := false
	for _, claim := range claims {
		weight := claim.Weight
		if weight <= 0 {
			weight = claim.Source.TierWeight
		}
		if field == FieldAddress {
			verified := claim.FetchedAt
			if claim.VerifiedAt != nil && !claim.VerifiedAt.IsZero() {
				verified = *claim.VerifiedAt
			}
			if !verified.IsZero() && now.After(verified) {
				years := now.Sub(verified).Hours() / (24 * 365)
				if years > 0 {
					weight *= math.Pow(0.90, years)
					if years >= 1 {
						stale = true
					}
					if years > oldestYears {
						oldestYears = years
					}
				}
			}
		}
		key := strings.ToLower(claim.Source.Name)
		if weight > weightsBySource[key] {
			weightsBySource[key] = clamp(weight, 0, 0.99)
		}
	}
	product := 1.0
	for _, weight := range weightsBySource {
		product *= (1 - weight)
	}
	note := ""
	if stale {
		note = "address confidence decayed for stale verification"
		if oldestYears >= 1 {
			note = "address confidence decayed over " + strconvYears(oldestYears) + " years since verification"
		}
	}
	return clamp(1-product, 0, 1), stale, note
}

func applyConflicts(candidates []FieldCandidate) ([]FieldCandidate, []Conflict) {
	conflicts := []Conflict{}
	for i := range candidates {
		for j := i + 1; j < len(candidates); j++ {
			if candidates[i].Field != candidates[j].Field || !conflictingField(candidates[i].Field) {
				continue
			}
			if sameCluster(candidates[i].Field, candidates[i].NormalizedValue, candidates[j].NormalizedValue) {
				continue
			}
			conflict := Conflict{
				Field:          candidates[i].Field,
				ValueA:         candidates[i].DisplayValue,
				SourceA:        sourceNames(candidates[i].Sources),
				ValueB:         candidates[j].DisplayValue,
				SourceB:        sourceNames(candidates[j].Sources),
				PenaltyApplied: conflictPenalty,
			}
			candidates[i].Confidence = roundConfidence(clamp(candidates[i].Confidence-conflictPenalty, 0, 1))
			candidates[j].Confidence = roundConfidence(clamp(candidates[j].Confidence-conflictPenalty, 0, 1))
			candidates[i].ConfidenceLabel = ConfidenceLabel(candidates[i].Confidence)
			candidates[j].ConfidenceLabel = ConfidenceLabel(candidates[j].Confidence)
			candidates[i].Suppressed = candidates[i].Confidence < LowConfidenceThreshold
			candidates[j].Suppressed = candidates[j].Confidence < LowConfidenceThreshold
			conflicts = append(conflicts, conflict)
		}
	}
	return candidates, conflicts
}

func conflictingField(field string) bool {
	switch field {
	case FieldName, FieldAddress, FieldDOB:
		return true
	default:
		return false
	}
}

func ConfidenceLabel(confidence float64) string {
	switch {
	case confidence >= HighConfidenceThreshold:
		return "high"
	case confidence >= MediumConfidenceThreshold:
		return "medium"
	case confidence >= LowConfidenceThreshold:
		return "low"
	default:
		return "suppressed"
	}
}

func uniqueSources(claims []PIIClaim) []SourceMeta {
	seen := map[string]SourceMeta{}
	for _, claim := range claims {
		key := strings.ToLower(claim.Source.Name)
		if key == "" {
			continue
		}
		seen[key] = claim.Source
	}
	keys := make([]string, 0, len(seen))
	for key := range seen {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	out := make([]SourceMeta, 0, len(keys))
	for _, key := range keys {
		out = append(out, seen[key])
	}
	return out
}

func sortCandidates(candidates []FieldCandidate) {
	sort.SliceStable(candidates, func(i, j int) bool {
		if candidates[i].Confidence == candidates[j].Confidence {
			return strings.ToLower(candidates[i].DisplayValue) < strings.ToLower(candidates[j].DisplayValue)
		}
		return candidates[i].Confidence > candidates[j].Confidence
	})
}

func sourceNames(sources []SourceMeta) string {
	names := make([]string, 0, len(sources))
	for _, source := range sources {
		names = append(names, source.Name)
	}
	sort.Strings(names)
	return strings.Join(names, ", ")
}

func roundConfidence(value float64) float64 {
	return math.Round(value*1000) / 1000
}

func clamp(value, min, max float64) float64 {
	if value < min {
		return min
	}
	if value > max {
		return max
	}
	return value
}

func strconvYears(value float64) string {
	return strings.TrimRight(strings.TrimRight(fmtFloat(value, 1), "0"), ".")
}

func fmtFloat(value float64, precision int) string {
	return strconv.FormatFloat(value, 'f', precision, 64)
}
