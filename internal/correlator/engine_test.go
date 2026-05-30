package correlator

import (
	"context"
	"strings"
	"testing"
	"time"
)

func TestUSCNAMAndNumLookupAgreementHighConfidence(t *testing.T) {
	now := fixedNow()
	engine := NewEngine([]ClaimSource{
		fakeSource{name: "OpenCNAM", claims: []PIIClaim{nameClaim("Jane Example", "OpenCNAM", "Commercial", 0.75, now)}},
		fakeSource{name: "NumLookup", claims: []PIIClaim{nameClaim("Jane Example", "NumLookup", "Commercial", 0.75, now)}},
	}, WithNow(func() time.Time { return now }))

	record, err := engine.Run(context.Background(), "+14155552671")
	if err != nil {
		t.Fatalf("run correlator: %v", err)
	}
	if len(record.Names) != 1 {
		t.Fatalf("names = %d, want 1", len(record.Names))
	}
	if record.Names[0].ConfidenceLabel != "high" || record.Names[0].Confidence < 0.85 {
		t.Fatalf("confidence = %.3f %s, want high", record.Names[0].Confidence, record.Names[0].ConfidenceLabel)
	}
	if len(record.Names[0].Sources) != 2 {
		t.Fatalf("sources = %d, want 2", len(record.Names[0].Sources))
	}
}

func TestUKNumberTriggersCompaniesHouseAfterCandidateName(t *testing.T) {
	now := fixedNow()
	var queried []string
	ch := fakeCompaniesHouse{seen: &queried, now: now}
	engine := NewEngine([]ClaimSource{
		fakeSource{name: "NumLookup", claims: []PIIClaim{nameClaim("Ada Lovelace", "NumLookup", "Commercial", 0.75, now)}},
		ch,
	}, WithNow(func() time.Time { return now }))

	record, err := engine.Run(context.Background(), "+447911123456")
	if err != nil {
		t.Fatalf("run correlator: %v", err)
	}
	if strings.Join(queried, "|") != "Ada Lovelace" {
		t.Fatalf("companies house queried names = %#v", queried)
	}
	if len(record.Addresses) == 0 || !strings.Contains(record.Addresses[0].DisplayValue, "EC1A 1BB") {
		t.Fatalf("companies house address not present: %#v", record.Addresses)
	}
	if len(record.DOBs) == 0 || record.DOBs[0].DisplayValue != "1980-05" || record.DOBs[0].Precision != "month" {
		t.Fatalf("dob = %#v, want partial month", record.DOBs)
	}
}

func TestNameConflictAppliesPenalty(t *testing.T) {
	now := fixedNow()
	engine := NewEngine([]ClaimSource{
		fakeSource{name: "OpenCNAM", claims: []PIIClaim{nameClaim("Jane Example", "OpenCNAM", "Commercial", 0.75, now)}},
		fakeSource{name: "Trestle", claims: []PIIClaim{nameClaim("Janet Other", "Trestle", "Commercial", 0.75, now)}},
	}, WithNow(func() time.Time { return now }))

	record, err := engine.Run(context.Background(), "+14155552671")
	if err != nil {
		t.Fatalf("run correlator: %v", err)
	}
	if len(record.Conflicts) != 1 {
		t.Fatalf("conflicts = %d, want 1", len(record.Conflicts))
	}
	if record.Conflicts[0].PenaltyApplied != 0.30 {
		t.Fatalf("penalty = %.2f, want 0.30", record.Conflicts[0].PenaltyApplied)
	}
	for _, candidate := range record.Names {
		if candidate.Confidence != 0.45 {
			t.Fatalf("candidate confidence = %.3f, want 0.45 after penalty", candidate.Confidence)
		}
	}
}

func TestAddressDecayCalculation(t *testing.T) {
	now := fixedNow()
	verified := now.AddDate(-10, 0, 0)
	claim := addressClaim("10 Downing Street, London SW1A 2AA", "Companies House", "Government", 0.90, now)
	claim.VerifiedAt = &verified
	engine := NewEngine([]ClaimSource{fakeSource{name: "NumLookup", claims: []PIIClaim{claim}}}, WithNow(func() time.Time { return now }))

	record, err := engine.Run(context.Background(), "+447911123456")
	if err != nil {
		t.Fatalf("run correlator: %v", err)
	}
	if len(record.Addresses) != 1 {
		t.Fatalf("addresses = %d, want 1", len(record.Addresses))
	}
	if record.Addresses[0].Confidence < 0.31 || record.Addresses[0].Confidence > 0.32 {
		t.Fatalf("decayed confidence = %.3f, want about 0.314", record.Addresses[0].Confidence)
	}
	if !record.Addresses[0].Stale || record.Addresses[0].DecayNote == "" {
		t.Fatalf("stale decay metadata missing: %#v", record.Addresses[0])
	}
}

func TestSubThresholdSuppressionRetainsJSONCandidate(t *testing.T) {
	now := fixedNow()
	engine := NewEngine([]ClaimSource{
		fakeSource{name: "LeakSight", claims: []PIIClaim{nameClaim("Low Signal", "LeakSight", "Breach", 0.25, now)}},
	}, WithNow(func() time.Time { return now }))

	record, err := engine.Run(context.Background(), "+14155552671")
	if err != nil {
		t.Fatalf("run correlator: %v", err)
	}
	if len(record.Names) != 1 || !record.Names[0].Suppressed {
		t.Fatalf("suppressed candidate missing: %#v", record.Names)
	}
	if record.SuppressedCount != 1 || record.SuppressionNote == "" {
		t.Fatalf("suppression metadata missing: %#v", record)
	}
}

func TestJurisdictionSelectionLogic(t *testing.T) {
	cases := map[string][]string{
		"+919876543210": {"NumLookup", "LeakSight", "IPQualityScore"},
		"+14155552671":  {"OpenCNAM", "NumLookup", "Trestle", "LeakSight", "IPQualityScore"},
		"+447911123456": {"NumLookup", "LeakSight", "Companies House"},
		"+33123456789":  {"NumLookup", "LeakSight", "IPQualityScore"},
	}
	for number, want := range cases {
		selected := SelectSourceNames(number, true)
		for _, name := range want {
			if !selected[strings.ToLower(name)] {
				t.Fatalf("%s missing selected source %s in %#v", number, name, selected)
			}
		}
	}
}

func TestPassiveSkip(t *testing.T) {
	engine := NewEngine([]ClaimSource{fakeSource{name: "OpenCNAM"}}, WithPassive(true), WithNow(fixedNow))
	record, err := engine.Run(context.Background(), "+14155552671")
	if err != nil {
		t.Fatalf("run correlator: %v", err)
	}
	if record.Status != StatusSkipped || !strings.Contains(record.Note, "passive") {
		t.Fatalf("record = %#v, want passive skip", record)
	}
}

type fakeSource struct {
	name   string
	claims []PIIClaim
}

func (s fakeSource) Name() string           { return s.name }
func (s fakeSource) Jurisdiction() []string { return []string{"US", "GB", "ZZ"} }
func (s fakeSource) Fetch(context.Context, string) ([]PIIClaim, error) {
	return append([]PIIClaim(nil), s.claims...), nil
}

type fakeCompaniesHouse struct {
	seen *[]string
	now  time.Time
}

func (s fakeCompaniesHouse) Name() string           { return "Companies House" }
func (s fakeCompaniesHouse) Jurisdiction() []string { return []string{"GB"} }
func (s fakeCompaniesHouse) WithCandidateNames(names []string) ClaimSource {
	*s.seen = append([]string(nil), names...)
	return fakeSource{name: "Companies House", claims: []PIIClaim{
		nameClaim("Ada Lovelace", "Companies House", "Government", 0.90, s.now),
		addressClaim("1 Example Street, London EC1A 1BB", "Companies House", "Government", 0.90, s.now),
		dobClaim("1980-05", "Companies House", "Government", 0.90, s.now, "month"),
	}}
}
func (s fakeCompaniesHouse) Fetch(context.Context, string) ([]PIIClaim, error) { return nil, nil }

func fixedNow() time.Time {
	return time.Date(2026, 5, 27, 12, 0, 0, 0, time.UTC)
}

func nameClaim(value, source, tier string, weight float64, now time.Time) PIIClaim {
	return claim(FieldName, value, source, tier, weight, now)
}

func addressClaim(value, source, tier string, weight float64, now time.Time) PIIClaim {
	return claim(FieldAddress, value, source, tier, weight, now)
}

func dobClaim(value, source, tier string, weight float64, now time.Time, precision string) PIIClaim {
	claim := claim(FieldDOB, value, source, tier, weight, now)
	claim.Precision = precision
	return claim
}

func claim(field, value, source, tier string, weight float64, now time.Time) PIIClaim {
	return PIIClaim{
		Field:  field,
		Value:  value,
		Weight: weight,
		Source: SourceMeta{
			Name:          source,
			Tier:          tier,
			TierWeight:    weight,
			Jurisdictions: []string{"US", "GB", "ZZ"},
		},
		FetchedAt: now,
	}
}

func (s fakeSource) ProxyAware() bool { return true }

func (s fakeCompaniesHouse) ProxyAware() bool { return true }
