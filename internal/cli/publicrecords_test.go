package cli

import (
	"context"
	"testing"
	"time"

	"github.com/KatrielMoses/PhoneAccess/internal/core"
	"github.com/KatrielMoses/PhoneAccess/internal/correlator"
	publicrecords "github.com/KatrielMoses/PhoneAccess/internal/modules/publicrecords"
)

func TestAddPublicRecordsIdentityClaimsUsesGovernmentTierForOpenCorporates(t *testing.T) {
	number, err := core.NormalizePhoneNumber("+14155552671")
	if err != nil {
		t.Fatalf("normalize: %v", err)
	}
	report := &core.InvestigationReport{
		Number: number,
		Results: []*core.ModuleResult{{
			ModuleName: "public_records",
			Status:     core.ModuleStatusSuccess,
			Data: publicrecords.PublicRecordsResult{
				OpencorpHits: []publicrecords.OfficerHit{
					{OfficerName: "Alex Doe", Company: "Acme Ltd"},
				},
			},
		}},
	}
	record := &correlator.UnifiedIdentityRecord{Claims: []correlator.PIIClaim{}}
	addPublicRecordsIdentityClaims(record, report)

	var found bool
	for _, claim := range record.Claims {
		if claim.Field == correlator.FieldName && claim.Value == "Alex Doe" {
			found = true
			if claim.Source.Tier != "Government" {
				t.Fatalf("tier = %q, want Government", claim.Source.Tier)
			}
			if claim.Source.TierWeight != 0.90 {
				t.Fatalf("tier weight = %v, want 0.90", claim.Source.TierWeight)
			}
		}
	}
	if !found {
		t.Fatalf("expected OpenCorporates officer name claim in record: %#v", record.Claims)
	}
}

func TestDefaultIdentityBuilderIncorporatesPublicRecordsClaims(t *testing.T) {
	number, err := core.NormalizePhoneNumber("+14155552671")
	if err != nil {
		t.Fatalf("normalize: %v", err)
	}
	report := &core.InvestigationReport{
		GeneratedAt: time.Now().UTC(),
		Number:      number,
		Results: []*core.ModuleResult{{
			ModuleName: "public_records",
			Status:     core.ModuleStatusSuccess,
			Data: publicrecords.PublicRecordsResult{
				EdgarHits: []publicrecords.EdgarHit{
					{EntityName: "Example Company Inc."},
				},
			},
		}},
	}

	builder := defaultIdentityBuilder(false, true)
	raw := builder(context.Background(), report)
	record, ok := raw.(*correlator.UnifiedIdentityRecord)
	if !ok {
		t.Fatalf("builder returned %T, want *correlator.UnifiedIdentityRecord", raw)
	}
	found := false
	for _, claim := range record.Claims {
		if claim.Field == correlator.FieldName && claim.Value == "Example Company Inc." {
			found = true
			if claim.Source.Tier != "Commercial" {
				t.Fatalf("tier = %q, want Commercial", claim.Source.Tier)
			}
			if claim.Source.TierWeight != 0.75 {
				t.Fatalf("tier weight = %v, want 0.75", claim.Source.TierWeight)
			}
		}
	}
	if !found {
		t.Fatalf("expected EDGAR claim in identity record: %#v", record.Claims)
	}
}
