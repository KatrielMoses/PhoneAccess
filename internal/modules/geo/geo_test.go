package geo

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/KatrielMoses/PhoneAccess/internal/core"
)

func TestPortedNumberHint(t *testing.T) {
	module := New(WithNow(fixedUTC("2026-01-02T22:30:00Z")))
	number := &core.PhoneNumber{
		E164:           "+14155552671",
		CountryCode:    1,
		CountryAlpha2:  "US",
		NationalNumber: "4155552671",
		CarrierHint:    "Twilio",
		Timezone:       "America/Los_Angeles",
		Valid:          true,
	}

	result, err := module.Run(context.Background(), number)
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	data := result.Data.(Result)

	if !strings.Contains(data.AreaCodeOrigin, "San Francisco") {
		t.Fatalf("AreaCodeOrigin = %q, want San Francisco", data.AreaCodeOrigin)
	}
	if !data.AreaCodeSplitHistory {
		t.Fatal("AreaCodeSplitHistory = false, want true")
	}
	if !data.LikelyPorted {
		t.Fatal("LikelyPorted = false, want true")
	}
	if !strings.Contains(data.PortedReason, "differs") {
		t.Fatalf("PortedReason = %q, want differs reasoning", data.PortedReason)
	}
}

func TestBusinessHoursCalculationAcrossTimezones(t *testing.T) {
	module := New(WithNow(fixedUTC("2026-01-02T22:30:00Z")))

	newYork := runGeo(t, module, &core.PhoneNumber{
		CountryCode:    1,
		CountryAlpha2:  "US",
		NationalNumber: "2125551212",
		Timezone:       "America/New_York",
	})
	losAngeles := runGeo(t, module, &core.PhoneNumber{
		CountryCode:    1,
		CountryAlpha2:  "US",
		NationalNumber: "4155551212",
		Timezone:       "America/Los_Angeles",
	})

	if newYork.TimezoneDetail.BusinessHours {
		t.Fatalf("New York business hours = true at %s, want false", newYork.TimezoneDetail.LocalTime)
	}
	if !losAngeles.TimezoneDetail.BusinessHours {
		t.Fatalf("Los Angeles business hours = false at %s, want true", losAngeles.TimezoneDetail.LocalTime)
	}
	if newYork.TimezoneDetail.UTCOffset != "-05:00" {
		t.Fatalf("New York offset = %q, want -05:00", newYork.TimezoneDetail.UTCOffset)
	}
	if losAngeles.TimezoneDetail.UTCOffset != "-08:00" {
		t.Fatalf("Los Angeles offset = %q, want -08:00", losAngeles.TimezoneDetail.UTCOffset)
	}
}

func TestHighRiskRegionFlag(t *testing.T) {
	module := New(WithNow(fixedUTC("2026-01-02T12:00:00Z")))
	number := &core.PhoneNumber{
		E164:           "+18765551234",
		CountryCode:    1,
		CountryAlpha2:  "JM",
		NationalNumber: "8765551234",
		Timezone:       "America/Jamaica",
	}

	result, err := module.Run(context.Background(), number)
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	data := result.Data.(Result)

	if !data.RegionalRiskFlag {
		t.Fatal("RegionalRiskFlag = false, want true")
	}
	if data.RegionalRiskRegion != "Jamaica" {
		t.Fatalf("RegionalRiskRegion = %q, want Jamaica", data.RegionalRiskRegion)
	}
	if !strings.Contains(strings.ToLower(data.RegionalRiskBasis), "public") {
		t.Fatalf("RegionalRiskBasis = %q, want public-data basis", data.RegionalRiskBasis)
	}
}

func TestCountryCodeHighRiskRegionFlag(t *testing.T) {
	module := New(WithNow(fixedUTC("2026-01-02T12:00:00Z")))
	number := &core.PhoneNumber{
		E164:           "+2348012345678",
		CountryCode:    234,
		CountryAlpha2:  "NG",
		NationalNumber: "8012345678",
		Timezone:       "Africa/Lagos",
	}

	data := runGeo(t, module, number)
	if !data.RegionalRiskFlag {
		t.Fatal("RegionalRiskFlag = false, want true")
	}
	if data.RegionalRiskRegion != "Nigeria" {
		t.Fatalf("RegionalRiskRegion = %q, want Nigeria", data.RegionalRiskRegion)
	}
}

func TestPassiveModeStillRunsOfflineInference(t *testing.T) {
	module := New(WithNow(fixedUTC("2026-01-02T22:30:00Z")))
	result, err := module.RunPassive(context.Background(), &core.PhoneNumber{
		CountryCode:    1,
		CountryAlpha2:  "US",
		NationalNumber: "6505551212",
		CarrierHint:    "Pacific Bell",
		Timezone:       "America/Los_Angeles",
	})
	if err != nil {
		t.Fatalf("run passive: %v", err)
	}
	data := result.Data.(Result)
	if !strings.Contains(data.AreaCodeOrigin, "San Mateo") {
		t.Fatalf("AreaCodeOrigin = %q, want San Mateo", data.AreaCodeOrigin)
	}
	if data.LikelyPorted {
		t.Fatal("LikelyPorted = true, want false for matching historical carrier")
	}
}

func runGeo(t *testing.T, module *Module, number *core.PhoneNumber) Result {
	t.Helper()
	result, err := module.Run(context.Background(), number)
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	return result.Data.(Result)
}

func fixedUTC(value string) func() time.Time {
	return func() time.Time {
		parsed, err := time.Parse(time.RFC3339, value)
		if err != nil {
			panic(err)
		}
		return parsed
	}
}
