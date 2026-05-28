package storage

import (
	"testing"
)

func TestStorage(t *testing.T) {
	s, err := Open("file::memory:?cache=shared")
	if err != nil {
		t.Fatalf("failed to open storage: %v", err)
	}
	defer s.Close()

	jsonReport := `{"test":"data"}`
	pivots := []Pivot{
		{Type: "email", Value: "test@example.com", Confidence: 0.25, Source: "Breach Intelligence"},
	}
	
	id1, matches1, err := s.SaveInvestigation("+1234567890", jsonReport, 50, "HIGH", pivots)
	if err != nil {
		t.Fatalf("failed to save investigation 1: %v", err)
	}
	if len(matches1) != 0 {
		t.Fatalf("expected 0 matches for first investigation, got %d", len(matches1))
	}

	id2, matches2, err := s.SaveInvestigation("+0987654321", jsonReport, 50, "HIGH", pivots)
	if err != nil {
		t.Fatalf("failed to save investigation 2: %v", err)
	}
	if len(matches2) != 1 {
		t.Fatalf("expected 1 match for second investigation, got %d", len(matches2))
	}
	if matches2[0].Investigation.ID != id1 {
		t.Fatalf("expected match to be investigation %d, got %d", id1, matches2[0].Investigation.ID)
	}

	invs, err := s.ListInvestigations()
	if err != nil {
		t.Fatalf("ListInvestigations error: %v", err)
	}
	if len(invs) != 2 {
		t.Fatalf("expected 2 investigations, got %d", len(invs))
	}

	s.UpdateTag(id1, "malicious")
	s.UpdateNote(id2, "suspected fraud")

	res, err := s.Search("malicious")
	if err != nil || len(res) != 1 || res[0].ID != id1 {
		t.Fatalf("search for 'malicious' failed")
	}

	res, err = s.Search("fraud")
	if err != nil || len(res) != 1 || res[0].ID != id2 {
		t.Fatalf("search for 'fraud' failed")
	}
}
