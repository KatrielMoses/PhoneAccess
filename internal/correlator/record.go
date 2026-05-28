package correlator

import "time"

const (
	FieldName       = "name"
	FieldAddress    = "address"
	FieldDOB        = "dob"
	FieldEmail      = "email"
	FieldUsername   = "username"
	FieldSocialLink = "social_link"
	FieldCarrier    = "carrier"
	FieldLineType   = "line_type"
	FieldRegion     = "region"

	StatusSuccess = "success"
	StatusSkipped = "skipped"
)

type SourceMeta struct {
	Name          string   `json:"name"`
	Tier          string   `json:"tier"`
	TierWeight    float64  `json:"tier_weight"`
	Jurisdictions []string `json:"jurisdiction"`
}

type PIIClaim struct {
	Field      string            `json:"field"`
	Value      string            `json:"value"`
	Source     SourceMeta        `json:"source"`
	Weight     float64           `json:"weight"`
	FetchedAt  time.Time         `json:"fetched_at"`
	VerifiedAt *time.Time        `json:"verified_at,omitempty"`
	Precision  string            `json:"precision,omitempty"`
	Metadata   map[string]string `json:"metadata,omitempty"`
}

type FieldCandidate struct {
	Field           string       `json:"field"`
	NormalizedValue string       `json:"normalized_value"`
	DisplayValue    string       `json:"display_value"`
	RawVariants     []string     `json:"raw_variants"`
	Sources         []SourceMeta `json:"sources"`
	Confidence      float64      `json:"confidence"`
	ConfidenceLabel string       `json:"confidence_label"`
	LastSeen        time.Time    `json:"last_seen"`
	Precision       string       `json:"precision,omitempty"`
	Stale           bool         `json:"stale,omitempty"`
	DecayNote       string       `json:"decay_note,omitempty"`
	Suppressed      bool         `json:"suppressed"`
}

type Conflict struct {
	Field          string  `json:"field"`
	ValueA         string  `json:"value_a"`
	SourceA        string  `json:"source_a"`
	ValueB         string  `json:"value_b"`
	SourceB        string  `json:"source_b"`
	PenaltyApplied float64 `json:"penalty_applied"`
}

type SourceRun struct {
	Name        string `json:"name"`
	Status      string `json:"status"`
	ClaimsCount int    `json:"claims_count"`
	Error       string `json:"error,omitempty"`
}

type UnifiedIdentityRecord struct {
	Status            string            `json:"status"`
	Names             []FieldCandidate  `json:"names"`
	Addresses         []FieldCandidate  `json:"addresses"`
	DOBs              []FieldCandidate  `json:"dobs"`
	Emails            []FieldCandidate  `json:"emails"`
	SocialLinks       []FieldCandidate  `json:"social_links"`
	Conflicts         []Conflict        `json:"conflicts"`
	OverallConfidence float64           `json:"overall_confidence"`
	Jurisdiction      string            `json:"jurisdiction"`
	GeneratedAt       time.Time         `json:"generated_at"`
	SuppressedCount   int               `json:"suppressed_count"`
	SuppressionNote   string            `json:"suppression_note,omitempty"`
	Note              string            `json:"note,omitempty"`
	Truecaller        *TruecallerRecord `json:"truecaller,omitempty"`
	Claims            []PIIClaim        `json:"claims,omitempty"`
	SourceRuns        []SourceRun       `json:"source_runs"`
}

type TruecallerRecord struct {
	Name            string   `json:"name,omitempty"`
	City            string   `json:"city,omitempty"`
	ConfidenceScore float64  `json:"score,omitempty"`
	Emails          []string `json:"emails,omitempty"`
	CountryCode     string   `json:"country_code,omitempty"`
	NumberType      string   `json:"number_type,omitempty"`
	Company         string   `json:"company,omitempty"`
	JobTitle        string   `json:"job_title,omitempty"`
	Tags            []string `json:"tags,omitempty"`
}
