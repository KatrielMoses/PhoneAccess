package core

import (
	"context"
	"encoding/json"
	"time"
)

// PostMessengerModule is implemented by modules that need the completed MessengerReport.
// The engine runs these after all parallel modules finish and BuildMessengerReport completes.
type PostMessengerModule interface {
	RunPostMessenger(ctx context.Context, number *PhoneNumber, report *InvestigationReport) (*ModuleResult, error)
}

type ImageIntelResult struct {
	PhotoPath        string             `json:"photo_path,omitempty"`
	PhotoSource      string             `json:"photo_source,omitempty"`
	PhotoPHash       string             `json:"photo_phash,omitempty"`
	TinEye           TinEyeResult       `json:"tineye"`
	ReverseURLs      ReverseSearchURLs  `json:"reverse_urls"`
	CrossSessionHits []CrossSessionMatch `json:"cross_session_hits,omitempty"`
}

type TinEyeResult struct {
	MatchCount int           `json:"match_count"`
	Matches    []TinEyeMatch `json:"matches,omitempty"`
}

type TinEyeMatch struct {
	Domain    string    `json:"domain"`
	URL       string    `json:"url"`
	CrawlDate time.Time `json:"crawl_date"`
	ImageURL  string    `json:"image_url,omitempty"`
	Score     float64   `json:"score,omitempty"`
}

type ReverseSearchURLs struct {
	GoogleLens string `json:"google_lens,omitempty"`
	Yandex     string `json:"yandex,omitempty"`
	Bing       string `json:"bing,omitempty"`
	TinEyeWeb  string `json:"tineye_web,omitempty"`
}

type CrossSessionMatch struct {
	CaseID      int64     `json:"case_id"`
	PhoneE164   string    `json:"phone_e164"`
	CaseName    string    `json:"case_name,omitempty"`
	HammingDist int       `json:"hamming_dist"`
	FoundAt     time.Time `json:"found_at"`
}

type LineType string

const (
	LineTypeMobile      LineType = "mobile"
	LineTypeLandline    LineType = "landline"
	LineTypeVoIP        LineType = "voip"
	LineTypeTollFree    LineType = "toll-free"
	LineTypePremiumRate LineType = "premium-rate"
	LineTypeUnknown     LineType = "unknown"
)

type PhoneNumber struct {
	RawInput          string   `json:"raw_input"`
	E164              string   `json:"e164"`
	SearchVariants    []string `json:"search_variants,omitempty"`
	CountryCode       int      `json:"country_code"`
	CountryAlpha2     string   `json:"country_alpha2"`
	NationalNumber    string   `json:"national_number"`
	RegionDescription string   `json:"region_description"`
	LineType          LineType `json:"line_type"`
	CarrierHint       string   `json:"carrier_hint,omitempty"`
	Timezone          string   `json:"timezone"`
	Valid             bool     `json:"valid"`
}

type ModuleStatus string

const (
	ModuleStatusSuccess ModuleStatus = "success"
	ModuleStatusSkipped ModuleStatus = "skipped"
	ModuleStatusGated   ModuleStatus = "gated"
	ModuleStatusError   ModuleStatus = "error"
)

type ModuleTier int

const (
	TierPassive ModuleTier = 0
	TierActive  ModuleTier = 1
)

func (t ModuleTier) String() string {
	switch t {
	case TierPassive:
		return "passive"
	case TierActive:
		return "active"
	default:
		return "unknown"
	}
}

type ModuleResult struct {
	ModuleName string            `json:"module_name"`
	Status     ModuleStatus      `json:"status"`
	Findings   map[string]string `json:"findings,omitempty"`
	Data       any               `json:"data,omitempty"`
	Evidence   []string          `json:"evidence,omitempty"`
}

type RiskBand string

const (
	RiskBandLow      RiskBand = "LOW"
	RiskBandModerate RiskBand = "MODERATE"
	RiskBandHigh     RiskBand = "HIGH"
	RiskBandCritical RiskBand = "CRITICAL"
)

type RiskDriver struct {
	Label  string `json:"label"`
	Points int    `json:"points"`
}

type RiskScore struct {
	Score   int          `json:"score"`
	Band    RiskBand     `json:"band"`
	Drivers []RiskDriver `json:"drivers"`
	Summary string       `json:"summary"`
}

type Module interface {
	Name() string
	Description() string
	RequiresAPIKey() bool
	Tier() ModuleTier
	ProxyAware() bool
	DryRun(ctx context.Context, number *PhoneNumber) error
	Run(ctx context.Context, number *PhoneNumber) (*ModuleResult, error)
}

type PassiveModule interface {
	RunPassive(ctx context.Context, number *PhoneNumber) (*ModuleResult, error)
}

type MessengerReport struct {
	Telegram *MessengerAccount `json:"telegram,omitempty"`
	WhatsApp *MessengerAccount `json:"whatsapp,omitempty"`
	Signal   *MessengerAccount `json:"signal,omitempty"`
}

type MessengerAccount struct {
	Found             bool   `json:"found"`
	DisplayName       string `json:"display_name,omitempty"`
	Username          string `json:"username,omitempty"`
	Bio               string `json:"bio,omitempty"`
	LastSeenBucket    string `json:"last_seen_bucket,omitempty"`
	AccountID         string `json:"account_id,omitempty"`
	ProfilePhotoPath  string `json:"profile_photo_path,omitempty"`
	ProfilePhotoPHash string `json:"profile_photo_phash,omitempty"`
	AboutBio          string `json:"about_bio,omitempty"`
	DataSource        string `json:"data_source"`
}

type InvestigationReport struct {
	GeneratedAt      time.Time         `json:"generated_at"`
	Passive          bool              `json:"passive"`
	Number           *PhoneNumber      `json:"number"`
	Results          []*ModuleResult   `json:"results"`
	Messenger        *MessengerReport  `json:"messenger,omitempty"`
	ImageIntelligence *ImageIntelResult `json:"image_intelligence,omitempty"`
	IdentityGraph    *IdentityGraph    `json:"identity_graph,omitempty"`
	PivotChain       *PivotChainNode   `json:"pivot_chain,omitempty"`
	Timeline         *Timeline         `json:"timeline,omitempty"`
	IdentityRecord   any               `json:"identity_record,omitempty"`
	RiskScore        *RiskScore        `json:"risk_score,omitempty"`
}

func (r *InvestigationReport) MarshalJSON() ([]byte, error) {
	type alias InvestigationReport
	base, err := json.Marshal((*alias)(r))
	if err != nil {
		return nil, err
	}

	var out map[string]any
	if err := json.Unmarshal(base, &out); err != nil {
		return nil, err
	}

	for _, result := range r.Results {
		if result == nil || result.ModuleName == "" {
			continue
		}
		if result.Status == ModuleStatusGated {
			continue
		}
		if result.Data != nil {
			out[result.ModuleName] = result.Data
			continue
		}
		if len(result.Findings) > 0 {
			out[result.ModuleName] = result.Findings
		}
	}

	return json.Marshal(out)
}
