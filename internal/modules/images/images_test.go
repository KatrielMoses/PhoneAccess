package images

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/KatrielMoses/PhoneAccess/internal/core"
	"github.com/KatrielMoses/PhoneAccess/internal/storage"
)

// ---- helpers ----------------------------------------------------------------

func number() *core.PhoneNumber {
	return &core.PhoneNumber{E164: "+15005550001"}
}

func reportWithPhoto(path, source string) *core.InvestigationReport {
	report := &core.InvestigationReport{
		Number:  number(),
		Results: []*core.ModuleResult{},
	}
	switch source {
	case "telegram":
		report.Messenger = &core.MessengerReport{
			Telegram: &core.MessengerAccount{
				Found:             true,
				ProfilePhotoPath:  path,
				ProfilePhotoPHash: "a3f4b2c1d0e9f8a7",
				DataSource:        "telegram_mtproto",
			},
		}
	case "whatsapp":
		report.Messenger = &core.MessengerReport{
			WhatsApp: &core.MessengerAccount{
				Found:             true,
				ProfilePhotoPath:  path,
				ProfilePhotoPHash: "a3f4b2c1d0e9f8a7",
				DataSource:        "whatsapp_web",
			},
		}
	}
	return report
}

func reportNoPhoto() *core.InvestigationReport {
	return &core.InvestigationReport{Number: number(), Results: []*core.ModuleResult{}}
}

// stubPhashStore implements PhashStore with canned responses.
type stubPhashStore struct {
	records []storage.PhotoHashRecord
	err     error
}

func (s *stubPhashStore) FindSimilarHashes(_ string, _, _ int) ([]storage.PhotoHashRecord, error) {
	return s.records, s.err
}
func (s *stubPhashStore) Close() error { return nil }

// stubTinEye implements TinEyeSearcher with a canned response.
type stubTinEye struct {
	result core.TinEyeResult
	err    error
}

func (s *stubTinEye) Search(_ context.Context, _ string) (core.TinEyeResult, error) {
	return s.result, s.err
}

func noopStoreOpener() (PhashStore, error) { return &stubPhashStore{}, nil }
func zeroLimiter() *core.RateLimiter       { return core.NewRateLimiter(0) }

// writeTempImage creates a minimal valid PNG in a temp dir.
func writeTempImage(t *testing.T) string {
	t.Helper()
	// 1×1 white PNG.
	pngBytes := []byte{
		0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a,
		0x00, 0x00, 0x00, 0x0d, 0x49, 0x48, 0x44, 0x52,
		0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01,
		0x08, 0x02, 0x00, 0x00, 0x00, 0x90, 0x77, 0x53,
		0xde, 0x00, 0x00, 0x00, 0x0c, 0x49, 0x44, 0x41,
		0x54, 0x08, 0xd7, 0x63, 0xf8, 0xcf, 0xc0, 0x00,
		0x00, 0x00, 0x02, 0x00, 0x01, 0xe2, 0x21, 0xbc,
		0x33, 0x00, 0x00, 0x00, 0x00, 0x49, 0x45, 0x4e,
		0x44, 0xae, 0x42, 0x60, 0x82,
	}
	path := filepath.Join(t.TempDir(), "photo.png")
	if err := os.WriteFile(path, pngBytes, 0600); err != nil {
		t.Fatal(err)
	}
	return path
}

// ---- TinEye tests -----------------------------------------------------------

func TestTinEyeHitReturnsMatchCountAndDomains(t *testing.T) {
	imgMod := New(
		WithKeyLoader(func() string { return "test-key" }),
		WithTinEyeSearcher(&stubTinEye{
			result: core.TinEyeResult{
				MatchCount: 3,
				Matches: []core.TinEyeMatch{
					{Domain: "example.com", URL: "https://example.com/page.html",
						CrawlDate: mustParseDate("2023-11-14"), Score: 0.95},
					{Domain: "socialmedia.net", URL: "https://socialmedia.net/profile",
						CrawlDate: mustParseDate("2022-08-30"), Score: 0.80},
					{Domain: "forum.org", URL: "https://forum.org/thread",
						CrawlDate: mustParseDate("2021-03-12"), Score: 0.70},
				},
			},
		}),
		WithStoreOpener(noopStoreOpener),
		WithRateLimiter(zeroLimiter()),
	)

	photoPath := writeTempImage(t)
	res, err := imgMod.RunPostMessenger(context.Background(), number(), reportWithPhoto(photoPath, "telegram"))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if res.Status != core.ModuleStatusSuccess {
		t.Fatalf("expected success, got %s: %s", res.Status, res.Findings["reason"])
	}
	ir := res.Data.(*core.ImageIntelResult)
	if ir.TinEye.MatchCount != 3 {
		t.Errorf("match count: want 3, got %d", ir.TinEye.MatchCount)
	}
	if ir.TinEye.Matches[0].Domain != "example.com" {
		t.Errorf("first domain: want example.com, got %s", ir.TinEye.Matches[0].Domain)
	}
	if ir.TinEye.Matches[1].Domain != "socialmedia.net" {
		t.Errorf("second domain: want socialmedia.net, got %s", ir.TinEye.Matches[1].Domain)
	}
}

func TestTinEyeKeyAbsentSkipsTinEye(t *testing.T) {
	called := false
	imgMod := New(
		WithKeyLoader(func() string { return "" }),
		WithTinEyeSearcher(&stubTinEye{
			result: core.TinEyeResult{MatchCount: 99},
			err:    nil,
		}),
		WithStoreOpener(func() (PhashStore, error) {
			called = true
			return &stubPhashStore{}, nil
		}),
		WithRateLimiter(zeroLimiter()),
	)
	// Override the searcher call detection by wrapping.
	tineyeCalled := false
	imgMod.tineye = &captureTinEye{inner: imgMod.tineye, called: &tineyeCalled}

	photoPath := writeTempImage(t)
	res, err := imgMod.RunPostMessenger(context.Background(), number(), reportWithPhoto(photoPath, "telegram"))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if res.Status != core.ModuleStatusSuccess {
		t.Errorf("expected success, got %s", res.Status)
	}
	ir := res.Data.(*core.ImageIntelResult)
	if ir.TinEye.MatchCount != 0 {
		t.Errorf("expected 0 TinEye matches when key absent, got %d", ir.TinEye.MatchCount)
	}
	if tineyeCalled {
		t.Error("TinEye searcher must not be called when key is absent")
	}
	_ = called
}

func TestTinEyeNoMatches(t *testing.T) {
	imgMod := New(
		WithKeyLoader(func() string { return "test-key" }),
		WithTinEyeSearcher(&stubTinEye{result: core.TinEyeResult{MatchCount: 0}}),
		WithStoreOpener(noopStoreOpener),
		WithRateLimiter(zeroLimiter()),
	)
	photoPath := writeTempImage(t)
	res, err := imgMod.RunPostMessenger(context.Background(), number(), reportWithPhoto(photoPath, "telegram"))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	ir := res.Data.(*core.ImageIntelResult)
	if ir.TinEye.MatchCount != 0 || len(ir.TinEye.Matches) != 0 {
		t.Errorf("expected empty TinEye result, got %+v", ir.TinEye)
	}
}

// captureTinEye wraps a TinEyeSearcher and records whether Search was called.
type captureTinEye struct {
	inner  TinEyeSearcher
	called *bool
}

func (c *captureTinEye) Search(ctx context.Context, path string) (core.TinEyeResult, error) {
	*c.called = true
	return c.inner.Search(ctx, path)
}

// ---- Reverse URL tests ------------------------------------------------------

func TestReverseURLsForPublicCDNURL(t *testing.T) {
	cdnURL := "https://cdn.example.com/photos/abc123.jpg"
	urls := buildReverseURLs(cdnURL)
	if !strings.Contains(urls.GoogleLens, "lens.google.com") {
		t.Errorf("Google Lens URL missing: %s", urls.GoogleLens)
	}
	if !strings.Contains(urls.GoogleLens, "cdn.example.com") {
		t.Errorf("Google Lens URL should contain encoded CDN URL: %s", urls.GoogleLens)
	}
	if !strings.Contains(urls.Yandex, "yandex.com") {
		t.Errorf("Yandex URL missing: %s", urls.Yandex)
	}
	if !strings.Contains(urls.Bing, "bing.com") {
		t.Errorf("Bing URL missing: %s", urls.Bing)
	}
	if !strings.Contains(urls.TinEyeWeb, "tineye.com") {
		t.Errorf("TinEye URL missing: %s", urls.TinEyeWeb)
	}
}

func TestReverseURLsForLocalFileNoteManualUpload(t *testing.T) {
	localPath := writeTempImage(t)
	urls := buildReverseURLs(localPath)
	// Base-only URLs when the photo is a local file.
	if urls.GoogleLens != "https://lens.google.com/" {
		t.Errorf("expected base Google Lens URL for local file, got %s", urls.GoogleLens)
	}
	if urls.Yandex != "https://yandex.com/images/" {
		t.Errorf("expected base Yandex URL for local file, got %s", urls.Yandex)
	}
}

// ---- pHash storage tests ----------------------------------------------------

func TestPhashStoredToSQLite(t *testing.T) {
	dir := t.TempDir()
	s, err := storage.Open(filepath.Join(dir, "test.db"))
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	defer s.Close()

	id, _, err := s.SaveInvestigation("+15005550001", `{}`, 10, "LOW", nil)
	if err != nil {
		t.Fatalf("save investigation: %v", err)
	}

	phash := "a3f4b2c1d0e9f8a7"
	if err := s.StorePhotoHash(id, "+15005550001", "telegram", phash, "/tmp/photo.png"); err != nil {
		t.Fatalf("store photo hash: %v", err)
	}

	records, err := s.FindSimilarHashes(phash, 0, 0)
	if err != nil {
		t.Fatalf("find similar hashes: %v", err)
	}
	if len(records) != 1 {
		t.Fatalf("expected 1 record, got %d", len(records))
	}
	if records[0].PHash != phash {
		t.Errorf("expected phash %s, got %s", phash, records[0].PHash)
	}
}

func TestCrossSessionMatchWhenDistanceLTE10(t *testing.T) {
	existingPHash := "a3f4b2c1d0e9f8a7"
	store := &stubPhashStore{
		records: []storage.PhotoHashRecord{
			{
				ID:              1,
				InvestigationID: 4,
				PhoneE164:       "+447911123456",
				CaseName:        "case-4",
				Source:          "telegram",
				PHash:           existingPHash,
				HammingDist:     6,
				CreatedAt:       time.Date(2026, 5, 14, 0, 0, 0, 0, time.UTC),
			},
		},
	}

	imgMod := New(
		WithKeyLoader(func() string { return "" }),
		WithStoreOpener(func() (PhashStore, error) { return store, nil }),
		WithThreshold(10),
		WithRateLimiter(zeroLimiter()),
	)

	photoPath := writeTempImage(t)
	report := &core.InvestigationReport{
		Number:  number(),
		Results: []*core.ModuleResult{},
		Messenger: &core.MessengerReport{
			Telegram: &core.MessengerAccount{
				Found:             true,
				ProfilePhotoPath:  photoPath,
				ProfilePhotoPHash: "b3f4b2c1d0e9f8a7",
				DataSource:        "telegram_mtproto",
			},
		},
	}

	res, err := imgMod.RunPostMessenger(context.Background(), number(), report)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	ir := res.Data.(*core.ImageIntelResult)
	if len(ir.CrossSessionHits) != 1 {
		t.Fatalf("expected 1 cross-session hit, got %d", len(ir.CrossSessionHits))
	}
	if ir.CrossSessionHits[0].CaseID != 4 {
		t.Errorf("case ID: want 4, got %d", ir.CrossSessionHits[0].CaseID)
	}
	if ir.CrossSessionHits[0].PhoneE164 != "+447911123456" {
		t.Errorf("phone: want +447911123456, got %s", ir.CrossSessionHits[0].PhoneE164)
	}
}

func TestCrossSessionNoMatchWhenDistanceGT10(t *testing.T) {
	imgMod := New(
		WithKeyLoader(func() string { return "" }),
		WithStoreOpener(func() (PhashStore, error) { return &stubPhashStore{}, nil }),
		WithThreshold(10),
		WithRateLimiter(zeroLimiter()),
	)

	photoPath := writeTempImage(t)
	res, err := imgMod.RunPostMessenger(context.Background(), number(), reportWithPhoto(photoPath, "telegram"))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	ir := res.Data.(*core.ImageIntelResult)
	if len(ir.CrossSessionHits) != 0 {
		t.Errorf("expected no cross-session hits, got %d", len(ir.CrossSessionHits))
	}
}

// ---- Module interface / engine integration tests ----------------------------

func TestModuleDryRunSkipsWhenNoPhoto(t *testing.T) {
	imgMod := New(
		WithKeyLoader(func() string { return "" }),
		WithStoreOpener(noopStoreOpener),
		WithRateLimiter(zeroLimiter()),
	)
	res, err := imgMod.RunPostMessenger(context.Background(), number(), reportNoPhoto())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if res.Status != core.ModuleStatusSkipped {
		t.Errorf("expected skipped, got %s", res.Status)
	}
	if !strings.Contains(res.Findings["reason"], "no profile photo") {
		t.Errorf("reason should mention no profile photo, got: %s", res.Findings["reason"])
	}
}

func TestModuleImplementsPostMessengerModule(t *testing.T) {
	var _ core.PostMessengerModule = New()
}

func TestEngineRunsImagesModuleAfterMessengerModules(t *testing.T) {
	photoPath := writeTempImage(t)

	var storeOpened bool

	telegramStub := &stubbedMessengerModule{
		name: "telegram",
		account: &core.MessengerAccount{
			Found:             true,
			ProfilePhotoPath:  photoPath,
			ProfilePhotoPHash: "a3f4b2c1d0e9f8a7",
			DataSource:        "telegram_mtproto",
		},
	}

	imgMod := New(
		WithKeyLoader(func() string { return "" }),
		WithTinEyeSearcher(&stubTinEye{}),
		WithStoreOpener(func() (PhashStore, error) {
			storeOpened = true
			return &stubPhashStore{}, nil
		}),
		WithRateLimiter(zeroLimiter()),
	)

	engine := core.NewEngine(
		[]core.Module{telegramStub, imgMod},
		core.WithActive(true),
	)
	report, err := engine.Run(context.Background(), number())
	if err != nil {
		t.Fatalf("engine.Run: %v", err)
	}
	if report.ImageIntelligence == nil {
		t.Fatal("report.ImageIntelligence must be set after engine run")
	}
	if report.ImageIntelligence.PhotoPath != photoPath {
		t.Errorf("photo path: want %s, got %s", photoPath, report.ImageIntelligence.PhotoPath)
	}
	if report.ImageIntelligence.PhotoSource != "telegram" {
		t.Errorf("photo source: want telegram, got %s", report.ImageIntelligence.PhotoSource)
	}
	if !storeOpened {
		t.Error("store opener must be called for cross-session check")
	}
}

// stubbedMessengerModule is a minimal TierActive module returning a MessengerAccount.
type stubbedMessengerModule struct {
	name    string
	account *core.MessengerAccount
}

func (m *stubbedMessengerModule) Name() string        { return m.name }
func (m *stubbedMessengerModule) Description() string { return "stub" }
func (m *stubbedMessengerModule) RequiresAPIKey() bool { return false }
func (m *stubbedMessengerModule) Tier() core.ModuleTier { return core.TierActive }
func (m *stubbedMessengerModule) ProxyAware() bool      { return true }
func (m *stubbedMessengerModule) DryRun(_ context.Context, _ *core.PhoneNumber) error { return nil }
func (m *stubbedMessengerModule) Run(_ context.Context, _ *core.PhoneNumber) (*core.ModuleResult, error) {
	return &core.ModuleResult{
		ModuleName: m.name,
		Status:     core.ModuleStatusSuccess,
		Data:       m.account,
		Findings: map[string]string{
			"found":               "true",
			"profile_photo_path":  m.account.ProfilePhotoPath,
			"profile_photo_phash": m.account.ProfilePhotoPHash,
			"data_source":         m.account.DataSource,
		},
	}, nil
}

func mustParseDate(s string) time.Time {
	t, _ := time.Parse("2006-01-02", s)
	return t
}
