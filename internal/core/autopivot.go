package core

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"time"
)

const AutoPivotConfidenceThreshold = 0.65

type PivotChainNode struct {
	Type            string           `json:"type"`
	Value           string           `json:"value"`
	Label           string           `json:"label,omitempty"`
	Confidence      float64          `json:"confidence,omitempty"`
	ConfidenceLabel string           `json:"confidence_label,omitempty"`
	Source          string           `json:"source,omitempty"`
	URL             string           `json:"url,omitempty"`
	Depth           int              `json:"depth"`
	Children        []*PivotChainNode `json:"children,omitempty"`
}

type UsernameProfileHit struct {
	Platform   string
	URL        string
	Source     string
	Confidence float64
}

type LinkedInvestigation struct {
	ParentType  string
	ParentValue string
	Depth       int
	Report      *InvestigationReport
	Children    []*LinkedInvestigation
}

type AutoPivotResult struct {
	Chain  *PivotChainNode
	Linked []*LinkedInvestigation
}

type UsernameSearcher func(ctx context.Context, username string) ([]UsernameProfileHit, error)

type AutoPivotEngine struct {
	maxDepth        int
	minConfidence   float64
	delay           time.Duration
	usernameSearch  UsernameSearcher
	reportTimestamp func() time.Time
}

type AutoPivotOption func(*AutoPivotEngine)

func NewAutoPivotEngine(opts ...AutoPivotOption) *AutoPivotEngine {
	engine := &AutoPivotEngine{
		maxDepth:        0,
		minConfidence:   AutoPivotConfidenceThreshold,
		delay:           2 * time.Second,
		reportTimestamp: time.Now,
	}
	for _, opt := range opts {
		opt(engine)
	}
	if engine.maxDepth < 0 {
		engine.maxDepth = 0
	}
	if engine.maxDepth > 3 {
		engine.maxDepth = 3
	}
	if engine.minConfidence <= 0 {
		engine.minConfidence = AutoPivotConfidenceThreshold
	}
	if engine.delay < 0 {
		engine.delay = 0
	}
	if engine.reportTimestamp == nil {
		engine.reportTimestamp = time.Now
	}
	return engine
}

func WithAutoPivotDepth(depth int) AutoPivotOption {
	return func(engine *AutoPivotEngine) {
		if depth < 0 {
			depth = 0
		}
		if depth > 3 {
			depth = 3
		}
		engine.maxDepth = depth
	}
}

func WithAutoPivotDelay(delay time.Duration) AutoPivotOption {
	return func(engine *AutoPivotEngine) {
		engine.delay = delay
	}
}

func WithAutoPivotUsernameSearcher(searcher UsernameSearcher) AutoPivotOption {
	return func(engine *AutoPivotEngine) {
		engine.usernameSearch = searcher
	}
}

func WithAutoPivotTimeSource(now func() time.Time) AutoPivotOption {
	return func(engine *AutoPivotEngine) {
		if now != nil {
			engine.reportTimestamp = now
		}
	}
}

func (e *AutoPivotEngine) Run(ctx context.Context, report *InvestigationReport) (*AutoPivotResult, error) {
	if report == nil {
		return &AutoPivotResult{}, nil
	}
	root := &PivotChainNode{
		Type:     "phone",
		Value:    reportNumber(report),
		Depth:    0,
		Source:   "primary",
		Children: []*PivotChainNode{},
	}
	if e.maxDepth <= 0 {
		report.PivotChain = root
		return &AutoPivotResult{Chain: root}, nil
	}

	visited := map[string]bool{}
	result := &AutoPivotResult{
		Chain:  root,
		Linked: []*LinkedInvestigation{},
	}

	if report.IdentityGraph == nil || len(report.IdentityGraph.PivotPoints) == 0 {
		report.PivotChain = root
		return result, nil
	}

	children, linked, err := e.expandReport(ctx, report, root, visited, 1)
	if err != nil {
		return nil, err
	}
	root.Children = children
	result.Linked = append(result.Linked, linked...)
	report.PivotChain = root
	return result, nil
}

func (e *AutoPivotEngine) expandReport(ctx context.Context, report *InvestigationReport, parent *PivotChainNode, visited map[string]bool, depth int) ([]*PivotChainNode, []*LinkedInvestigation, error) {
	if report == nil || report.IdentityGraph == nil || depth > e.maxDepth {
		return nil, nil, nil
	}

	pivots := append([]IdentityPivot(nil), report.IdentityGraph.PivotPoints...)
	sort.SliceStable(pivots, func(i, j int) bool {
		if pivots[i].Type == pivots[j].Type {
			return strings.ToLower(pivots[i].Value) < strings.ToLower(pivots[j].Value)
		}
		return pivots[i].Type < pivots[j].Type
	})

	nodes := make([]*PivotChainNode, 0, len(pivots))
	linked := make([]*LinkedInvestigation, 0)
	for _, pivot := range pivots {
		if depth > e.maxDepth {
			break
		}
		if !strings.EqualFold(pivot.Type, "email") && !strings.EqualFold(pivot.Type, "username") {
			continue
		}
		confidence := confidenceScore(pivot.Confidence)
		if confidence < e.minConfidence {
			continue
		}
		key := pivotKey(pivot.Type, pivot.Value)
		node := &PivotChainNode{
			Type:            strings.ToLower(strings.TrimSpace(pivot.Type)),
			Value:           cleanPivotValue(pivot.Value),
			Confidence:      confidence,
			ConfidenceLabel: pivot.Confidence,
			Source:          strings.Join(pivot.Modules, ", "),
			Depth:           depth,
		}
		if node.Value == "" {
			continue
		}
		if visited[key] {
			node.Label = "duplicate pivot skipped"
			nodes = append(nodes, node)
			continue
		}
		visited[key] = true

		switch node.Type {
		case "email":
			node.Label = fmt.Sprintf("→ Pivot: mailaccess investigate %s", node.Value)
			nodes = append(nodes, node)
		case "username":
			if e.usernameSearch == nil {
				node.Label = "username search unavailable"
				nodes = append(nodes, node)
				continue
			}
			if err := e.wait(ctx); err != nil {
				return nil, nil, err
			}
			hits, err := e.usernameSearch(ctx, node.Value)
			if err != nil {
				node.Label = "username search failed: " + err.Error()
				nodes = append(nodes, node)
				continue
			}
			childReport := e.buildUsernameReport(report, pivot, hits)
			item := &LinkedInvestigation{
				ParentType:  parent.Type,
				ParentValue: parent.Value,
				Depth:       depth,
				Report:      childReport,
			}
			node.Children = usernameHitNodes(hits, depth+1)
			if len(node.Children) > 0 {
				node.Label = fmt.Sprintf("verified on %d platform(s)", len(node.Children))
			} else {
				node.Label = "no verified platforms found"
			}
			nodes = append(nodes, node)
			if depth < e.maxDepth && childReport != nil && childReport.IdentityGraph != nil && len(childReport.IdentityGraph.PivotPoints) > 0 {
				grandChildren, grandLinked, err := e.expandReport(ctx, childReport, node, visited, depth+1)
				if err != nil {
					return nil, nil, err
				}
				node.Children = append(node.Children, grandChildren...)
				item.Children = grandLinked
			}
			linked = append(linked, item)
		}
	}

	return nodes, linked, nil
}

func (e *AutoPivotEngine) buildUsernameReport(parent *InvestigationReport, pivot IdentityPivot, hits []UsernameProfileHit) *InvestigationReport {
	if parent == nil {
		return nil
	}
	platforms := make([]string, 0, len(hits))
	for _, hit := range hits {
		if strings.TrimSpace(hit.Platform) == "" {
			continue
		}
		platforms = append(platforms, hit.Platform)
	}
	findings := map[string]string{
		"pivot_type":       "username",
		"pivot_value":      cleanPivotValue(pivot.Value),
		"platforms_found":  strings.Join(platforms, ", "),
		"platform_count":   fmt.Sprintf("%d", len(platforms)),
		"investigated_at":  e.reportTimestamp().UTC().Format(time.RFC3339),
	}
	for i, hit := range hits {
		if strings.TrimSpace(hit.URL) == "" {
			continue
		}
		findings[fmt.Sprintf("platform_%d_url", i+1)] = hit.URL
	}
	var data any = map[string]any{
		"pivot": map[string]any{
			"type":       "username",
			"value":      cleanPivotValue(pivot.Value),
			"confidence": confidenceScore(pivot.Confidence),
		},
		"hits": hits,
	}
	child := &InvestigationReport{
		GeneratedAt:   e.reportTimestamp().UTC(),
		Passive:       parent.Passive,
		Number:        parent.Number,
		Results: []*ModuleResult{
			{
				ModuleName: "autopivot",
				Status:     ModuleStatusSuccess,
				Findings:   findings,
				Data:       data,
				Evidence:   platformEvidence(hits),
			},
		},
	}
	child.IdentityGraph = BuildIdentityGraph(child)
	child.RiskScore = ScoreRisk(child)
	child.PivotChain = &PivotChainNode{
		Type:            "username",
		Value:           cleanPivotValue(pivot.Value),
		Confidence:      confidenceScore(pivot.Confidence),
		ConfidenceLabel: pivot.Confidence,
		Source:          strings.Join(pivot.Modules, ", "),
		Depth:           0,
		Children:        usernameHitNodes(hits, 1),
	}
	return child
}

func (e *AutoPivotEngine) wait(ctx context.Context) error {
	if e.delay <= 0 {
		return nil
	}
	timer := time.NewTimer(e.delay)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}

func usernameHitNodes(hits []UsernameProfileHit, depth int) []*PivotChainNode {
	nodes := make([]*PivotChainNode, 0, len(hits))
	for _, hit := range hits {
		if strings.TrimSpace(hit.Platform) == "" {
			continue
		}
		nodes = append(nodes, &PivotChainNode{
			Type:            "platform",
			Value:           hit.Platform,
			URL:             hit.URL,
			Confidence:      hit.Confidence,
			ConfidenceLabel: "verified",
			Source:          hit.Source,
			Depth:           depth,
			Label:           "profile_found",
		})
	}
	return nodes
}

func platformEvidence(hits []UsernameProfileHit) []string {
	if len(hits) == 0 {
		return nil
	}
	evidence := make([]string, 0, len(hits))
	for _, hit := range hits {
		line := strings.TrimSpace(hit.Platform)
		if line == "" {
			continue
		}
		if strings.TrimSpace(hit.URL) != "" {
			line += ": " + hit.URL
		}
		evidence = append(evidence, line)
	}
	return evidence
}

func reportNumber(report *InvestigationReport) string {
	if report == nil || report.Number == nil {
		return ""
	}
	return firstNonEmpty(report.Number.E164, report.Number.RawInput)
}

func pivotKey(kind, value string) string {
	kind = strings.ToLower(strings.TrimSpace(kind))
	value = cleanPivotValue(value)
	if kind == "username" {
		value = strings.TrimPrefix(strings.ToLower(value), "@")
	}
	return kind + ":" + strings.ToLower(value)
}

func confidenceScore(label string) float64 {
	switch strings.ToLower(strings.TrimSpace(label)) {
	case "high":
		return 0.90
	case "medium":
		return 0.75
	case "inference":
		return 0.65
	case "low":
		return 0.55
	default:
		return 0
	}
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return strings.TrimSpace(value)
		}
	}
	return ""
}
