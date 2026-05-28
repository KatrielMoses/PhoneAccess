package exporters

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/KatrielMoses/PhoneAccess/internal/core"
)

type GEXFExporter struct{}

func (GEXFExporter) Format() string {
	return "gexf"
}

func (GEXFExporter) Export(report *core.InvestigationReport, w io.Writer) error {
	if w == nil {
		return errors.New("export gexf: writer is nil")
	}
	data, err := marshalGEXF(report)
	if err != nil {
		return err
	}
	_, err = w.Write(data)
	return err
}

type gexfNode struct {
	ID         string
	Label      string
	Type       string
	Confidence  string
	Source     string
	FirstSeen  string
	Color      [3]int
}

type gexfEdge struct {
	ID     string
	Source string
	Target string
	Label  string
	Weight string
}

type gexfGraph struct {
	nodes    map[string]*gexfNode
	nodeIDs  map[string]string
	edges    map[string]*gexfEdge
	order    []string
	edgeSeq  int
	nodeSeq  int
}

func marshalGEXF(report *core.InvestigationReport) ([]byte, error) {
	graph := newGEXFGraph()
	populateGEXFGraph(graph, report)

	var b strings.Builder
	b.WriteString(xmlHeader())
	b.WriteString(`<gexf xmlns="http://www.gexf.net/1.3" xmlns:viz="http://www.gexf.net/1.3/viz" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:schemaLocation="http://www.gexf.net/1.3 http://gexf.net/1.3/gexf.xsd" version="1.3">`)
	b.WriteString("<meta lastmodifieddate=\"")
	b.WriteString(escapeXML(time.Now().UTC().Format("2006-01-02")))
	b.WriteString("\"><creator>PhoneAccess</creator><description>")
	b.WriteString(escapeXML("PhoneAccess investigation graph export"))
	b.WriteString("</description></meta>")
	b.WriteString(`<graph mode="static" defaultedgetype="directed">`)
	b.WriteString(`<attributes class="node">`)
	for i, attr := range []struct {
		title string
		typ   string
	}{
		{"id", "string"},
		{"label", "string"},
		{"type", "string"},
		{"confidence", "string"},
		{"source", "string"},
		{"first_seen", "string"},
	} {
		b.WriteString(fmt.Sprintf(`<attribute id="%d" title="%s" type="%s"/>`, i, escapeXML(attr.title), escapeXML(attr.typ)))
	}
	b.WriteString(`</attributes>`)
	b.WriteString("<nodes>")
	nodeKeys := make([]string, 0, len(graph.order))
	nodeKeys = append(nodeKeys, graph.order...)
	sort.Strings(nodeKeys)
	for _, key := range nodeKeys {
		node := graph.nodes[key]
		b.WriteString(`<node id="`)
		b.WriteString(escapeXML(node.ID))
		b.WriteString(`" label="`)
		b.WriteString(escapeXML(node.Label))
		b.WriteString(`">`)
		b.WriteString("<attvalues>")
		attvals := []string{node.ID, node.Label, node.Type, node.Confidence, node.Source, node.FirstSeen}
		for i, value := range attvals {
			if strings.TrimSpace(value) == "" {
				continue
			}
			b.WriteString(fmt.Sprintf(`<attvalue for="%d" value="%s"/>`, i, escapeXML(value)))
		}
		b.WriteString("</attvalues>")
		b.WriteString(fmt.Sprintf(`<viz:color r="%d" g="%d" b="%d"/>`, node.Color[0], node.Color[1], node.Color[2]))
		b.WriteString("</node>")
	}
	b.WriteString("</nodes><edges>")
	edgeKeys := make([]string, 0, len(graph.edges))
	for key := range graph.edges {
		edgeKeys = append(edgeKeys, key)
	}
	sort.Strings(edgeKeys)
	for _, key := range edgeKeys {
		edge := graph.edges[key]
		b.WriteString(`<edge id="`)
		b.WriteString(escapeXML(edge.ID))
		b.WriteString(`" source="`)
		b.WriteString(escapeXML(edge.Source))
		b.WriteString(`" target="`)
		b.WriteString(escapeXML(edge.Target))
		b.WriteString(`" label="`)
		b.WriteString(escapeXML(edge.Label))
		b.WriteString(`" weight="`)
		b.WriteString(escapeXML(edge.Weight))
		b.WriteString(`"/>`)
	}
	b.WriteString("</edges></graph></gexf>")
	return []byte(b.String() + "\n"), nil
}

func newGEXFGraph() *gexfGraph {
	return &gexfGraph{
		nodes:   map[string]*gexfNode{},
		nodeIDs: map[string]string{},
		edges:   map[string]*gexfEdge{},
		order:   []string{},
	}
}

func populateGEXFGraph(g *gexfGraph, report *core.InvestigationReport) {
	if g == nil {
		return
	}
	phone := ""
	if report != nil && report.Number != nil {
		phone = firstNonEmpty(report.Number.E164, report.Number.RawInput)
	}
	rootID := ""
	if phone != "" {
		rootID = g.addNode("phone", phone, "primary", 1, reportTime(report), "")
	}

	identityIDs := []string{}
	bestIdentity := ""
	if report != nil && report.IdentityGraph != nil {
		for _, pivot := range report.IdentityGraph.PivotPoints {
			kind := strings.ToLower(strings.TrimSpace(pivot.Type))
			switch kind {
			case "name":
				id := g.addNode("identity", pivot.Value, strings.Join(pivot.Modules, ", "), pivotConfidence(pivot.Confidence), reportTime(report), "")
				if id != "" {
					identityIDs = append(identityIDs, id)
					if rootID != "" {
						g.addEdge(rootID, id, "reverse_lookup", pivotConfidence(pivot.Confidence))
					}
					if bestIdentity == "" {
						bestIdentity = id
					}
				}
			case "email":
				id := g.addNode("email", pivot.Value, strings.Join(pivot.Modules, ", "), pivotConfidence(pivot.Confidence), reportTime(report), "")
				if id != "" && len(identityIDs) > 0 {
					for _, identityID := range identityIDs {
						g.addEdge(identityID, id, "associated_email", pivotConfidence(pivot.Confidence))
					}
				}
			case "username":
				id := g.addNode("username", pivot.Value, strings.Join(pivot.Modules, ", "), pivotConfidence(pivot.Confidence), reportTime(report), "")
				if id != "" && len(identityIDs) > 0 {
					for _, identityID := range identityIDs {
						g.addEdge(identityID, id, "associated_username", pivotConfidence(pivot.Confidence))
					}
				}
			}
		}
	}
	if bestIdentity == "" && len(identityIDs) > 0 {
		bestIdentity = identityIDs[0]
	}

	if platforms := enumeratorPlatformHits(report); len(platforms) > 0 && rootID != "" {
		for _, platform := range platforms {
			id := g.addNode("platform", platform, "enumerator", 1, reportTime(report), "")
			if id != "" {
				g.addEdge(rootID, id, "registered_on", 1)
			}
		}
	}

	if report != nil {
		for _, breach := range gexfBreachNames(report) {
			id := g.addNode("breach", breach, "breach", 0.8, reportTime(report), "")
			if id != "" && rootID != "" {
				g.addEdge(rootID, id, "found_in", 0.8)
			}
		}
		for _, org := range organizationNames(report) {
			g.addNode("organization", org, "public_records", 0.6, reportTime(report), "")
		}
	}

	walkPivotChainForGEXF(g, report, bestIdentity, rootID)
}

func walkPivotChainForGEXF(g *gexfGraph, report *core.InvestigationReport, identityID, rootID string) {
	if g == nil || report == nil || report.PivotChain == nil {
		return
	}
	var walk func(parent *core.PivotChainNode, parentID string)
	walk = func(parent *core.PivotChainNode, parentID string) {
		if parent == nil {
			return
		}
		for _, child := range parent.Children {
			if child == nil {
				continue
			}
			switch strings.ToLower(strings.TrimSpace(child.Type)) {
			case "username":
				id := g.addNode("username", child.Value, child.Source, child.Confidence, reportTime(report), "")
				if id == "" {
					continue
				}
				nextParent := id
				if identityID != "" {
					g.addEdge(identityID, id, "associated_username", child.Confidence)
				}
				if strings.TrimSpace(child.Label) == "duplicate pivot skipped" || strings.TrimSpace(child.Label) == "username search unavailable" {
					continue
				}
				for _, platform := range child.Children {
					if platform == nil || strings.ToLower(strings.TrimSpace(platform.Type)) != "platform" {
						continue
					}
					pid := g.addNode("platform", platform.Value, platform.Source, platform.Confidence, reportTime(report), platform.URL)
					if pid != "" {
						g.addEdge(nextParent, pid, "profile_found", platform.Confidence)
					}
				}
			case "email":
				id := g.addNode("email", child.Value, child.Source, child.Confidence, reportTime(report), "")
				if id != "" && identityID != "" {
					g.addEdge(identityID, id, "associated_email", child.Confidence)
				}
			}
			if len(child.Children) > 0 {
				walk(child, identityID)
			}
		}
	}
	walk(report.PivotChain, rootID)
}

func (g *gexfGraph) addNode(kind, label, source string, confidence float64, firstSeen, url string) string {
	kind = strings.ToLower(strings.TrimSpace(kind))
	label = strings.TrimSpace(label)
	if kind == "" || label == "" {
		return ""
	}
	key := kind + "|" + strings.ToLower(label) + "|" + strings.ToLower(strings.TrimSpace(url))
	if id, ok := g.nodeIDs[key]; ok {
		return id
	}
	g.nodeSeq++
	id := "n" + strconv.Itoa(g.nodeSeq)
	g.nodeIDs[key] = id
	g.order = append(g.order, key)
	g.nodes[key] = &gexfNode{
		ID:        id,
		Label:     label,
		Type:      kind,
		Confidence: fmt.Sprintf("%.2f", confidence),
		Source:    source,
		FirstSeen: firstSeen,
		Color:     gexfColorForType(kind),
	}
	return id
}

func (g *gexfGraph) addEdge(source, target, label string, weight float64) {
	if strings.TrimSpace(source) == "" || strings.TrimSpace(target) == "" {
		return
	}
	key := source + "|" + target + "|" + label
	if _, ok := g.edges[key]; ok {
		return
	}
	g.edgeSeq++
	g.edges[key] = &gexfEdge{
		ID:     "e" + strconv.Itoa(g.edgeSeq),
		Source: source,
		Target: target,
		Label:  label,
		Weight: fmt.Sprintf("%.2f", weight),
	}
}

func gexfColorForType(kind string) [3]int {
	switch strings.ToLower(strings.TrimSpace(kind)) {
	case "phone":
		return [3]int{255, 0, 0}
	case "identity":
		return [3]int{0, 102, 255}
	case "platform":
		return [3]int{0, 153, 0}
	case "breach":
		return [3]int{255, 153, 0}
	case "email":
		return [3]int{153, 0, 204}
	case "organization":
		return [3]int{204, 204, 0}
	case "username":
		return [3]int{64, 128, 255}
	default:
		return [3]int{128, 128, 128}
	}
}

func reportTime(report *core.InvestigationReport) string {
	if report == nil || report.GeneratedAt.IsZero() {
		return ""
	}
	return report.GeneratedAt.UTC().Format(time.RFC3339)
}

func pivotConfidence(label string) float64 {
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

func enumeratorPlatformHits(report *core.InvestigationReport) []string {
	result := moduleResult(report, "enumerator")
	if result == nil || result.Findings == nil {
		return nil
	}
	hits := strings.TrimSpace(result.Findings["hits"])
	if hits == "" {
		return nil
	}
	lines := strings.Split(hits, "\n")
	platforms := map[string]string{}
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "[") {
			continue
		}
		platform := line
		if idx := strings.Index(platform, " ("); idx >= 0 {
			platform = platform[:idx]
		}
		platform = strings.TrimSpace(platform)
		if platform != "" {
			platforms[strings.ToLower(platform)] = platform
		}
	}
	out := make([]string, 0, len(platforms))
	for _, platform := range platforms {
		out = append(out, platform)
	}
	sort.Strings(out)
	return out
}

func gexfBreachNames(report *core.InvestigationReport) []string {
	result := moduleResult(report, "breach")
	if result == nil {
		return nil
	}
	var decoded struct {
		Breaches []struct {
			Name     string `json:"name"`
			SourceAPI string `json:"source_api"`
		} `json:"breaches"`
	}
	if result.Data != nil {
		if raw, err := json.Marshal(result.Data); err == nil {
			_ = json.Unmarshal(raw, &decoded)
		}
	}
	if len(decoded.Breaches) == 0 {
		lines := splitLines(result.Findings["breaches"])
		out := make([]string, 0, len(lines))
		for _, line := range lines {
			if idx := strings.Index(line, " ["); idx >= 0 {
				line = line[:idx]
			}
			line = strings.TrimSpace(line)
			if line != "" {
				out = append(out, line)
			}
		}
		return uniqueSorted(out)
	}
	out := make([]string, 0, len(decoded.Breaches))
	for _, breach := range decoded.Breaches {
		if strings.TrimSpace(breach.Name) != "" {
			out = append(out, strings.TrimSpace(breach.Name))
		}
	}
	return uniqueSorted(out)
}

func organizationNames(report *core.InvestigationReport) []string {
	result := moduleResult(report, "public_records")
	if result == nil {
		return nil
	}
	var decoded struct {
		EdgarHits []struct {
			EntityName string `json:"entity_name"`
		} `json:"edgar_hits"`
		OpencorpHits []struct {
			Company string `json:"company"`
		} `json:"opencorp_hits"`
		CompaniesHouseHits []struct {
			CompanyName string `json:"company_name"`
		} `json:"companies_house_hits"`
		LicenseHits []struct {
			Name string `json:"name"`
		} `json:"license_hits"`
		Names []string `json:"names"`
	}
	if result.Data != nil {
		if raw, err := json.Marshal(result.Data); err == nil {
			_ = json.Unmarshal(raw, &decoded)
		}
	}
	seen := map[string]string{}
	add := func(value string) {
		value = strings.TrimSpace(value)
		if value == "" {
			return
		}
		seen[strings.ToLower(value)] = value
	}
	for _, hit := range decoded.EdgarHits {
		add(hit.EntityName)
	}
	for _, hit := range decoded.OpencorpHits {
		add(hit.Company)
	}
	for _, hit := range decoded.CompaniesHouseHits {
		add(hit.CompanyName)
	}
	for _, hit := range decoded.LicenseHits {
		add(hit.Name)
	}
	for _, name := range decoded.Names {
		add(name)
	}
	out := make([]string, 0, len(seen))
	for _, name := range seen {
		out = append(out, name)
	}
	sort.Strings(out)
	return out
}

func splitLines(value string) []string {
	lines := strings.Split(value, "\n")
	out := make([]string, 0, len(lines))
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line != "" {
			out = append(out, line)
		}
	}
	return out
}

func xmlHeader() string {
	return "<?xml version=\"1.0\" encoding=\"UTF-8\"?>"
}

func escapeXML(value string) string {
	return xmlEscapeString(value)
}

func xmlEscapeString(value string) string {
	var b strings.Builder
	for _, r := range value {
		switch r {
		case '&':
			b.WriteString("&amp;")
		case '<':
			b.WriteString("&lt;")
		case '>':
			b.WriteString("&gt;")
		case '"':
			b.WriteString("&quot;")
		case '\'':
			b.WriteString("&apos;")
		default:
			if r < 32 && r != '\n' && r != '\t' && r != '\r' {
				continue
			}
			b.WriteRune(r)
		}
	}
	return b.String()
}
