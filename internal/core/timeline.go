package core

import (
	"encoding/json"
	"strconv"
	"sort"
	"strings"
	"time"
)

type Timeline struct {
	FirstSeen  string          `json:"first_seen,omitempty"`
	MostRecent string          `json:"most_recent,omitempty"`
	Events     []TimelineEvent `json:"events"`
}

type TimelineEvent struct {
	Date        string `json:"date"`
	Source      string `json:"source"`
	EventType   string `json:"event_type"`
	Description string `json:"description"`
	Confidence  string `json:"confidence"`
}

type timelineEvent struct {
	TimelineEvent
	sortTime  time.Time
	hasDate   bool
	sourceKey string
}

func BuildTimeline(report *InvestigationReport) *Timeline {
	timeline := &Timeline{Events: []TimelineEvent{}}
	if report == nil {
		return timeline
	}

	events := []timelineEvent{}
	add := func(date, source, eventType, description, confidence string) {
		date = strings.TrimSpace(date)
		source = strings.TrimSpace(source)
		eventType = strings.TrimSpace(eventType)
		description = strings.TrimSpace(description)
		if source == "" || eventType == "" || description == "" {
			return
		}
		event := timelineEvent{
			TimelineEvent: TimelineEvent{
				Date:        date,
				Source:      source,
				EventType:   eventType,
				Description: description,
				Confidence:  confidence,
			},
			sourceKey: strings.ToLower(source + "|" + eventType + "|" + date + "|" + description),
		}
		if parsed, ok := parseTimelineDate(date); ok {
			event.sortTime = parsed
			event.hasDate = true
		}
		events = append(events, event)
	}

	for _, result := range report.Results {
		if result == nil {
			continue
		}
		collectTimelineFromModule(result, report, add)
	}
	collectTimelineFromMessenger(report.Messenger, report, add)

	sort.SliceStable(events, func(i, j int) bool {
		switch {
		case events[i].hasDate && events[j].hasDate:
			if events[i].sortTime.Equal(events[j].sortTime) {
				return events[i].sourceKey < events[j].sourceKey
			}
			return events[i].sortTime.Before(events[j].sortTime)
		case events[i].hasDate:
			return true
		case events[j].hasDate:
			return false
		default:
			return events[i].sourceKey < events[j].sourceKey
		}
	})

	seen := map[string]bool{}
	outEvents := make([]TimelineEvent, 0, len(events))
	for _, event := range events {
		if seen[event.sourceKey] {
			continue
		}
		seen[event.sourceKey] = true
		outEvents = append(outEvents, event.TimelineEvent)
		if event.hasDate {
			if timeline.FirstSeen == "" {
				timeline.FirstSeen = event.Date
			}
			timeline.MostRecent = event.Date
		}
	}
	timeline.Events = outEvents
	return timeline
}

func collectTimelineFromModule(result *ModuleResult, report *InvestigationReport, add func(date, source, eventType, description, confidence string)) {
	if result == nil {
		return
	}
	switch strings.ToLower(result.ModuleName) {
	case "breach":
		collectBreachTimeline(result.Data, add)
	case "search":
		collectSearchTimeline(result.Data, add)
	case "paste":
		collectPasteTimeline(result.Data, add)
	case "reverse":
		collectReverseTimeline(result.Data, add)
	}
}

func collectBreachTimeline(data any, add func(date, source, eventType, description, confidence string)) {
	var payload struct {
		Breaches []struct {
			Name        string `json:"name"`
			Date        string `json:"date"`
			SourceAPI   string `json:"source_api"`
			DataClasses []string `json:"data_classes"`
		} `json:"breaches"`
		MostRecentBreach string `json:"most_recent_breach"`
		SourceStatuses   map[string]string `json:"source_statuses"`
	}
	if !decodeTimelineData(data, &payload) {
		return
	}
	for _, breach := range payload.Breaches {
		source := firstNonEmptyTimeline(breach.SourceAPI, "breach")
		description := breach.Name
		if description == "" {
			description = "breach entry"
		}
		if len(breach.DataClasses) > 0 {
			description += " [" + strings.Join(breach.DataClasses, ", ") + "]"
		}
		add(breach.Date, source, "breach", description, "high")
	}
	if payload.MostRecentBreach != "" {
		add(payload.MostRecentBreach, "breach", "most_recent_breach", "most recent breach activity", "high")
	}
}

func collectSearchTimeline(data any, add func(date, source, eventType, description, confidence string)) {
	var payload struct {
		Hits []struct {
			Title         string `json:"title"`
			Snippet       string `json:"snippet"`
			URL           string `json:"url"`
			Source        string `json:"source"`
			QueryCategory  string `json:"query_category"`
			RetrievedAt   string `json:"retrieved_at"`
		} `json:"hits"`
	}
	if !decodeTimelineData(data, &payload) {
		return
	}
	for _, hit := range payload.Hits {
		desc := hit.Title
		if desc == "" {
			desc = hit.Snippet
		}
		if desc == "" {
			desc = hit.URL
		}
		add(hit.RetrievedAt, firstNonEmptyTimeline(hit.Source, "search"), "search_index", desc, "low")
	}
}

func collectPasteTimeline(data any, add func(date, source, eventType, description, confidence string)) {
	var payload struct {
		Psbdmp []struct {
			PasteID string `json:"paste_id"`
			Date    string `json:"date"`
			Preview string `json:"preview"`
			Emails  []string `json:"emails"`
			Names   []string `json:"names"`
		} `json:"psbdmp_hits"`
		GitHub []struct {
			Repo      string `json:"repo"`
			Path      string `json:"path"`
			HTMLURL   string `json:"html_url"`
			CreatedAt string `json:"created_at"`
		} `json:"github_hits"`
		Reddit []struct {
			Title     string `json:"title"`
			Subreddit string `json:"subreddit"`
			CreatedUTC int64  `json:"created_utc"`
			URL       string `json:"url"`
		} `json:"reddit_hits"`
		IntelX []struct {
			SourceName string `json:"source_name"`
			Type       string `json:"type"`
			IndexDate  string `json:"index_date"`
		} `json:"intelx_hits"`
		DeHashed []struct {
			DatabaseName string `json:"database_name"`
			Email        string `json:"email"`
			Name         string `json:"name"`
			Username     string `json:"username"`
			Date         string `json:"date"`
		} `json:"dehashed_hits"`
	}
	if !decodeTimelineData(data, &payload) {
		return
	}
	for _, hit := range payload.Psbdmp {
		desc := hit.PasteID
		if desc == "" {
			desc = "psbdmp paste"
		}
		if hit.Preview != "" {
			desc += ": " + compactDescription(hit.Preview)
		}
		add(hit.Date, "psbdmp", "paste", desc, "medium")
	}
	for _, hit := range payload.GitHub {
		desc := firstNonEmptyTimeline(hit.Repo, hit.Path, hit.HTMLURL)
		add(hit.CreatedAt, "github", "code_search", desc, "low")
	}
	for _, hit := range payload.Reddit {
		desc := firstNonEmptyTimeline(hit.Title, hit.Subreddit, hit.URL)
		add(unixDate(hit.CreatedUTC), "reddit", "post", desc, "low")
	}
	for _, hit := range payload.IntelX {
		desc := firstNonEmptyTimeline(hit.SourceName, hit.Type, "IntelX hit")
		add(hit.IndexDate, "intelx", "index", desc, "medium")
	}
	for _, hit := range payload.DeHashed {
		desc := firstNonEmptyTimeline(hit.DatabaseName, hit.Email, hit.Username, hit.Name)
		add(hit.Date, "dehashed", "breach", desc, "high")
	}
}

func collectReverseTimeline(data any, add func(date, source, eventType, description, confidence string)) {
	var payload struct {
		Wayback []struct {
			URL       string `json:"url"`
			FirstSeen string `json:"first_seen"`
			Source    string `json:"source"`
		} `json:"wayback_hits"`
	}
	if !decodeTimelineData(data, &payload) {
		return
	}
	for _, hit := range payload.Wayback {
		desc := firstNonEmptyTimeline(hit.URL, hit.Source, "Wayback CDX listing confirmation")
		add(hit.FirstSeen, firstNonEmptyTimeline(hit.Source, "wayback"), "wayback_index", desc, "low")
	}
}

func collectTimelineFromMessenger(report *MessengerReport, root *InvestigationReport, add func(date, source, eventType, description, confidence string)) {
	if report == nil || root == nil {
		return
	}
	if report.Telegram != nil && strings.TrimSpace(report.Telegram.LastSeenBucket) != "" {
		add(root.GeneratedAt.UTC().Format("2006-01-02"), "telegram", "last_seen_bucket", "last seen bucket: "+report.Telegram.LastSeenBucket, "low")
	}
	if report.WhatsApp != nil && strings.TrimSpace(report.WhatsApp.LastSeenBucket) != "" {
		add(root.GeneratedAt.UTC().Format("2006-01-02"), "whatsapp", "last_seen", "last seen: "+report.WhatsApp.LastSeenBucket, "low")
	}
}

func decodeTimelineData(data any, target any) bool {
	if data == nil || target == nil {
		return false
	}
	bytes, err := json.Marshal(data)
	if err != nil {
		return false
	}
	if err := json.Unmarshal(bytes, target); err != nil {
		return false
	}
	return true
}

func parseTimelineDate(value string) (time.Time, bool) {
	value = strings.TrimSpace(value)
	if value == "" {
		return time.Time{}, false
	}
	layouts := []string{
		time.RFC3339,
		"2006-01-02",
		"2006-1-2",
		"2006-01",
		"2006",
		"Jan 2, 2006",
		"January 2, 2006",
	}
	for _, layout := range layouts {
		if parsed, err := time.Parse(layout, value); err == nil {
			switch layout {
			case "2006":
				return time.Date(parsed.Year(), 1, 1, 0, 0, 0, 0, time.UTC), true
			case "2006-01":
				return time.Date(parsed.Year(), parsed.Month(), 1, 0, 0, 0, 0, time.UTC), true
			default:
				return parsed.UTC(), true
			}
		}
	}
	if unix, ok := parseUnixSeconds(value); ok {
		return unix, true
	}
	return time.Time{}, false
}

func parseUnixSeconds(value string) (time.Time, bool) {
	if len(value) < 9 || len(value) > 11 {
		return time.Time{}, false
	}
	for _, r := range value {
		if r < '0' || r > '9' {
			return time.Time{}, false
		}
	}
	seconds, err := strconv.ParseInt(value, 10, 64)
	if err != nil {
		return time.Time{}, false
	}
	return time.Unix(seconds, 0).UTC(), true
}

func unixDate(seconds int64) string {
	if seconds <= 0 {
		return ""
	}
	return time.Unix(seconds, 0).UTC().Format("2006-01-02")
}

func compactDescription(value string) string {
	value = strings.TrimSpace(value)
	if len(value) > 160 {
		return strings.TrimSpace(value[:160])
	}
	return value
}

func firstNonEmptyTimeline(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return strings.TrimSpace(value)
		}
	}
	return ""
}
