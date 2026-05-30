package core

import (
	"encoding/json"
	"strings"
)

func BuildMessengerReport(results []*ModuleResult) *MessengerReport {
	report := &MessengerReport{}
	for _, result := range results {
		if result == nil {
			continue
		}
		account := messengerAccountFromResult(result)
		if account == nil {
			continue
		}
		switch strings.ToLower(result.ModuleName) {
		case "telegram":
			report.Telegram = account
		case "whatsapp":
			report.WhatsApp = account
		case "signal":
			report.Signal = account
		}
	}
	if report.Telegram == nil && report.WhatsApp == nil && report.Signal == nil {
		return nil
	}
	return report
}

func messengerAccountFromResult(result *ModuleResult) *MessengerAccount {
	if result.Status == ModuleStatusSkipped || result.Status == ModuleStatusGated {
		return nil
	}
	if account, ok := result.Data.(*MessengerAccount); ok {
		return account
	}
	if account, ok := result.Data.(MessengerAccount); ok {
		return &account
	}
	if result.Data != nil {
		data, err := json.Marshal(result.Data)
		if err == nil {
			var account MessengerAccount
			if json.Unmarshal(data, &account) == nil && account.DataSource != "" {
				return &account
			}
		}
	}
	if len(result.Findings) == 0 {
		return nil
	}
	source := result.Findings["data_source"]
	if source == "" {
		return nil
	}
	return &MessengerAccount{
		Found:             strings.EqualFold(result.Findings["found"], "true"),
		DisplayName:       result.Findings["display_name"],
		Username:          result.Findings["username"],
		Bio:               result.Findings["bio"],
		LastSeenBucket:    result.Findings["last_seen_bucket"],
		AccountID:         result.Findings["account_id"],
		ProfilePhotoPath:  result.Findings["profile_photo_path"],
		ProfilePhotoPHash: result.Findings["profile_photo_phash"],
		AboutBio:          result.Findings["about_bio"],
		DataSource:        source,
	}
}
