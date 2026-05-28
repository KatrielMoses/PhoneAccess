package core

import (
	"context"
	"os"
	"strings"

	"github.com/KatrielMoses/PhoneAccess/internal/config"
)

type phoneNumberContextKey struct{}

// WithPhoneNumber stores a PhoneNumber in the context so Sources can retrieve it.
func WithPhoneNumber(ctx context.Context, number *PhoneNumber) context.Context {
	return context.WithValue(ctx, phoneNumberContextKey{}, number)
}

// PhoneNumberFromContext retrieves a PhoneNumber stored by WithPhoneNumber.
func PhoneNumberFromContext(ctx context.Context) *PhoneNumber {
	number, _ := ctx.Value(phoneNumberContextKey{}).(*PhoneNumber)
	return number
}

// GetAPIKey looks up name first in environment variables, then in the config store.
func GetAPIKey(ctx context.Context, name string) string {
	if v := strings.TrimSpace(os.Getenv(name)); v != "" {
		return v
	}
	store, err := config.NewDefaultStore()
	if err != nil {
		return ""
	}
	cfg, err := store.Load()
	if err != nil {
		return ""
	}
	return strings.TrimSpace(cfg.APIKeys[name])
}
