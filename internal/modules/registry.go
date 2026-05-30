package modules

import (
	"github.com/KatrielMoses/PhoneAccess/internal/core"
	"github.com/KatrielMoses/PhoneAccess/internal/modules/breach"
	"github.com/KatrielMoses/PhoneAccess/internal/modules/carrier"
	"github.com/KatrielMoses/PhoneAccess/internal/modules/enumerator"
	"github.com/KatrielMoses/PhoneAccess/internal/modules/finance"
	"github.com/KatrielMoses/PhoneAccess/internal/modules/geo"
	"github.com/KatrielMoses/PhoneAccess/internal/modules/images"
	"github.com/KatrielMoses/PhoneAccess/internal/modules/infrastructure"
	"github.com/KatrielMoses/PhoneAccess/internal/modules/intelligence"
	"github.com/KatrielMoses/PhoneAccess/internal/modules/paste"
	publicrecords "github.com/KatrielMoses/PhoneAccess/internal/modules/publicrecords"
	"github.com/KatrielMoses/PhoneAccess/internal/modules/reverse"
	"github.com/KatrielMoses/PhoneAccess/internal/modules/search"
	"github.com/KatrielMoses/PhoneAccess/internal/modules/social/signal"
	"github.com/KatrielMoses/PhoneAccess/internal/modules/social/telegram"
	"github.com/KatrielMoses/PhoneAccess/internal/modules/social/whatsapp"
	"github.com/KatrielMoses/PhoneAccess/internal/modules/spam"
	"github.com/KatrielMoses/PhoneAccess/internal/modules/truecaller"
	"github.com/KatrielMoses/PhoneAccess/internal/modules/voip"
)

func Registry() []core.Module {
	return []core.Module{
		carrier.New(),
		voip.New(),
		enumerator.New(),
		finance.New(),
		geo.New(),
		spam.New(),
		breach.New(),
		publicrecords.New(),
		search.New(),
		paste.New(),
		reverse.New(),
		truecaller.New(),
		signal.New(),
		telegram.New(),
		whatsapp.New(),
		images.New(),
		infrastructure.New(),
		intelligence.New(),
		NewStubModule(),
	}
}
