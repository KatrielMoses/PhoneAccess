# PhoneAccess

PhoneAccess is a free, open-source phone number OSINT CLI for lawful security research. It is designed as a single Go binary: easy to install, easy to audit, and usable without paid services. Optional API keys can enrich results, but the tool keeps offline and public-source behavior first.

> Legal notice: PhoneAccess is for lawful security research, fraud investigation, abuse triage, and defensive analysis only. Use it only on numbers you are authorized to investigate, respect applicable laws and platform terms, and do not use it for stalking, harassment, doxxing, or unauthorized surveillance.

## Installation

### Linux / macOS

```sh
curl -fsSL https://raw.githubusercontent.com/KatrielMoses/PhoneAccess/main/install.sh | sudo bash
```

### Windows (PowerShell)

```powershell
irm https://raw.githubusercontent.com/KatrielMoses/PhoneAccess/main/install.ps1 | iex
```

### Go install (all platforms)

```sh
go install github.com/KatrielMoses/PhoneAccess/cmd/phoneaccess@latest
```

## OPSEC

PhoneAccess is designed for use by professional investigators. All active module runs expose your IP address to probed services by default. Configure OPSEC before running active investigations.

### Proxy and Tor

```sh
phoneaccess investigate +14155552671 --proxy socks5://127.0.0.1:9050
phoneaccess investigate +14155552671 --proxy http://user:pass@proxy.host:8080
phoneaccess investigate +14155552671 --tor
phoneaccess investigate +14155552671 --tor --tor-address 127.0.0.1:9150
phoneaccess investigate +14155552671 --tor --tor-skip-check
```

### DNS-over-HTTPS

```sh
phoneaccess investigate +14155552671 --doh
phoneaccess investigate +14155552671 --doh --doh-provider google
phoneaccess investigate +14155552671 --doh --doh-provider quad9
phoneaccess investigate +14155552671 --doh --doh-provider https://custom.resolver.example/dns-query
```

### User-Agent

```sh
phoneaccess investigate +14155552671 --ua-mode random
phoneaccess investigate +14155552671 --user-agent "Mozilla/5.0 ..."
```

### Persistent OPSEC configuration

```sh
phoneaccess keys set TOR_ENABLED true
phoneaccess keys set PROXY_URL socks5://127.0.0.1:9050
phoneaccess keys set PHONEACCESS_DOH_ENABLED true
phoneaccess keys set PHONEACCESS_DOH_PROVIDER cloudflare
phoneaccess keys set PHONEACCESS_UA_MODE random
```

### OPSEC pre-flight prompt

Active runs display a summary of the current OPSEC state (proxy, DoH, UA mode) and ask for confirmation before any modules execute. Pass `--yes` / `-y` to skip for non-interactive or scripted use:

```sh
phoneaccess investigate +14155552671 --active --yes
```

### Session file encryption

Telegram and WhatsApp session files are encrypted at rest using AES-256-GCM. The default key is derived from the machine ID and is transparent. Set `SESSION_KEY_SOURCE=passphrase` to require a passphrase on each use, or `both` for passphrase + machine ID.

```sh
phoneaccess keys set SESSION_KEY_SOURCE passphrase
```

## Quick Start

```sh
phoneaccess investigate +14155552671
phoneaccess investigate +14155552671 -o report.pdf
phoneaccess investigate +14155552671 --format json
phoneaccess investigate -                              # read from stdin
phoneaccess investigate +14155552671 --active          # include probing modules
phoneaccess investigate +14155552671 -m enumerator     # specific module only
phoneaccess investigate phones.txt --batch             # bulk investigation
phoneaccess keys list
phoneaccess keys set NUMVERIFY_API_KEY your-key-here
phoneaccess modules
phoneaccess setup whatsapp
phoneaccess setup telegram
phoneaccess cases list
phoneaccess cases show 3
phoneaccess cases tag 3 fraud
phoneaccess cases note 3 "Confirmed Truecaller identity"
phoneaccess cases name 3 "Smith investigation"
phoneaccess cases delete 3
phoneaccess cases search "Smith"
phoneaccess pivot email discovered@example.com
phoneaccess pivot username johndoe
phoneaccess pivot domain example.com
phoneaccess pivot name "John Smith"
phoneaccess pivot phone +14155552671
```

## Usage

Run a full investigation:

```sh
phoneaccess investigate +14155552671
```

Use passive mode to avoid active public lookup requests:

```sh
phoneaccess investigate +14155552671 --passive
```

Run only selected modules. Non-selected modules are recorded as skipped in JSON output:

```sh
phoneaccess investigate +14155552671 -m carrier,geo,spam
```

Read the phone number from stdin (useful for piping):

```sh
echo "+14155552671" | phoneaccess investigate -
```

## Module Tiers

PhoneAccess modules are split into two tiers:

**Passive modules** run by default. They query public APIs and databases without probing platform endpoints.

**Active modules** must be explicitly enabled. They probe platform registration endpoints and are intended for professional OSINT investigations.

```sh
# Run passive modules only (default)
phoneaccess investigate +14155552671

# Run all modules including active probing
phoneaccess investigate +14155552671 --active

# Run specific active module only
phoneaccess investigate +14155552671 -m enumerator

# Batch mode also accepts --active
phoneaccess investigate phones.txt --batch --active
```

`--passive` remains available for operators who want passive-mode behavior inside modules that support it.

Export reports:

```sh
phoneaccess investigate +14155552671 --format json
phoneaccess investigate +14155552671 --format csv -o report.csv
phoneaccess investigate +14155552671 --format txt -o report.txt
phoneaccess investigate +14155552671 --format pdf -o report.pdf
```

Set a per-module timeout:

```sh
phoneaccess investigate +14155552671 --timeout 10
```

Investigate a batch file sequentially:

```sh
phoneaccess investigate phones.txt --batch
phoneaccess investigate phones.txt --batch --passive
phoneaccess investigate phones.txt --batch -m carrier,geo,spam
phoneaccess investigate phones.txt --batch --active
```

Batch files are plain text with one number per line. Blank lines and lines beginning with `#` are ignored. Batch mode writes `phoneaccess_batch_{timestamp}.csv` and `phoneaccess_batch_{timestamp}.json` in the current directory.

## Compact and field mode

**Compact mode** — a ≤6-line triage summary instead of the full terminal report:

```sh
phoneaccess investigate +14155552671 --compact
phoneaccess investigate +14155552671 --format compact
phoneaccess investigate phones.txt --batch --compact
```

Example output:
```
+14155552671  US · AT&T Mobility · Mobile · California
RISK: 45/100 MODERATE  |  Spam: 0 reports  |  Breaches: 2  |  Services: 3/277
Identity: John S. (0.82, Truecaller)  |  Email pivot: j***@gmail.com
Messenger: ✓WhatsApp  ✓Telegram  —Signal
Timeline: first seen 2021-03-14  |  last seen 2024-11-08
```

Risk band is colour-coded: green `LOW`, yellow `MODERATE`, red `HIGH`/`CRITICAL`. Fields with no data are omitted. Wraps gracefully at 80 characters. No banner. No section headers.

Persist compact as the default with a config key:
```sh
phoneaccess keys set PHONEACCESS_COMPACT true
# or
export PHONEACCESS_COMPACT=true
```

**Field mode** — a single pipe-delimited line for logging, grep, and scripting:

```sh
phoneaccess investigate +14155552671 --field
phoneaccess investigate phones.txt --batch --field
```

Example output:
```
+14155552671|MODERATE|45|AT&T Mobility|Mobile|US|2|3|John S.|WhatsApp,Telegram
```

Field order: `e164|risk_band|risk_score|carrier|line_type|country|breach_count|service_hits|top_name|messengers`

Empty fields output as an empty string between delimiters. No colour codes.

```sh
# Extract just the risk band
phoneaccess investigate +14155552671 --field | cut -d'|' -f2

# Filter a batch by risk band
phoneaccess investigate phones.txt --batch --field | grep HIGH
```

`--compact` and `--field` are mutually exclusive.

## Webhook notifications

PhoneAccess can POST a JSON payload to a webhook after every investigation.

```sh
# One-off override
phoneaccess investigate +14155552671 --webhook https://hooks.slack.com/T00000000/B00000000/XXXX

# Persist via config keys
phoneaccess keys set PHONEACCESS_WEBHOOK_URL https://hooks.slack.com/...
phoneaccess keys set PHONEACCESS_WEBHOOK_SECRET mysigningkey    # optional
phoneaccess keys set PHONEACCESS_WEBHOOK_RISK_MIN MODERATE       # default: HIGH
```

| Config key | Default | Description |
| --- | --- | --- |
| `PHONEACCESS_WEBHOOK_URL` | — | Webhook endpoint URL |
| `PHONEACCESS_WEBHOOK_SECRET` | — | HMAC-SHA256 signing secret (optional); adds `X-PhoneAccess-Signature: sha256=<hex>` header |
| `PHONEACCESS_WEBHOOK_RISK_MIN` | `HIGH` | Minimum risk band to notify: `LOW`, `MODERATE`, `HIGH`, `CRITICAL` |

**Payload format:**

```json
{
  "event": "investigation_complete",
  "timestamp": "2026-05-29T12:00:00Z",
  "phone": "+14155552671",
  "risk_score": 45,
  "risk_band": "MODERATE",
  "top_findings": {
    "carrier": "AT&T Mobility",
    "breach_count": 2,
    "service_hits": 3,
    "top_name": "John S.",
    "messengers": ["WhatsApp", "Telegram"]
  },
  "case_id": 42
}
```

Webhook delivery is best-effort: one attempt, 10-second timeout. If delivery fails, a warning is printed to stderr but the investigation result is unaffected.

**Supported targets:**

- **Slack**: `PHONEACCESS_WEBHOOK_URL=https://hooks.slack.com/services/T.../B.../...`
- **Generic HTTP endpoint**: any HTTPS URL that accepts a POST with `Content-Type: application/json`
- **Discord**: `PHONEACCESS_WEBHOOK_URL=https://discord.com/api/webhooks/{id}/{token}` — automatically detected; payload is reformatted as a Discord embed:

```json
{
  "content": "⚠ PhoneAccess Alert",
  "embeds": [{
    "title": "+14155552671 — HIGH (70/100)",
    "color": 15158332,
    "fields": [
      {"name": "Risk Band", "value": "HIGH", "inline": true},
      {"name": "Carrier", "value": "AT&T Mobility", "inline": true},
      {"name": "Breaches", "value": "2", "inline": true},
      {"name": "Services", "value": "3", "inline": true}
    ]
  }]
}
```

**Batch mode:** when `--batch` is combined with a webhook, one notification is fired per investigation as it completes — not a single summary at the end.

## Pivoting

Pivot from any artifact discovered during an investigation to expand coverage.

```sh
phoneaccess pivot email discovered@example.com
phoneaccess pivot email discovered@example.com --case 4
phoneaccess pivot username johndoe
phoneaccess pivot domain example.com
phoneaccess pivot name "John Smith"
phoneaccess pivot phone +14155552671
```

All pivot types support `--format json`, `--no-save`, and `--case <id>` to link the pivot to a parent case in the SQLite database.

`pivot phone` additionally supports `--active`, `--yes`, `--timeout`, `--compact`, and `--field`.

`pivot domain` runs SSL certificate transparency (crt.sh), WHOIS/RDAP registrant lookup, and VirusTotal domain intelligence (when `VIRUSTOTAL_API_KEY` is configured).

`pivot username` searches the full enumerator service list (200+ platforms) and returns a profile URL per hit.

`pivot email` runs breach, search, and paste modules against the email address and prints a cross-tool suggestion for MailAccess.

## Output Modes

### Full report (default)

```sh
phoneaccess investigate +14155552671
```

### Compact — fast triage

A ≤6-line summary with colour-coded risk band. Fields with no data are omitted. Wraps at 80 columns.

```sh
phoneaccess investigate +14155552671 --compact
phoneaccess investigate phones.txt --batch --compact
```

Persist as default:

```sh
phoneaccess keys set PHONEACCESS_COMPACT true
```

### Field — pipeline-safe single line

Pipe-delimited: `e164|risk_band|risk_score|carrier|line_type|country|breach_count|service_hits|top_name|messengers`

```sh
phoneaccess investigate +14155552671 --field
phoneaccess investigate phones.txt --batch --field | grep "HIGH\|CRITICAL"
phoneaccess investigate phones.txt --batch --field | cut -d'|' -f2
```

`--compact` and `--field` are mutually exclusive.

### Confidence filtering

Hide terminal findings below a confidence threshold. JSON output always includes all findings.

```sh
phoneaccess investigate +14155552671 --min-confidence 0.75
```

Persist:

```sh
phoneaccess keys set PHONEACCESS_MIN_CONFIDENCE 0.75
```

Other commands:

```sh
phoneaccess modules
phoneaccess version
phoneaccess keys list
phoneaccess keys set OPENCNAM_SID your_sid
phoneaccess keys set GOOGLE_CSE_API_KEY your_key
phoneaccess keys set GOOGLE_CSE_CX your_cx
phoneaccess keys set BING_SEARCH_API_KEY your_key
phoneaccess keys set OPENCORPORATES_API_KEY your_key
phoneaccess keys set PACER_USERNAME your_username
phoneaccess keys set PACER_PASSWORD your_password
phoneaccess keys set GITHUB_TOKEN your_token
phoneaccess keys set INTELX_API_KEY your_key
phoneaccess keys set DEHASHED_EMAIL your_email
phoneaccess keys set DEHASHED_API_KEY your_key
phoneaccess keys set NUMLOOKUP_API_KEY your_key
phoneaccess keys set TRESTLE_API_KEY your_key
phoneaccess keys set VERIPHONE_API_KEY your_key
phoneaccess keys set TWILIO_ACCOUNT_SID your_sid
phoneaccess keys set TWILIO_AUTH_TOKEN your_token
phoneaccess keys set TWILIO_ENABLE_CALLER_NAME true
phoneaccess keys set TRUECALLER_INSTALLATION_ID your_session_token
phoneaccess keys unset OPENCNAM_SID
phoneaccess setup whatsapp
phoneaccess setup telegram
```

## Modules

| Name | Tier | Requires Key | Description |
| --- | --- | --- | --- |
| carrier | passive | no | Offline carrier, line type, VOIP, and regional phone intelligence with optional phone validation APIs. |
| voip | passive | no | VOIP, disposable number, prepaid, and phone risk intelligence. |
| enumerator | active | no | Silent phone registration enumeration across 200+ services without triggering SMS or notifications. |
| finance | active | no | Silent financial-platform registration checks. Venmo phone-to-name resolution requires PHONEACCESS_FINANCE_VENMO=allow (opt-in, 50-lookup cap, 6s delay). |
| geo | passive | no | Area-code history, timezone, portability, and regional complaint-pattern intelligence. |
| spam | passive | no | Public spam-report reputation checks across caller complaint databases. |
| breach | passive | no | Public breach and infostealer-log intelligence for phone numbers. |
| search | active | no | Targeted Google CSE and Bing dork execution for phone-number intelligence. |
| public_records | active | no | Official government and business registry lookups tied to a phone number. |
| paste | active | no | Paste, code-search, breach, and leak monitoring across public sources. |
| reverse | passive | no | Public reverse lookup and identity pivot discovery. |
| truecaller | active | yes | Unofficial Truecaller session-token scanner for rich identity pivots. |
| telegram | active | yes | Telegram account discovery using the official MTProto contacts import flow. |
| whatsapp | active | no | WhatsApp presence checks through the user's linked WhatsApp Web session. |
| signal | active | no | Signal registration check via HMAC-SHA256 hashed CDN lookup. Profile photo retrieval and pHash capture. No credentials required. |
| infrastructure | active | optional | SSL certificate transparency (crt.sh), WHOIS/RDAP registrant lookup, VirusTotal cross-reference (VIRUSTOTAL_API_KEY), MalwareBazaar search. |
| intelligence | active | optional | OpenSanctions sanctions and PEP screening across 100+ official lists. Adverse-media screening with risk keyword extraction. OPENSANCTIONS_API_KEY unlocks higher rate limits. |
| image_intelligence | active | optional | TinEye reverse image search (TINEYE_API_KEY). Google Lens, Yandex, Bing, and TinEye web URL generation. Cross-session pHash deduplication via SQLite. |
| phase1-stub | passive | no | Offline placeholder for future OSINT modules. |

Every report includes a final risk score from 0 to 100, a band (`LOW`, `MODERATE`, `HIGH`, `CRITICAL`), the top contributing drivers, and a one-sentence summary.

Reports also include an `identity_record` generated by the jurisdiction-aware correlator. It combines legally accessible name, address, DOB, email, and social-link signals with source tier provenance; terminal output suppresses candidates below 0.45 confidence while JSON keeps the full analyst record.

## Optional API Keys

| Key name | Source | Free tier limit | How to set |
| --- | --- | --- | --- |
| `NUMVERIFY_API_KEY` | NumVerify / APILayer carrier lookup | Varies by APILayer plan | `phoneaccess keys set NUMVERIFY_API_KEY <key>` or environment variable |
| `VERIPHONE_API_KEY` | Veriphone carrier lookup, signup/docs: https://veriphone.io/docs | 1,000/month free tier | `phoneaccess keys set VERIPHONE_API_KEY <key>` or environment variable |
| `ABSTRACT_API_KEY` | AbstractAPI phone validation, signup: https://www.abstractapi.com/phone-validator | 250/month free tier | `phoneaccess keys set ABSTRACT_API_KEY <key>` or environment variable |
| `IPQS_API_KEY` | IPQualityScore Phone Validation API | Varies by IPQS plan | `phoneaccess keys set IPQS_API_KEY <key>` or environment variable |
| `OPENCNAM_SID` | OpenCNAM | Varies by OpenCNAM plan | `phoneaccess keys set OPENCNAM_SID <sid>` or environment variable |
| `GOOGLE_CSE_API_KEY` | Google Custom Search API | Query-based free quota varies by Google plan | `phoneaccess keys set GOOGLE_CSE_API_KEY <key>` or environment variable |
| `GOOGLE_CSE_CX` | Google Custom Search Engine context | Required with the CSE API key | `phoneaccess keys set GOOGLE_CSE_CX <cx>` or environment variable |
| `BING_SEARCH_API_KEY` | Bing Web Search API | 1,000/month free tier | `phoneaccess keys set BING_SEARCH_API_KEY <key>` or environment variable |
| `OPENCORPORATES_API_KEY` | OpenCorporates officer search API | Free tier available; 500 requests/month enforced locally | `phoneaccess keys set OPENCORPORATES_API_KEY <key>` or environment variable |
| `PACER_USERNAME` | PACER federal court party search | Registration required; commonly under $30/quarter for research access | `phoneaccess keys set PACER_USERNAME <username>` or environment variable |
| `PACER_PASSWORD` | PACER federal court party search | Pair with `PACER_USERNAME` for access | `phoneaccess keys set PACER_PASSWORD <password>` or environment variable |
| `GITHUB_TOKEN` | GitHub code search | Higher rate limit than unauthenticated requests | `phoneaccess keys set GITHUB_TOKEN <token>` or environment variable |
| `INTELX_API_KEY` | IntelX phonebook search | Free signup at intelx.io | `phoneaccess keys set INTELX_API_KEY <key>` or environment variable |
| `DEHASHED_EMAIL` | DeHashed Basic Auth email | Required with API key | `phoneaccess keys set DEHASHED_EMAIL <email>` or environment variable |
| `DEHASHED_API_KEY` | DeHashed breach search API key | Free tier queries are limited | `phoneaccess keys set DEHASHED_API_KEY <key>` or environment variable |
| `NUMLOOKUP_API_KEY` | NumLookup API | 500/month free tier | `phoneaccess keys set NUMLOOKUP_API_KEY <key>` or environment variable |
| `LEAKSIGHT_API_KEY` | LeakSight | Varies by LeakSight plan | `phoneaccess keys set LEAKSIGHT_API_KEY <key>` or environment variable |
| `HIBP_API_KEY` | Have I Been Pwned breach intelligence — most recognised breach database, signup: haveibeenpwned.com/API/Key | $3.50/month (no free tier for the breachedaccount endpoint) | `phoneaccess keys set HIBP_API_KEY <key>` or environment variable |
| `OPENSANCTIONS_API_KEY` | OpenSanctions — OFAC SDN, UN, EU, UK HMT, 100+ official sanctions/PEP lists (used by intelligence module, --active). Search endpoint always runs without a key; key unlocks higher rate limits and match API. Free tier: 10,000 req/month at opensanctions.org/api | 10,000/month free tier | `phoneaccess keys set OPENSANCTIONS_API_KEY <key>` or environment variable |
| `TRESTLE_API_KEY` | Trestle IQ | Paid/partner access | `phoneaccess keys set TRESTLE_API_KEY <key>` or environment variable |
| `TWILIO_ACCOUNT_SID` | Twilio Lookup v2, signup: https://www.twilio.com/en-us/go/try-twilio-de-1 | Pay-per-use | `phoneaccess keys set TWILIO_ACCOUNT_SID <sid>` or environment variable |
| `TWILIO_AUTH_TOKEN` | Twilio Lookup v2, signup: https://www.twilio.com/en-us/go/try-twilio-de-1 | Pay-per-use | `phoneaccess keys set TWILIO_AUTH_TOKEN <token>` or environment variable |
| `TWILIO_ENABLE_CALLER_NAME` | Twilio caller name opt-in | Additional per-lookup cost if enabled | `phoneaccess keys set TWILIO_ENABLE_CALLER_NAME true` or environment variable |
| `TRUECALLER_INSTALLATION_ID` | Truecaller unofficial session token, install/signup: https://www.truecaller.com/download | No public free tier; operator-managed session token | `phoneaccess keys set TRUECALLER_INSTALLATION_ID <token>` or environment variable |
| `PHONEACCESS_USER_AGENT` | Custom User-Agent string (used when `--ua-mode=custom` or `--user-agent` flag is set) | — | `phoneaccess keys set PHONEACCESS_USER_AGENT "Mozilla/5.0 ..."` or environment variable |
| `PHONEACCESS_UA_MODE` | UA rotation mode: `fixed` (default), `random`, `custom` | — | `phoneaccess keys set PHONEACCESS_UA_MODE random` or environment variable |
| `PHONEACCESS_COMPACT` | Set to `true` to use compact triage output (≤6 lines) as the persistent default | — | `phoneaccess keys set PHONEACCESS_COMPACT true` or environment variable |
| `PHONEACCESS_WEBHOOK_URL` | Webhook endpoint URL; supports Slack, Discord (auto-detected), and generic HTTP | — | `phoneaccess keys set PHONEACCESS_WEBHOOK_URL https://...` or environment variable |
| `PHONEACCESS_WEBHOOK_SECRET` | HMAC-SHA256 signing secret; adds `X-PhoneAccess-Signature` header for payload verification | — | `phoneaccess keys set PHONEACCESS_WEBHOOK_SECRET <secret>` or environment variable |
| `PHONEACCESS_WEBHOOK_RISK_MIN` | Minimum risk band to trigger webhook: `LOW`, `MODERATE`, `HIGH`, `CRITICAL` | `HIGH` | `phoneaccess keys set PHONEACCESS_WEBHOOK_RISK_MIN MODERATE` or environment variable |
| `PROXY_URL` | Proxy URL for all requests — equivalent to `--proxy` flag | — | `phoneaccess keys set PROXY_URL socks5://127.0.0.1:9050` or environment variable |
| `TOR_ENABLED` | Set to `true` to route all requests through Tor (127.0.0.1:9050) — equivalent to `--tor` flag | — | `phoneaccess keys set TOR_ENABLED true` or environment variable |
| `TOR_ADDRESS` | Custom Tor SOCKS5 address (default: 127.0.0.1:9050) — equivalent to `--tor-address` flag | — | `phoneaccess keys set TOR_ADDRESS 127.0.0.1:9150` or environment variable |
| `PHONEACCESS_DOH_ENABLED` | Set to `true` to enable DNS-over-HTTPS on every run — equivalent to `--doh` flag | — | `phoneaccess keys set PHONEACCESS_DOH_ENABLED true` or environment variable |
| `PHONEACCESS_DOH_PROVIDER` | DoH provider: `cloudflare` (default), `google`, `quad9`, or a custom URL | — | `phoneaccess keys set PHONEACCESS_DOH_PROVIDER google` or environment variable |
| `SESSION_KEY_SOURCE` | Session file encryption key source: `machine` (default, transparent), `passphrase` (PBKDF2-SHA256), `both` (passphrase + machine ID) | — | `phoneaccess keys set SESSION_KEY_SOURCE passphrase` or environment variable |
| `SNUSBASE_API_KEY` | Snusbase breach intelligence | Paid | `phoneaccess keys set SNUSBASE_API_KEY <key>` or environment variable |
| `BREACHDIRECTORY_API_KEY` | BreachDirectory breach search via RapidAPI | Free tier available via RapidAPI | `phoneaccess keys set BREACHDIRECTORY_API_KEY <key>` or environment variable |
| `LEAKLOOKUP_API_KEY` | Leak-Lookup phone number breach search, signup: leak-lookup.com | Paid | `phoneaccess keys set LEAKLOOKUP_API_KEY <key>` or environment variable |
| `VIRUSTOTAL_API_KEY` | VirusTotal threat intelligence (infrastructure module, pivot domain), signup: virustotal.com | 500 req/day free tier | `phoneaccess keys set VIRUSTOTAL_API_KEY <key>` or environment variable |
| `TINEYE_API_KEY` | TinEye reverse image search, signup: tineye.com/api | 100 searches/month free tier | `phoneaccess keys set TINEYE_API_KEY <key>` or environment variable |
| `PHASH_HAMMING_THRESHOLD` | Maximum Hamming distance for cross-session photo deduplication (default: 10; lower = stricter matching) | — | `phoneaccess keys set PHASH_HAMMING_THRESHOLD 8` or environment variable |
| `PHONEACCESS_MIN_CONFIDENCE` | Default minimum confidence threshold for terminal display (0.0–1.0); findings below this are hidden from terminal but always present in JSON | — | `phoneaccess keys set PHONEACCESS_MIN_CONFIDENCE 0.6` or environment variable |

API providers change limits over time. Check each provider's current pricing and acceptable-use terms before using a key.

Truecaller integration uses an unofficial session token. This is unsupported by Truecaller and may violate their Terms of Service. Use is the responsibility of the operator. Session tokens are obtained by registering the official Truecaller app on your own device.

## Request Fingerprint Hardening

By default PhoneAccess selects one realistic browser User-Agent at startup (fixed mode) and uses it for every request in that run. This looks like a single consistent browser session rather than a rotating bot. Browser-appropriate header profiles (Accept, Accept-Language, Sec-CH-UA, etc.) are injected automatically. Rate-limit delays include ±30% random jitter to avoid fixed timing fingerprints.

### User-Agent modes

| Flag | Config key | Values | Behaviour |
| --- | --- | --- | --- |
| `--ua-mode` | `PHONEACCESS_UA_MODE` | `fixed` (default), `random`, `custom` | How UA is selected per request |
| `--user-agent` | `PHONEACCESS_USER_AGENT` | any string | Custom UA string; implies `custom` mode |

```sh
# Default: one consistent browser UA for the whole run
phoneaccess investigate +14155552671

# New random UA per request (useful with a proxy pool)
phoneaccess investigate +14155552671 --ua-mode random

# Supply your own UA string
phoneaccess investigate +14155552671 --user-agent "Mozilla/5.0 ..."

# Persist via config key
phoneaccess keys set PHONEACCESS_UA_MODE random
phoneaccess keys set PHONEACCESS_USER_AGENT "Mozilla/5.0 ..."
```

The embedded UA pool covers Chrome on Windows and macOS, Firefox on Windows and Linux, Safari on macOS, and Chrome on Android (22 variants). Chrome UAs receive full `Sec-CH-UA` / `Sec-Fetch-*` headers; Safari UAs omit `Sec-CH-UA` (matching real browser behaviour). Module-set headers (Authorization, API keys) always take precedence over profile headers.

## Building

```sh
make build
make test
make lint
make cross
```

The Makefile injects version metadata with Go ldflags:

```sh
make build VERSION=0.1.0
```

Without ldflags, `phoneaccess version` defaults to `dev` and `unknown`.

## Contributing

Contributions are welcome. Keep changes focused, preserve the existing project layout, include tests for behavior changes, and run:

```sh
go test ./...
go vet ./...
go build ./...
```

Please do not add modules that violate laws, platform terms, or user privacy. Defensive, transparent, auditable OSINT is the goal.

## License

PhoneAccess is released under the MIT License. See [LICENSE](LICENSE).
