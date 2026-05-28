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

## Usage

Run a full investigation:

```sh
phoneaccess +14155552671
```

Use passive mode to avoid active public lookup requests:

```sh
phoneaccess +14155552671 --passive
```

Run only selected modules. Non-selected modules are recorded as skipped in JSON output:

```sh
phoneaccess +14155552671 --modules carrier,geo,spam
```

## Module Tiers

PhoneAccess modules are split into two tiers:

**Passive modules** run by default. They query public APIs and databases without probing platform endpoints.

**Active modules** must be explicitly enabled. They probe platform registration endpoints and are intended for professional OSINT investigations.

```sh
# Run passive modules only (default)
phoneaccess +14155552671

# Run all modules including active probing
phoneaccess +14155552671 --active

# Run specific active module only
phoneaccess +14155552671 --modules enumerator

# Batch mode also accepts --active
phoneaccess batch phones.txt --active
```

`--passive` remains available for operators who want passive-mode behavior inside modules that support it.

Export reports:

```sh
phoneaccess +14155552671 --format json
phoneaccess +14155552671 --format csv -o report.csv
phoneaccess +14155552671 --format txt -o report.txt
phoneaccess +14155552671 --format pdf -o report.pdf
```

Set a per-module timeout:

```sh
phoneaccess +14155552671 --timeout 10
```

Investigate a batch file sequentially:

```sh
phoneaccess batch phones.txt
phoneaccess batch phones.txt --passive
phoneaccess batch phones.txt --modules carrier,geo,spam
phoneaccess batch phones.txt --active
```

Batch files are plain text with one number per line. Blank lines and lines beginning with `#` are ignored. Batch mode writes `phoneaccess_batch_{timestamp}.csv` and `phoneaccess_batch_{timestamp}.json` in the current directory.

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
| `TRESTLE_API_KEY` | Trestle IQ | Paid/partner access | `phoneaccess keys set TRESTLE_API_KEY <key>` or environment variable |
| `TWILIO_ACCOUNT_SID` | Twilio Lookup v2, signup: https://www.twilio.com/en-us/go/try-twilio-de-1 | Pay-per-use | `phoneaccess keys set TWILIO_ACCOUNT_SID <sid>` or environment variable |
| `TWILIO_AUTH_TOKEN` | Twilio Lookup v2, signup: https://www.twilio.com/en-us/go/try-twilio-de-1 | Pay-per-use | `phoneaccess keys set TWILIO_AUTH_TOKEN <token>` or environment variable |
| `TWILIO_ENABLE_CALLER_NAME` | Twilio caller name opt-in | Additional per-lookup cost if enabled | `phoneaccess keys set TWILIO_ENABLE_CALLER_NAME true` or environment variable |
| `TRUECALLER_INSTALLATION_ID` | Truecaller unofficial session token, install/signup: https://www.truecaller.com/download | No public free tier; operator-managed session token | `phoneaccess keys set TRUECALLER_INSTALLATION_ID <token>` or environment variable |

API providers change limits over time. Check each provider's current pricing and acceptable-use terms before using a key.

Truecaller integration uses an unofficial session token. This is unsupported by Truecaller and may violate their Terms of Service. Use is the responsibility of the operator. Session tokens are obtained by registering the official Truecaller app on your own device.

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
