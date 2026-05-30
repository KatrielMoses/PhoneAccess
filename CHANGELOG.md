# Changelog

All notable changes to PhoneAccess are documented here.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).

## [2.0.0] - 2026-05-30

### Added

**OPSEC**
- Proxy routing: `--proxy <url>` supports SOCKS5 and HTTP/HTTPS proxy URLs; `--tor` shorthand targets `127.0.0.1:9050`; `--tor-address` overrides the default; `--tor-skip-check` bypasses pre-flight circuit verification
- Tor pre-flight check via `check.torproject.org/api/ip` on every `--tor` run
- DNS-over-HTTPS: `--doh` flag with built-in providers `cloudflare` (default), `google`, `quad9` and custom URL support via `--doh-provider`; DoH client routes through active proxy when one is set
- OPSEC pre-flight prompt on `--active` runs: displays current proxy/DoH/UA state and requires confirmation; `--yes` / `-y` skips for non-interactive use
- Config keys: `PROXY_URL`, `TOR_ENABLED`, `TOR_ADDRESS`, `PHONEACCESS_DOH_ENABLED`, `PHONEACCESS_DOH_PROVIDER`

**Session security**
- Session files (Telegram, WhatsApp) are now encrypted at rest using AES-256-GCM with a random nonce and a `PHAC` magic header
- Three key derivation modes via `SESSION_KEY_SOURCE`: `machine` (SHA-256 of platform machine ID, default), `passphrase` (PBKDF2-SHA256, 100,000 iterations), `both` (PBKDF2 over passphrase + machine ID)
- Automatic migration: existing plaintext session files are encrypted in-place on first use

**Breach sources**
- Snusbase integration (`SNUSBASE_API_KEY`) — POST search returns email, username, name, password indicators per record
- BreachDirectory integration (`BREACHDIRECTORY_API_KEY`) via RapidAPI — returns source database names and credential indicators
- Leak-Lookup integration (`LEAKLOOKUP_API_KEY`) — phone_number query type against `leak-lookup.com/api/search`
- Scylla.sh integration — public unauthenticated search; returns email, username, name per breach record

**New modules**
- `signal` (active, no key) — Signal registration check via HMAC-SHA256 hashed CDN lookup; photo retrieval and pHash capture; 3-second rate limit; result integrated into `MessengerReport`
- `infrastructure` (active) — crt.sh SSL certificate transparency, WHOIS/RDAP via `rdap.org`, VirusTotal cross-reference (`VIRUSTOTAL_API_KEY`), MalwareBazaar search (keyless)
- `intelligence` (active) — OpenSanctions sanctions and PEP screening across 100+ official lists (`OPENSANCTIONS_API_KEY` optional); adverse-media screening with risk keyword extraction
- `image_intelligence` (active, PostMessengerModule) — TinEye reverse image search (`TINEYE_API_KEY`); Google Lens, Yandex, Bing, and TinEye web URL generation; cross-session pHash deduplication via SQLite with configurable Hamming threshold (`PHASH_HAMMING_THRESHOLD`, default: 10)

**Pivot commands**
- `phoneaccess pivot email <address>` — runs breach/search/paste against email; prints MailAccess cross-tool suggestion
- `phoneaccess pivot username <handle>` — searches 200+ platforms via enumerator service list
- `phoneaccess pivot domain <domain>` — crt.sh, WHOIS/RDAP, and VirusTotal against a domain
- `phoneaccess pivot name "Full Name"` — targeted search dorks via search module
- `phoneaccess pivot phone <number>` — full passive (or `--active`) investigation on a second number; supports `--compact`, `--field`, `--yes`, `--timeout`
- All pivot types support `--format json`, `--no-save`, `--case <id>`

**Cases workflow**
- `cases show <id>` — renders full terminal report; lists linked pivot investigations in a LINKED PIVOTS table
- `cases tag <id> <tag>` — add a searchable tag to a case
- `cases note <id> <text>` — attach a free-text note
- `cases name <id> <name>` — set a display name
- `cases delete <id>` — delete case and all linked pivot records
- `cases search <query>` — full-text search across names, tags, notes, and phone numbers

**Output modes**
- `--compact` / `--format compact` — ≤6-line triage summary with colour-coded risk band; zero-value fields omitted; wraps at 80 columns; config: `PHONEACCESS_COMPACT=true`
- `--field` / `--format field` — single pipe-delimited line (`e164|risk_band|risk_score|carrier|line_type|country|breach_count|service_hits|top_name|messengers`) for grep and scripting; no colour codes
- `--min-confidence <float>` — hide terminal findings below confidence threshold (0.0–1.0); JSON always includes all findings; config: `PHONEACCESS_MIN_CONFIDENCE`
- Both compact and field modes supported in batch mode and `pivot phone`

**Webhook**
- `--webhook <url>` per-run override; when set via flag the risk-minimum filter is bypassed
- HMAC-SHA256 signing via `PHONEACCESS_WEBHOOK_SECRET`; adds `X-PhoneAccess-Signature: sha256=<hex>` header
- Discord auto-detection: payloads to `discord.com/api/webhooks/` are reformatted as Discord embeds
- Batch mode fires one notification per investigation as it completes
- Config keys: `PHONEACCESS_WEBHOOK_URL`, `PHONEACCESS_WEBHOOK_SECRET`, `PHONEACCESS_WEBHOOK_RISK_MIN`

**User-Agent hardening**
- 22-variant browser UA pool (Chrome Windows/macOS, Firefox Windows/Linux, Safari macOS, Chrome Android)
- Three modes: `fixed` (one consistent UA per run, default), `random` (new UA per request), `custom` (operator-supplied string)
- Browser-appropriate header injection: `Accept`, `Accept-Language`, `Sec-CH-UA`, `Sec-Fetch-*`; Safari UAs omit `Sec-CH-UA` to match real browser behaviour
- Rate-limit delays include ±30% random jitter
- Flags: `--ua-mode`, `--user-agent`; config: `PHONEACCESS_UA_MODE`, `PHONEACCESS_USER_AGENT`

**Additional export formats**
- GEXF graph export (`--format gexf`, `-o report.gexf`) for identity graph visualisation
- JSON-LD export (`--format jsonld`, `-o report.jsonld`) for linked-data consumers

### Changed

- `Module` interface gains `ProxyAware() bool` — all built-in modules implement this; custom modules must be updated
- `investigate --active` now displays an OPSEC pre-flight prompt before running; use `--yes` to skip
- The `--webhook` flag, when set directly, bypasses `PHONEACCESS_WEBHOOK_RISK_MIN` and fires on every result regardless of risk band
- Batch output (`phoneaccess_batch_<timestamp>.csv` and `.json`) is unchanged but batch webhook fires per-investigation rather than once at completion
- `cases show` now renders linked pivot investigations beneath the main report

### Security

- Session files (Telegram, WhatsApp) encrypted at rest using AES-256-GCM; no plaintext session data remains on disk after first post-upgrade run
- DNS-over-HTTPS prevents resolver-level surveillance of investigation targets
- Proxy/Tor routing prevents direct IP exposure to probed services
- OPSEC pre-flight prompt surfaces current network configuration before active probing begins
- HMAC-SHA256 webhook signing allows receivers to verify payload authenticity

---

## [1.0.0] - 2026-05-28

### Added

- Initial release
- Passive modules: carrier, voip, geo, spam, breach, reverse
- Active modules: enumerator (200+ services), finance (Venmo opt-in), search (Google CSE, Bing), public_records (SEC EDGAR, OpenCorporates, Companies House, PACER, licence registries), paste, truecaller (session token), telegram (MTProto), whatsapp (session)
- Risk scorer (0–100, LOW/MODERATE/HIGH/CRITICAL) with driver breakdown and one-sentence summary
- Identity correlator: jurisdiction-aware name/address/DOB/email/social-link aggregation with source tier provenance
- Investigation timeline with first-seen/last-seen calculation
- Identity graph (GEXF, JSON-LD export)
- Batch mode (`--batch`) with CSV and JSON output
- Cases database (SQLite): save, list investigations; cross-pivot match detection on prior emails and usernames
- Export formats: terminal, JSON, CSV, PDF, TXT
- `phoneaccess keys` for local encrypted API key storage
- `phoneaccess setup whatsapp` / `phoneaccess setup telegram` for session initialisation
- Optional API keys: NUMVERIFY, VERIPHONE, ABSTRACT, IPQS, OPENCNAM, NUMLOOKUP, LEAKSIGHT, TRESTLE, HIBP, DEHASHED, INTELX, GOOGLE CSE, BING, OPENCORPORATES, PACER, GITHUB, TWILIO, TRUECALLER, TELEGRAM MTProto, OPENSANCTIONS
