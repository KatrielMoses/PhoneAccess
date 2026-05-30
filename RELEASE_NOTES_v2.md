# PhoneAccess v2.0.0

## What's New

### Phase 1 — OPSEC Hardening

#### 1a — Proxy and Tor Routing

All outbound requests now route through an operator-supplied proxy. Pass a SOCKS5 or HTTP proxy URL directly, or use the `--tor` shorthand which targets `127.0.0.1:9050`. A pre-flight TCP connectivity check runs before any modules execute; for Tor, the check verifies the circuit via `check.torproject.org/api/ip`. Use `--tor-skip-check` to bypass for offline testing.

```
--proxy socks5://127.0.0.1:9050
--proxy http://user:pass@proxy.host:8080
--tor
--tor-address 127.0.0.1:9150   # custom Tor port
--tor-skip-check                # skip circuit verification
```

Config keys: `PROXY_URL`, `TOR_ENABLED`, `TOR_ADDRESS`

Modules report proxy-awareness; any module that cannot route through the proxy emits a warning before the run proceeds.

#### 1b — DNS-over-HTTPS

DNS queries are forwarded over HTTPS (RFC 8484) to prevent resolver leaks. Three providers are built in: Cloudflare (default), Google, and Quad9. A custom URL can be supplied. When a SOCKS5 or Tor proxy is active, DoH queries route through it so the DNS provider never sees the operator's real IP.

```
--doh
--doh-provider google
--doh-provider https://custom.resolver.example/dns-query
```

Config keys: `PHONEACCESS_DOH_ENABLED`, `PHONEACCESS_DOH_PROVIDER`

#### 1c — Session File Encryption

Telegram and WhatsApp session files (`~/.phoneaccess/telegram_session.json`, `~/.phoneaccess/whatsapp_session.db`) are now encrypted at rest using AES-256-GCM with a per-file random nonce. The default key source is the machine ID (`SESSION_KEY_SOURCE=machine`), making encryption transparent on the machine where the session was created. Two additional modes are supported: `passphrase` (PBKDF2-SHA256, 100,000 iterations) and `both` (PBKDF2 over passphrase + machine ID). Existing plaintext session files are automatically migrated to encrypted storage on the next run.

Config key: `SESSION_KEY_SOURCE`  
Values: `machine` (default), `passphrase`, `both`

#### OPSEC Pre-flight Prompt

Runs that include active modules now display a pre-flight summary of the current OPSEC state (proxy, DoH, UA mode) and ask for confirmation before proceeding. For non-interactive or scripted use, pass `--yes` / `-y` to skip the prompt.

---

### Phase 2 — Source Expansion

#### 2a — Breach Module: Four Additional Sources

| Source | Key Required | Notes |
| --- | --- | --- |
| Snusbase | `SNUSBASE_API_KEY` | POST search against Snusbase API; returns email, username, name, password hash indicators |
| BreachDirectory | `BREACHDIRECTORY_API_KEY` | Via RapidAPI (`breachdirectory.p.rapidapi.com`); returns source database names and password indicators |
| Leak-Lookup | `LEAKLOOKUP_API_KEY` | `leak-lookup.com/api/search`; phone_number query type |
| Scylla.sh | none | Public unauthenticated search; returns email, username, name per breach record |

All four sources are integrated into the existing `breach` module result schema (`BreachEntry` with `SourceAPI` field indicating origin). Credential presence is signalled without exposing plaintext passwords.

#### 2b — Signal Discovery Module

New active module (`signal`) that checks Signal registration status using HMAC-SHA256 hashed phone number lookup against Signal's CDN (`storage.signal.org`). No API key required. Profile photo retrieval and pHash capture are supported when a photo is available. Minimum 3-second inter-request delay is enforced. Module output is integrated into `MessengerReport` alongside Telegram and WhatsApp.

#### 2c — Infrastructure Intelligence Module

New passive/active module (`infrastructure`) that runs four sub-checks:

- **crt.sh SSL Certificate Transparency** — queries certificate logs for domains associated with the number; returns domain, issuer, and issuance date per certificate
- **WHOIS/RDAP** — queries `rdap.org` for registrant name, email, and registration date
- **VirusTotal** — cross-references the number and associated domains against VirusTotal threat intelligence; returns malicious/suspicious hit count and threat labels (`VIRUSTOTAL_API_KEY` required)
- **MalwareBazaar** — searches Abuse.ch MalwareBazaar for malware samples referencing the number; no key required

#### 2d — Image Intelligence Module

New active module (`image_intelligence`) that runs after messenger modules complete (implements `PostMessengerModule`):

- **TinEye reverse image search** — submits the profile photo to TinEye; returns match count, originating domains, and crawl dates (`TINEYE_API_KEY` required; 2-second rate limit enforced)
- **Search URL generation** — constructs direct search URLs for Google Lens, Yandex Images, Bing Images, and TinEye web for manual follow-up
- **Cross-session pHash deduplication** — computes a perceptual hash (pHash) of every profile photo and stores it in SQLite; subsequent investigations search for prior cases with a Hamming distance below `PHASH_HAMMING_THRESHOLD` (default: 10), surfacing identity overlaps across separate investigations

#### Intelligence Module

New active module (`intelligence`) covering two sub-screens:

- **Sanctions and PEP screening** — queries OpenSanctions (`opensanctions.org/api`) against OFAC SDN, UN Consolidated, EU Asset Freeze, UK HMT, and 100+ additional official lists; returns entity match, dataset provenance, position, nationality, and birth date where available. The search endpoint always runs without a key; `OPENSANCTIONS_API_KEY` unlocks higher rate limits and the match API endpoint.
- **Adverse media screening** — searches public news sources for the phone number and associated identities; returns article title, source, publication date, snippet, and risk keyword extraction.

---

### Phase 3 — Workflow

#### 3a — Pivot Commands

New `pivot` subcommand with five pivot types:

```
phoneaccess pivot email <address>
phoneaccess pivot username <handle>
phoneaccess pivot domain <domain>
phoneaccess pivot name "Full Name"
phoneaccess pivot phone <number>
```

All pivot types support:
- `--format json` — machine-readable output
- `--no-save` — skip SQLite persistence
- `--case <id>` — link pivot to a parent case ID

**pivot email** runs breach, search, and paste modules against the email address, and prints a MailAccess cross-tool suggestion.

**pivot username** queries the full enumerator service list (200+ platforms) for username presence; returns platform and profile URL per hit.

**pivot domain** runs crt.sh certificate transparency, WHOIS/RDAP, and VirusTotal (when `VIRUSTOTAL_API_KEY` is set) against a domain artifact.

**pivot name** executes targeted search dorks (`"Name" phone`, `"Name" phone number`) via the search module.

**pivot phone** runs a full passive investigation on a second phone number. Additional flags: `--active`, `--yes`, `--timeout`, `--compact`, `--field`.

#### 3b — Cases Workflow Expansion

`cases` subcommands added beyond the original `cases list`:

| Subcommand | Description |
| --- | --- |
| `cases show <id>` | Render the full terminal report for a saved case; linked pivot investigations are listed in a LINKED PIVOTS table |
| `cases tag <id> <tag>` | Add a tag to a case |
| `cases note <id> <text>` | Attach a free-text note to a case |
| `cases name <id> <name>` | Set a display name for a case |
| `cases delete <id>` | Delete a case and all its linked pivot investigations |
| `cases search <query>` | Full-text search across case names, tags, notes, and phone numbers |

#### 3b — Output Modes

- **Compact mode** (`--compact` or `--format compact`) — ≤6-line triage summary; colour-coded risk band; omits zero-value fields; wraps at 80 columns. Persist as default: `PHONEACCESS_COMPACT=true`.
- **Field mode** (`--field` or `--format field`) — single pipe-delimited line for grep and scripting: `e164|risk_band|risk_score|carrier|line_type|country|breach_count|service_hits|top_name|messengers`. No colour codes.
- **Confidence filtering** (`--min-confidence <0.0–1.0>`) — hides terminal findings below the threshold; JSON output always includes all findings. Persist: `PHONEACCESS_MIN_CONFIDENCE`.
- Both compact and field modes are supported in batch mode and in `pivot phone`.

#### 3b — Webhook Improvements

- `--webhook <url>` flag — per-run webhook override; when set via flag (not config), the risk minimum filter is bypassed and every result fires a notification.
- HMAC-SHA256 signing via `PHONEACCESS_WEBHOOK_SECRET` — adds `X-PhoneAccess-Signature: sha256=<hex>` to every delivery.
- Discord auto-detection — payloads to `discord.com/api/webhooks/` are automatically reformatted as Discord embeds.
- Batch mode — one webhook notification per investigation, not one summary at the end.

---

## Breaking Changes

### Module Interface: `ProxyAware() bool`

The `core.Module` interface has a new required method:

```go
ProxyAware() bool
```

Any code that implements a custom module against v1 will fail to compile. Add the method returning `true` (most modules) or `false` (if the module makes direct connections that cannot be proxied). The engine logs a warning for any `false` module when a proxy is active.

### Session Files Encrypted by Default

Telegram and WhatsApp session files are now AES-256-GCM encrypted on write. On first run after upgrading, any existing plaintext session files are detected (by absence of the `PHAC` magic header) and automatically re-encrypted using the machine key. No session data is lost; no operator action is required unless `SESSION_KEY_SOURCE=passphrase` or `both` is desired.

### OPSEC Pre-flight Prompt on `--active` Runs

Scripts and automation that pass `--active` will now block on an interactive prompt asking the operator to confirm the current OPSEC state. Add `--yes` (or `-y`) to restore non-interactive behaviour:

```
phoneaccess investigate +14155552671 --active --yes
```

---

## Upgrade from v1.0.x

See [UPGRADING.md](UPGRADING.md) for the step-by-step guide.

---

## New Config Keys

Keys added in v2. None are required — existing v1 configurations continue to work without change.

| Key | Free Tier | Purpose |
| --- | --- | --- |
| `PROXY_URL` | — | Proxy URL (socks5://, http://) for all requests |
| `TOR_ENABLED` | — | Set `true` to route through Tor on every run |
| `TOR_ADDRESS` | — | Custom Tor SOCKS5 address (default: `127.0.0.1:9050`) |
| `PHONEACCESS_DOH_ENABLED` | — | Set `true` to enable DNS-over-HTTPS on every run |
| `PHONEACCESS_DOH_PROVIDER` | — | `cloudflare` (default), `google`, `quad9`, or custom URL |
| `SESSION_KEY_SOURCE` | — | Session encryption key: `machine` (default), `passphrase`, `both` |
| `SNUSBASE_API_KEY` | — | Snusbase breach intelligence |
| `BREACHDIRECTORY_API_KEY` | — | BreachDirectory via RapidAPI |
| `LEAKLOOKUP_API_KEY` | — | Leak-Lookup breach search |
| `VIRUSTOTAL_API_KEY` | 500 req/day | VirusTotal threat intelligence (infrastructure module + pivot domain) |
| `OPENSANCTIONS_API_KEY` | 10,000 req/month | Higher rate limits and match API for OpenSanctions |
| `TINEYE_API_KEY` | 100 searches/month | TinEye reverse image search |
| `PHASH_HAMMING_THRESHOLD` | — | Cross-session photo dedup sensitivity (default: `10`; lower = stricter) |
| `PHONEACCESS_USER_AGENT` | — | Custom UA string (used when `--ua-mode=custom`) |
| `PHONEACCESS_UA_MODE` | — | `fixed` (default), `random`, `custom` |
| `PHONEACCESS_MIN_CONFIDENCE` | — | Default minimum confidence for terminal display (0.0–1.0) |
| `PHONEACCESS_COMPACT` | — | Set `true` to default to compact triage output |
| `PHONEACCESS_WEBHOOK_URL` | — | Webhook endpoint; supports Slack, Discord (auto-detected), generic HTTPS |
| `PHONEACCESS_WEBHOOK_SECRET` | — | HMAC-SHA256 signing secret for webhook payload verification |
| `PHONEACCESS_WEBHOOK_RISK_MIN` | — | Minimum risk band to fire webhook: `LOW`, `MODERATE`, `HIGH` (default), `CRITICAL` |

---

## New CLI Commands and Flags

### `phoneaccess pivot`

```
phoneaccess pivot email <address>    [--format json] [--no-save] [--case <id>]
phoneaccess pivot username <handle>  [--format json] [--no-save] [--case <id>]
phoneaccess pivot domain <domain>    [--format json] [--no-save] [--case <id>]
phoneaccess pivot name "Full Name"   [--format json] [--no-save] [--case <id>]
phoneaccess pivot phone <number>     [--format json] [--no-save] [--case <id>]
                                     [--active] [--yes] [--timeout <secs>]
                                     [--compact] [--field]
```

### `phoneaccess cases` (new subcommands)

```
phoneaccess cases show <id>
phoneaccess cases tag <id> <tag>
phoneaccess cases note <id> <text>
phoneaccess cases name <id> <name>
phoneaccess cases delete <id>
phoneaccess cases search <query>
```

### New `investigate` flags

| Flag | Config Key | Description |
| --- | --- | --- |
| `--proxy <url>` | `PROXY_URL` | Route requests through HTTP or SOCKS5 proxy |
| `--tor` | `TOR_ENABLED` | Route through Tor (127.0.0.1:9050) |
| `--tor-address <addr>` | `TOR_ADDRESS` | Custom Tor SOCKS5 address |
| `--tor-skip-check` | — | Skip Tor circuit verification |
| `--doh` | `PHONEACCESS_DOH_ENABLED` | Enable DNS-over-HTTPS |
| `--doh-provider <name\|url>` | `PHONEACCESS_DOH_PROVIDER` | DoH provider: cloudflare, google, quad9, or custom URL |
| `--user-agent <string>` | `PHONEACCESS_USER_AGENT` | Custom User-Agent string |
| `--ua-mode <mode>` | `PHONEACCESS_UA_MODE` | UA selection: fixed, random, custom |
| `--yes` / `-y` | — | Skip OPSEC pre-flight prompt (for scripts) |
| `--min-confidence <float>` | `PHONEACCESS_MIN_CONFIDENCE` | Hide terminal findings below confidence threshold |
| `--compact` | `PHONEACCESS_COMPACT` | ≤6-line triage summary output |
| `--field` | — | Single pipe-delimited line for scripting |
| `--webhook <url>` | `PHONEACCESS_WEBHOOK_URL` | Per-run webhook override (bypasses risk minimum filter) |
