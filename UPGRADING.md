# Upgrading to v2.0.0

## From v1.0.x

### Automatic changes (no action required)

**Session file encryption.** Telegram and WhatsApp session files are now encrypted at rest using AES-256-GCM. On the first run after upgrading, any existing plaintext session files are detected by the absence of the `PHAC` file header and automatically re-encrypted using the machine ID as the key. No session data is lost and no operator action is required.

The default key source (`SESSION_KEY_SOURCE=machine`) is transparent: the encrypted file can be read only on the machine where it was created. If portability between machines is needed, set `SESSION_KEY_SOURCE=passphrase` before the first post-upgrade run; you will be prompted for a passphrase on each use.

**Suppressed identity findings now visible.** Terminal output previously hid identity candidates below confidence 0.45; those candidates now display with a `?` prefix. If your workflow relied on the old suppression behaviour, set `PHONEACCESS_MIN_CONFIDENCE=0.45` to restore it.

---

### Scripts and automation using `--active`

Add `--yes` (or `-y`) to skip the new OPSEC pre-flight prompt:

```
# v1 — worked non-interactively
phoneaccess investigate +14155552671 --active

# v2 — add --yes
phoneaccess investigate +14155552671 --active --yes
```

The prompt is skipped automatically when stdin is not a TTY and `--yes` is set. Omitting `--yes` in a non-interactive context (CI, cron, piped script) will cause the run to block waiting for input and eventually fail.

Batch runs with `--batch --active` require the same addition:

```
phoneaccess investigate phones.txt --batch --active --yes
```

---

### Custom modules (if any)

The `core.Module` interface has two new required methods in v2. Existing custom modules will not compile until both are added.

**Add `ProxyAware() bool`:**

```go
// Return true if the module routes all requests through the shared
// http.DefaultTransport (which carries the active proxy, if any).
// Return false only if the module opens direct connections that bypass
// the proxy — the engine will log a warning when a proxy is active.
func (m *MyModule) ProxyAware() bool { return true }
```

Most modules should return `true`. Return `false` only if your module opens raw TCP or TLS connections outside the standard `http.Client`.

`Tier() core.ModuleTier` was already required in v1; no change needed there.

---

### New optional configuration

None of the new keys introduced in v2 are required. The tool operates without them and they only unlock additional data sources or features.

If you want to pre-configure the new capabilities:

```sh
# Route all runs through Tor
phoneaccess keys set TOR_ENABLED true

# Enable DNS-over-HTTPS with Google
phoneaccess keys set PHONEACCESS_DOH_ENABLED true
phoneaccess keys set PHONEACCESS_DOH_PROVIDER google

# Add new breach sources
phoneaccess keys set SNUSBASE_API_KEY <key>
phoneaccess keys set BREACHDIRECTORY_API_KEY <rapidapi-key>
phoneaccess keys set LEAKLOOKUP_API_KEY <key>

# Threat intelligence
phoneaccess keys set VIRUSTOTAL_API_KEY <key>
phoneaccess keys set OPENSANCTIONS_API_KEY <key>

# Image intelligence
phoneaccess keys set TINEYE_API_KEY <key>

# Webhook
phoneaccess keys set PHONEACCESS_WEBHOOK_URL https://hooks.slack.com/...
phoneaccess keys set PHONEACCESS_WEBHOOK_RISK_MIN HIGH
```

Run `phoneaccess keys list` to see all available keys and which are currently configured.

---

### Binary size and resource usage

v2 adds several modules and the session crypto package. Binary size increases by approximately 10–15% over v1.0.6. SQLite storage now persists photo hashes in addition to investigation records; no manual database migration is needed.
