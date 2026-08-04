# check-cert-revoke

SSL/TLS certificate revocation checker with **OCSP + CRL auto-fallback**, watch mode, and Telegram alerts.

- Connects to a domain, retrieves its certificate chain
- Checks revocation via **OCSP** (preferred), falls back to **CRL**
- **Watch mode** — continuous monitoring on a schedule
- **Telegram notifications** on status changes or errors
- JSON config file for one-command setup

## 1-line install (Linux)

```bash
sudo apt install python3-pip -y && python3 -m pip install cryptography && git clone https://github.com/otherot/check-cert-revoke.git && cd check-cert-revoke
```

Or with `pipx`:

```bash
pipx run --spec cryptography git+https://github.com/otherot/check-cert-revoke.git check_cert_revoke example.com
```

## Quick start

```bash
# Single domain
python check_cert_revoke.py example.com

# Multiple domains
python check_cert_revoke.py example.com google.com github.com

# From a file (one domain per line, # for comments)
python check_cert_revoke.py -f domains.txt
```

**Example `domains.txt`:**
```
example.com
google.com
internal-host:8443
```

## Watch mode (continuous monitoring)

```bash
# Check every hour, log everything
python check_cert_revoke.py -w -f domains.txt -l certs.log

# Check every 5 minutes, alert only on status changes
python check_cert_revoke.py -w -i 300 -a -l certs.log example.com
```

## Telegram alerts

1. Create a bot via [@BotFather](https://t.me/BotFather) and get the token
2. Get your chat ID (send a message to your bot, then visit `https://api.telegram.org/bot<TOKEN>/getUpdates`)

### Via config file (recommended)

```bash
cp config.example.json config.json
# Edit config.json with your bot token and chat ID
python check_cert_revoke.py --config config.json
```

### Via CLI flags

```bash
python check_cert_revoke.py -w -f domains.txt --telegram-token "123:abc" --telegram-chat-id "456"
```

## JSON config file

All options can be placed in `config.json`. CLI flags override config values.

```json
{
    "domains": ["example.com", "google.com"],
    "port": 443,
    "timeout": 10,
    "watch": true,
    "interval": 3600,
    "alert_only": true,
    "log_file": "/var/log/check-cert-revoke.log",
    "telegram": {
        "bot_token": "123456:ABC-DEF...",
        "chat_id": "123456789"
    }
}
```

Run with:

```bash
python check_cert_revoke.py --config config.json
```

## All CLI options

```
usage: check_cert_revoke.py [-h] [-f FILE] [-p PORT] [-t TIMEOUT] [-v]
                            [-w] [-i INTERVAL] [-l FILE] [-a] [-c CONFIG]
                            [--telegram-token TOKEN] [--telegram-chat-id ID]
                            [domains ...]

SSL/TLS certificate revocation checker (OCSP + CRL)

positional arguments:
  domains               One or more domain names to check

options:
  -f, --file FILE       File with domain list
  -p, --port PORT       Port to connect to (default: 443)
  -t, --timeout SEC     Connection timeout (default: 10)
  -v, --verbose         Verbose output
  -w, --watch           Run in continuous watch mode
  -i, --interval SEC    Check interval (default: 3600, only with --watch)
  -l, --log FILE        Log results to file
  -a, --alert           Suppress unchanged GOOD results (only with --watch)
  -c, --config FILE     JSON config file
  --telegram-token      Telegram bot token (overrides config)
  --telegram-chat-id    Telegram chat ID (overrides config)
```

## How it works

1. Connects to `host:port` via TLS, retrieves the certificate and issuer chain
2. **OCSP** — sends a request to the OCSP responder URL from the certificate's AIA extension
3. If OCSP fails or is unavailable → **CRL** — downloads the CRL from Distribution Points and checks the serial number
4. If both methods fail → reports `UNKNOWN`

## Linux systemd service (background daemon)

```bash
# Clone, install, and start as a service
git clone https://github.com/otherot/check-cert-revoke.git
cd check-cert-revoke
sudo bash install-service.sh
```

This installs to `/opt/check-cert-revoke`, creates a config at `/etc/check-cert-revoke/config.json`, and starts a systemd service.

**Manual setup:**

```bash
sudo cp check-cert-revoke.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now check-cert-revoke
```

**Management:**

```bash
systemctl status check-cert-revoke    # check status
journalctl -u check-cert-revoke -f    # follow logs
systemctl stop check-cert-revoke      # stop
systemctl restart check-cert-revoke   # restart
```

The service auto-restarts on failure with a 30-second delay.

## Requirements

- **Python 3.11+**
- **cryptography** (`pip install cryptography`)

No other dependencies — uses only stdlib + `cryptography`.

## Exit codes

| Code | Meaning |
|------|---------|
| 0    | All certificates are GOOD |
| 1    | At least one certificate is REVOKED, EXPIRED, or ERROR |

## License

MIT
