<img src="https://github.com/Kerimniy/Abotrep/blob/main/abotreplogo.png" style="width: 30%">
<p>На русском тута <a href="https://github.com/Kerimniy/Abotrep/blob/main/README-RU.md">тык</a></p>

# Abotrep

Lightweight reverse proxy built on **Axum** (Rust) that protects your backend from crawlers, simple bots, and overload:

- IP-based Rate Limiting  
- Antibot challenges: PoW, CAPTCHA (Cloudflare Turnstile or any custom), Custom  
- Proper `X-Forwarded-For` chain handling  
- Transparent request proxying to the target backend  
- Optional HTTPS support  

## 🚀 Quick Start

### 1. Build
```bash
cargo build --release
```

### 2. Configuration file (`config.json`)

```json
[
  {
    "url": "http://localhost:8080",                  // your backend address
    "proxy_host": "0.0.0.0:3000",                    // address:port the proxy listens on
    "is_blacklist_rate_limit": true,                 // true = blacklist mode (only listed paths are limited), false = whitelist
    "rate_limit": {
      "/api": { "limit": 10, "window": 5 }           // 10 requests per 5 seconds
    },
    "default_rate_limit": { "limit": 20, "window": 10 },

    "is_blacklist_antibot": false,                   // true = only listed paths require challenge
    "antibot": {
      "/login": "CAPTCHA",
      "/register": "PoW"
    },
    "default_antibot": "PoW",

    "is_secure": false,
    "cert_path": "",
    "cert_key_path": ""
  }
]
```

### 3. Generate cookie signing secret

File `.SECRETKEY` (64 random bytes):

## 📁 Templates & Static Files

Place challenge and error templates in the `templates/` directory:

```
templates/
├── captcha.html    ← Cloudflare Turnstile / hCaptcha / any slider captcha
├── pow.html        ← Proof-of-Work challenge page
├── custom.html     ← your own custom challenge page
├── 429.html        ← Too Many Requests
├── 500.html        ← Internal Server Error
├── 502.html        ← Bad Gateway
└── 504.html        ← Gateway Timeout
```

## 🧩 Antibot Challenge Types

### CAPTCHA
- Slider-based.
- Detects mouse behavior

### PoW (Proof-of-Work)
- Client must find a nonce such that the first **N** bits of SHA256(`token + nonce`) are zeros.
- Solution is sent via POST → `/powver`:
```json
{ "token": "random_str", "nonce": 123456, "bits": 20 }
```

### Custom Challenge
Configure in `config.json`:
```json
"antibot": {
  "/somepath": {
    "type": "Custom",
    "verify_url": "https://your-service/verify",
    "secret_key": "supersecret123"
  }
}
```
The proxy will forward `secret_key` + user token to your verification endpoint via POST → `/tokenver`.

## ⏳ Rate Limiting

- Tracks real client IP (even behind multiple proxies)
- `limit` — max requests allowed
- `window` — time window in seconds
- Prefix path matching via Trie (e.g., `/api/v1/` protects the entire subtree)

## 🔒 HTTPS Support

Set `"is_secure": true` and provide certificate paths:
```json
"cert_path": "/path/to/fullchain.pem",
"cert_key_path": "/path/to/privkey.pem"
```

## 🌐 Header Proxying

All headers are forwarded **except**:
- `host`
- `content-length`
- `connection`
- `transfer-encoding`
- `date`
- `content-encoding`

Automatically appends:
```
X-Forwarded-For: <client_ip>, <previous_proxy>, ...
```

## 📌 Verification Cookie

After successful challenge completion, a signed cookie is set:

```
checked=1
```

- Lifetime: **36 hours**
