# envsh

Zero-knowledge secret sync. The server can't read your secrets — by design, not by promise.

## Install

```bash
curl -fsSL https://envsh.dev/install.sh | sh
```

## Usage

```bash
envsh login                          # authenticate
envsh push -p myapp -e production    # encrypt & push secrets
envsh pull -p myapp -e production    # pull & decrypt secrets
envsh run -p myapp -e production -- node app.js  # inject into process
```

## Documentation

Full docs at **[envsh.dev](https://envsh.dev)**

## What's in this repo

- **`cmd/cli/`** — The `envsh` CLI
- **`pkg/crypto/`** — Cryptographic library (AES-256-GCM, Ed25519, X25519, HKDF)
- **`pkg/sdk/`** — Go SDK client

## License

MIT
