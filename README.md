# envsh

Open-source CLI and cryptographic library for [envsh](https://github.com/envshq/envsh) — zero-knowledge secret sync.

> "The only secrets manager that can't read your secrets."

## What's in here

- **`pkg/crypto/`** — MIT-licensed cryptographic library (AES-256-GCM, Ed25519↔X25519, HKDF, SSH key parsing)
- **`pkg/sdk/`** — Go SDK client for the envsh API
- **`cmd/cli/`** — The `envsh` CLI binary

## Quick start

```bash
make build              # compile → bin/envsh
./bin/envsh --help

make test               # all tests with race detector
make test-crypto        # crypto library tests only (verbose)
```

For full setup instructions see [`DEV_GUIDE.md`](../DEV_GUIDE.md).

## Crypto library

```go
import "github.com/envshq/envsh/pkg/crypto"

// Encrypt for multiple recipients (SSH public keys)
bundle, err := crypto.EncryptForRecipients(plaintext, recipients)

// Decrypt with your private key
plaintext, err := crypto.DecryptWithPrivateKey(bundle, privKey, fingerprint, "ed25519")
```

## Module

`github.com/envshq/envsh` — Go 1.22+ — MIT License
