# Zeta Crypto CLI

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](./LICENSE)
![Language: Rust](https://img.shields.io/badge/language-Rust-orange)
![Status: Experimental](https://img.shields.io/badge/status-experimental-blueviolet)
![CLI](https://img.shields.io/badge/type-CLI-blue)

`zeta-crypto` is a lightweight Rust-based command-line tool for experimenting with wallet functionality, mnemonic generation, signing, and WalletConnect sessions.

---

### Commands Overview

#### Generate Mnemonic
```bash
zeta-cli gen-mnemonic
```
Generates a new BIP39 mnemonic phrase.

#### Derive Wallet
```bash
zeta-cli derive-wallet --phrase "<mnemonic>" --pass "<optional password>"
```
Derives a wallet address from a mnemonic phrase.

#### Sign Message
```bash
zeta-cli sign --phrase "<mnemonic>" --msg "hello world"
```
Signs a message using the wallet’s private key.

#### Verify Signature
```bash
zeta-cli verify --pubhex <public_key_hex> --msg "hello world" --sig <signature>
```
Verifies a previously signed message.

#### WalletConnect
```bash
zeta-cli walletconnect --peer <peer_url> --action connect
```
Establish or disconnect a WalletConnect session with a peer.

---

### WalletConnect Status

Check if a WalletConnect peer is active and reachable.

```bash
zeta-cli walletconnect-status --peer "wc:example@2?relay-protocol=irn&symKey=..."
```

**Output:**
```
✅ WalletConnect peer is active and reachable
```
or
```
⚠️ Unable to reach peer or session inactive
```

---

### WalletConnect Info

Display detailed information about a WalletConnect peer, including its status and last update timestamp.

```bash
zeta-cli walletconnect-info --peer "wc:example@2?relay-protocol=irn&symKey=..."
```

**Output:**
```
Peer: wc:example@2?relay-protocol=irn&symKey=...
Status: connected (updated at 1730573102)
```

This command helps monitor the current state of a WalletConnect session and can be used together with `walletconnect-status` to perform basic connection health checks.

---

### WalletConnect Restore

You can restore the last saved WalletConnect session from local storage.

```bash
zeta-cli walletconnect-restore
```

**Example output:**
```
Restored session:
Peer: wc:example@2?relay-protocol=irn&symKey=...
Status: connected (updated at 1730580445)
```

If no saved session is found, the CLI will display:
```
No saved WalletConnect session found
```

---

### WalletConnect Default & Config

You can define a default peer and optional auto-connect setting in `~/.zeta_crypto/config.toml`.

**Example:**
```toml
default_peer = "wc:example@2?relay-protocol=irn&symKey=..."
auto_connect = true
```

Use this configuration to simplify WalletConnect usage:

```bash
# Use the default peer from config to connect or disconnect
zeta-cli walletconnect-default connect
zeta-cli walletconnect-default disconnect

# Display current configuration
zeta-cli config-show
```

**Example output:**
```
ZetaConfig { default_peer: Some("wc:example@2?relay-protocol=irn&symKey=..."), auto_connect: Some(true) }
```

---

### Key Derivation (PBKDF2 / HKDF)

You can derive a secure key from a passphrase using PBKDF2 and HKDF functions implemented in the project.

```bash
zeta-cli derive-key --pass "mysecretpassword"
```

This will generate a deterministic key derived from the given passphrase. The derivation process uses PBKDF2 with HMAC-SHA256 and HKDF for additional entropy expansion.

**Example output:**
```
Derived key (hex): 4f3a12c6b7a9c1e3f6d8...
```

This can be useful for generating session secrets, encryption keys, or other secure materials in crypto-related workflows.

---

### License
MIT

