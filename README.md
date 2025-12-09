# Zeta Crypto CLI

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](./LICENSE)
![Language: Rust](https://img.shields.io/badge/language-Rust-orange)
![Network: Base](https://img.shields.io/badge/network-Base_Mainnet-blue)
![Status: Active](https://img.shields.io/badge/status-active-green)

`zeta-crypto` is a powerful Rust-based command-line tool designed for the **Base Network** ecosystem. It features a fully functional CLI wallet, **Basenames** resolution support, cryptographic primitives, and WalletConnect session management.

Built with **Alloy**, **Tokio**, and **Rust** for maximum performance and type safety.

---

## 🔵 Base Network Features

Interact directly with the Base Mainnet.

### Check Balance
Query the native ETH balance of any address or Basename.

```bash
# Using a hex address
zeta-cli base balance 0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045

# Using a Basename (auto-resolves)
zeta-cli base balance jesse.base
```

**Output:**
```
Balance: 0.0842 ETH
```

### Resolve Basenames
Resolve `.base` (and `.eth`) names to their underlying addresses using the official L2 Resolver.

```bash
zeta-cli base resolve den.base
```

**Output:**
```
Resolving den.base...
den.base -> 0x2211d1D0020DAEA8039E46Cf1367962070d77DA9
```

### Send ETH
Send Ether transactions. Supports both raw addresses and Basenames as destinations.

```bash
zeta-cli base send \
  --phrase "seed phrase here..." \
  --to jesse.base \
  --amount 0.001
```

**Features:**
* **Auto-Resolution:** Automatically detects if `--to` is a Basename and resolves it before sending.
* **Safety:** Derives private key locally from mnemonic; keys are never stored in plaintext.

**Output:**
```
Resolving destination: jesse.base
Sending 0.001 ETH to 0x2211...
Transaction sent! Hash: 0xab12...
```

---

## 🔐 Crypto Primitives

#### Generate Mnemonic
```bash
zeta-cli gen-mnemonic
```
Generates a new secure BIP39 mnemonic phrase.

#### Derive Wallet Address
```bash
zeta-cli derive-wallet --phrase "<mnemonic>" --pass "<optional_password>"
```
Derives the Ethereum/Base address (0x...) from the mnemonic.

#### Sign Message
```bash
zeta-cli sign --phrase "<mnemonic>" --msg "hello base"
```
Signs a message using the derived private key (ECDSA).

#### Verify Signature
```bash
zeta-cli verify --pubhex <public_key_hex> --msg "hello base" --sig <signature_hex>
```
Verifies a cryptographic signature.

---

## 🔗 WalletConnect Tools

Manage WalletConnect sessions for testing and development.

#### Connect / Disconnect
```bash
# Connect to a peer
zeta-cli walletconnect <PEER_URI> connect

# Disconnect
zeta-cli walletconnect <PEER_URI> disconnect
```

#### Session Management
```bash
# Save a default peer for future use
zeta-cli walletconnect-save --peer "wc:..."

# Check status of specific peer
zeta-cli walletconnect-status --peer "wc:..."

# View restored session info
zeta-cli walletconnect-restore
```

---

## 🛠 System & Config

#### Health Check
Verify the integrity of local configuration and log files.
```bash
zeta-cli healthcheck
```

#### Configuration
View current configuration (including default peer).
```bash
zeta-cli config-show
```
*Config location:* `~/.zeta_crypto/config.toml`

#### Logs
View logs, paths, or clear history.
```bash
zeta-cli log-path      # Show log path
zeta-cli log-size      # Check log size
zeta-cli clear-logs    # Clear log history
zeta-cli cleanup       # Remove all local data (logs/sessions)
```

---

### Installation & Build

Ensure you have Rust installed, then build in release mode for optimal performance:

```bash
cargo build --release
./target/release/zeta-cli version-info
```

### License
MIT