# Zeta Crypto CLI

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](./LICENSE)
![Language: Rust](https://img.shields.io/badge/language-Rust-orange)
![Network: Base](https://img.shields.io/badge/network-Base_Mainnet-blue)
![Status: Production](https://img.shields.io/badge/status-production-green)

`zeta-crypto` is a professional-grade Rust command-line tool for the **Base Network**. It provides a secure wallet, **Basenames** resolution, and advanced developer tools like **Batch Transfers (Disperse)** and **Contract Deployment**.

Built with **Alloy**, **Tokio**, and **Rust** for maximum performance and type safety.

---

## 🔐 Security & Setup

To avoid exposing your seed phrase in command history, use environment variables.

```bash
export ZETA_PHRASE="your twelve words mnemonic phrase here"
export ZETA_PASS="optional_password" # Optional
```

Once set, you can run commands without the `--phrase` flag.

---

## 🔵 Base Network Features

Interact directly with the Base Mainnet (Chain ID: 8453).

### Check Balance
Query ETH or USDC balance.

```bash
# ETH Balance
zeta-cli base balance jesse.base

# USDC Balance
zeta-cli base balance-usdc jesse.base
```

### Resolve Basenames
Resolve `.base` (and `.eth`) names using the official L2 Resolver.

```bash
zeta-cli base resolve den.base
# Output: den.base -> 0x...
```

### Send Assets
Send Ether or USDC. Supports auto-resolution of Basenames.

```bash
# Send ETH
zeta-cli base send --to jesse.base --amount 0.001

# Send USDC
zeta-cli base send-usdc --to jesse.base --amount 5.0
```

---

## 🏗 Builder Tools (MultiSender)

Deploy and interact with the ZetaMultiSender contract (Disperse) to batch transactions.

### 1. Deploy Contract
Deploy your own instance of the MultiSender contract to Base.

```bash
zeta-cli base deploy
```
*Save the contract address from the output.*

### 2. Disperse ETH
Send ETH to multiple recipients in a single transaction.

```bash
zeta-cli base disperse-eth \
  --contract 0xYourContractAddress... \
  0xRecipient1...=0.001 \
  vitalik.eth=0.005
```

### 3. Disperse USDC (ERC-20)
Batch send ERC-20 tokens. Requires approval first.

**Step A: Approve**
Allow the MultiSender contract to spend your USDC.
*(USDC Address on Base: 0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913)*

```bash
zeta-cli base approve \
  --token 0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913 \
  --spender 0xYourContractAddress... \
  --amount 100 \
  --decimals 6
```

**Step B: Disperse**
```bash
zeta-cli base disperse-token \
  --contract 0xYourContractAddress... \
  --token 0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913 \
  --decimals 6 \
  0xRecipient1...=10.5 \
  jesse.base=50.0
```

---

## 🔐 Crypto Primitives

#### Generate Mnemonic
```bash
zeta-cli gen-mnemonic
```

#### Derive Wallet Address
```bash
zeta-cli derive-wallet --phrase "..."
```

#### Sign Message
```bash
zeta-cli sign --phrase "..." --msg "hello base"
```

#### Verify Signature
```bash
zeta-cli verify --pubhex <public_key_hex> --msg "hello base" --sig <signature_hex>
```

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