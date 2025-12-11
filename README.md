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
Query the native ETH or USDC balance of any address or Basename.

```bash
# ETH Balance
zeta-cli base balance jesse.base

# USDC Balance
zeta-cli base balance-usdc jesse.base
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

### Send Assets
Send Ether or USDC transactions. Supports both raw addresses and Basenames as destinations.

```bash
# Send ETH
zeta-cli base send --phrase "..." --to jesse.base --amount 0.001

# Send USDC
zeta-cli base send-usdc --phrase "..." --to jesse.base --amount 5.0
```

**Features:**
* **Auto-Resolution:** Automatically detects if `--to` is a Basename and resolves it before sending.
* **Safety:** Derives private key locally from mnemonic; keys are never stored in plaintext.

---

## 🏗 Builder Tools (MultiSender)

Deploy and interact with the ZetaMultiSender contract (Disperse) to batch transactions and generate on-chain activity.

### Deploy Contract
Deploy your own instance of the MultiSender contract to Base.

```bash
zeta-cli base deploy --phrase "your mnemonic phrase"
```

**Output:**
```
Deploying ZetaMultiSender contract...
Contract deployed successfully!
Address: 0x...
```

### Disperse ETH (Batch Send)
Send ETH to multiple recipients in a single transaction.

Format: `address=amount_in_eth`

```bash
zeta-cli base disperse-eth \
  --phrase "your mnemonic phrase" \
  --contract 0xYourContractAddress... \
  0xRecipient1...=0.001 \
  0xRecipient2...=0.002 \
  vitalik.eth=0.005
```

**Features:**
* **Gas Saving:** Significantly cheaper than sending individual transactions.
* **Auto-Resolution:** Supports Basenames/ENS in the recipient list.
* **Safety:** Excess ETH sent to the contract is automatically refunded.

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