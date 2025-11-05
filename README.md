# Zeta Crypto CLI

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

**Output:**
```
✅ WalletConnect peer is active and reachable
```
or
```
⚠️ Unable to reach peer or session inactive
```

---

### License
MIT

