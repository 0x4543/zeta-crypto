# Zeta Crypto

Tiny crypto playground for experimenting with wallets, signing, and verification.

## Features

- Generate Mnemonic phrases
- Derive wallets from mnemonic
- Sign and verify messages
- WalletConnect sessions via CLI

## CLI Usage

### Mnemonic

```bash
# Generate a new mnemonic
zeta-cli gen-mnemonic

# Derive a wallet from a mnemonic
zeta-cli derive --phrase "<mnemonic_phrase>" --pass "optional_password"
```

### Wallet

```bash
# Sign a message
zeta-cli sign --phrase "<mnemonic_phrase>" --pass "optional_password" --msg "Hello"

# Verify a signature
zeta-cli verify --pubhex "<public_key_hex>" --msg "Hello" --sig "<signature>"
```

### WalletConnect

```bash
# Connect to a peer
zeta-cli walletconnect --peer <PEER_NAME> --action connect

# Disconnect from a peer
zeta-cli walletconnect --peer <PEER_NAME> --action disconnect
```

The CLI will display the session status after each action.

