# Zeta Crypto

Tiny Rust library and CLI demonstrating mnemonic, key derivation, signing and verifying.

For learning and prototyping only.

## Features

- Generate 12-word BIP39 mnemonic
- Derive wallet from mnemonic with simple PBKDF2-based key derivation
- ECDSA secp256k1 keypair generation, signing and verifying
- CLI for quick testing and wallet operations
- Generate random 32-byte hex keys (for demo/testing)

## CLI Examples

```bash
# Generate new mnemonic
cargo run --bin zeta-cli -- GenMnemonic

# Derive wallet address
cargo run --bin zeta-cli -- Derive --phrase "your twelve word mnemonic"

# Sign a message
cargo run --bin zeta-cli -- Sign --phrase "your mnemonic" --msg "hello world"

# Verify a signature
cargo run --bin zeta-cli -- Verify --pubhex "<pubkey hex>" --msg "hello world" --sig "<signature hex>"