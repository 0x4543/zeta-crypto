use alloy::primitives::{keccak256, Address, FixedBytes, U256};
use alloy::providers::{Provider, ProviderBuilder, RootProvider};
use alloy::signers::local::PrivateKeySigner;
use alloy::sol;
use alloy::network::EthereumWallet;
use alloy::transports::http::Http;
use anyhow::{anyhow, Result};
use reqwest::Client;
use std::str::FromStr;
use url::Url;

const ENS_REGISTRY_ADDR: &str = "0x00000000000C2E074eC69A0dFb2997BA6C7d2e1e";

sol! {
    #[sol(rpc)]
    interface L2Resolver {
        function addr(bytes32 node) external view returns (address);
    }

    #[sol(rpc)]
    interface ENSRegistry {
        function resolver(bytes32 node) external view returns (address);
    }
}

pub struct BaseClient {
    rpc_url: Url,
    provider: RootProvider<Http<Client>>,
}

impl BaseClient {
    pub fn new(rpc_url: &str) -> Result<Self> {
        let url = Url::parse(rpc_url)?;
        let provider = ProviderBuilder::new().on_http(url.clone());
        Ok(Self {
            rpc_url: url,
            provider,
        })
    }

    pub async fn get_balance(&self, address: &str) -> Result<U256> {
        let addr = Address::from_str(address)?;
        let balance = self.provider.get_balance(addr).await?;
        Ok(balance)
    }

    pub async fn send_eth(&self, private_key: &[u8], to: &str, value_wei: U256) -> Result<String> {
        let signer = PrivateKeySigner::from_slice(private_key)?;
        let wallet = EthereumWallet::from(signer);

        let provider = ProviderBuilder::new()
            .wallet(wallet)
            .on_http(self.rpc_url.clone());

        let to_addr = Address::from_str(to)?;

        let tx_hash = provider
            .send_transaction(
                alloy::rpc::types::TransactionRequest::default()
                    .to(to_addr)
                    .value(value_wei),
            )
            .await?
            .watch()
            .await?;

        Ok(tx_hash.to_string())
    }

    pub async fn resolve_name(&self, name: &str) -> Result<String> {
        let node = namehash(name);
        let registry_addr = Address::from_str(ENS_REGISTRY_ADDR)?;
        let registry = ENSRegistry::new(registry_addr, &self.provider);

        let resolver_addr = registry.resolver(node).call().await?._0;

        if resolver_addr == Address::ZERO {
            return Err(anyhow!("Name is not registered (no resolver set)"));
        }

        let resolver = L2Resolver::new(resolver_addr, &self.provider);
        
        match resolver.addr(node).call().await {
            Ok(result) => {
                let address = result._0;
                if address == Address::ZERO {
                    Err(anyhow!("Name registered but has no address record"))
                } else {
                    Ok(address.to_string())
                }
            },
            Err(_) => {
                Err(anyhow!("Standard resolution failed. This name might use Wildcard/CCIP-Read which is not yet supported."))
            }
        }
    }
}

fn namehash(name: &str) -> FixedBytes<32> {
    let mut node = FixedBytes::<32>::ZERO;

    if name.is_empty() {
        return node;
    }

    for label in name.split('.').rev() {
        let label_hash = keccak256(label.as_bytes());
        let mut combined = Vec::new();
        combined.extend_from_slice(node.as_slice());
        combined.extend_from_slice(label_hash.as_slice());
        node = keccak256(&combined);
    }

    node
}