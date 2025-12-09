use alloy::network::EthereumWallet;
use alloy::primitives::{Address, U256};
use alloy::providers::{Provider, ProviderBuilder, RootProvider};
use alloy::signers::local::PrivateKeySigner;
use alloy::transports::http::Http;
use anyhow::Result;
use reqwest::Client;
use std::str::FromStr;
use url::Url;

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
}
