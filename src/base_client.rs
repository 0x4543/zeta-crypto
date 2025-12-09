use alloy::primitives::Address;
use alloy::providers::{Provider, ProviderBuilder, RootProvider};
use alloy::transports::http::Http;
use anyhow::Result;
use reqwest::Client;
use std::str::FromStr;
use url::Url;

pub struct BaseClient {
    provider: RootProvider<Http<Client>>,
}

impl BaseClient {
    pub fn new(rpc_url: &str) -> Result<Self> {
        let url = Url::parse(rpc_url)?;
        let provider = ProviderBuilder::new().on_http(url);
        Ok(Self { provider })
    }

    pub async fn get_balance(&self, address: &str) -> Result<String> {
        let addr = Address::from_str(address)?;
        let balance = self.provider.get_balance(addr).await?;
        Ok(balance.to_string())
    }
}
