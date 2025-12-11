use alloy::network::EthereumWallet;
use alloy::primitives::{keccak256, Address, Bytes, FixedBytes, U256};
use alloy::providers::{Provider, ProviderBuilder, RootProvider};
use alloy::signers::local::PrivateKeySigner;
use alloy::sol;
use alloy::transports::http::Http;
use anyhow::{anyhow, Result};
use reqwest::Client;
use std::str::FromStr;
use url::Url;

const BASENAMES_RESOLVER: &str = "0xC6d566A56A1aFf6508b41f6c90ff131615583BCD";
const BASE_USDC_ADDR: &str = "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913";

sol! {
    #[sol(rpc)]
    interface L2Resolver {
        function addr(bytes32 node) external view returns (address);
    }

    #[sol(rpc)]
    interface IERC20 {
        function balanceOf(address account) external view returns (uint256);
        function transfer(address to, uint256 value) external returns (bool);
        function approve(address spender, uint256 value) external returns (bool);
        function allowance(address owner, address spender) external view returns (uint256);
    }

    #[sol(rpc)]
    interface ZetaMultiSender {
        function disperseEther(address[] recipients, uint256[] values) external payable;
        function disperseToken(address token, address[] recipients, uint256[] values) external;
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

    pub async fn get_chain_id(&self) -> Result<u64> {
        let id = self.provider.get_chain_id().await?;
        Ok(id)
    }

    pub async fn get_gas_price(&self) -> Result<U256> {
        let price = self.provider.get_gas_price().await?;
        Ok(U256::from(price))
    }

    pub async fn get_balance(&self, address: &str) -> Result<U256> {
        let addr = Address::from_str(address)?;
        let balance = self.provider.get_balance(addr).await?;
        Ok(balance)
    }

    pub async fn get_usdc_balance(&self, address: &str) -> Result<U256> {
        let token_addr = Address::from_str(BASE_USDC_ADDR)?;
        let owner = Address::from_str(address)?;
        let token = IERC20::new(token_addr, &self.provider);
        let balance = token.balanceOf(owner).call().await?._0;
        Ok(balance)
    }

    pub async fn get_allowance(&self, token_addr: &str, owner: &str, spender: &str) -> Result<U256> {
        let token = Address::from_str(token_addr)?;
        let owner_addr = Address::from_str(owner)?;
        let spender_addr = Address::from_str(spender)?;
        
        let contract = IERC20::new(token, &self.provider);
        let value = contract.allowance(owner_addr, spender_addr).call().await?._0;
        Ok(value)
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

    pub async fn send_usdc(&self, private_key: &[u8], to: &str, value_units: U256) -> Result<String> {
        let signer = PrivateKeySigner::from_slice(private_key)?;
        let wallet = EthereumWallet::from(signer);
        let provider = ProviderBuilder::new()
            .wallet(wallet)
            .on_http(self.rpc_url.clone());

        let token_addr = Address::from_str(BASE_USDC_ADDR)?;
        let to_addr = Address::from_str(to)?;
        let token = IERC20::new(token_addr, &provider);

        let tx_hash = token.transfer(to_addr, value_units).send().await?.watch().await?;
        Ok(tx_hash.to_string())
    }

    pub async fn deploy_contract(&self, private_key: &[u8], bytecode_hex: &str) -> Result<String> {
        let signer = PrivateKeySigner::from_slice(private_key)?;
        let wallet = EthereumWallet::from(signer);
        let provider = ProviderBuilder::new()
            .wallet(wallet)
            .on_http(self.rpc_url.clone());

        let bytecode_bytes = hex::decode(bytecode_hex.trim_start_matches("0x"))?;
        let tx = alloy::rpc::types::TransactionRequest::default().input(Bytes::from(bytecode_bytes).into());

        let receipt = provider.send_transaction(tx).await?.get_receipt().await?;
        
        if let Some(addr) = receipt.contract_address {
            Ok(addr.to_string())
        } else {
            Err(anyhow!("Contract deployment failed: no address returned"))
        }
    }

    pub async fn disperse_eth(&self, private_key: &[u8], contract_addr: &str, recipients: Vec<Address>, values: Vec<U256>, total_value: U256) -> Result<String> {
        let signer = PrivateKeySigner::from_slice(private_key)?;
        let wallet = EthereumWallet::from(signer);
        let provider = ProviderBuilder::new()
            .wallet(wallet)
            .on_http(self.rpc_url.clone());

        let contract = Address::from_str(contract_addr)?;
        let multisender = ZetaMultiSender::new(contract, &provider);

        let tx_hash = multisender.disperseEther(recipients, values)
            .value(total_value)
            .send()
            .await?
            .watch()
            .await?;

        Ok(tx_hash.to_string())
    }

    pub async fn approve_token(&self, private_key: &[u8], token_addr: &str, spender: &str, amount: U256) -> Result<String> {
        let signer = PrivateKeySigner::from_slice(private_key)?;
        let wallet = EthereumWallet::from(signer);
        let provider = ProviderBuilder::new()
            .wallet(wallet)
            .on_http(self.rpc_url.clone());

        let token = Address::from_str(token_addr)?;
        let spender_addr = Address::from_str(spender)?;
        let contract = IERC20::new(token, &provider);

        let tx_hash = contract.approve(spender_addr, amount).send().await?.watch().await?;
        Ok(tx_hash.to_string())
    }

    pub async fn disperse_token(&self, private_key: &[u8], contract_addr: &str, token_addr: &str, recipients: Vec<Address>, values: Vec<U256>) -> Result<String> {
        let signer = PrivateKeySigner::from_slice(private_key)?;
        let wallet = EthereumWallet::from(signer);
        let provider = ProviderBuilder::new()
            .wallet(wallet)
            .on_http(self.rpc_url.clone());

        let contract = Address::from_str(contract_addr)?;
        let token = Address::from_str(token_addr)?;
        let multisender = ZetaMultiSender::new(contract, &provider);

        let tx_hash = multisender.disperseToken(token, recipients, values)
            .send()
            .await?
            .watch()
            .await?;

        Ok(tx_hash.to_string())
    }

    pub async fn resolve_name(&self, name: &str) -> Result<String> {
        let normalized_name = if name.ends_with(".base") {
            format!("{}.eth", name)
        } else {
            name.to_string()
        };

        let node = namehash(&normalized_name);
        let resolver_addr = Address::from_str(BASENAMES_RESOLVER)?;

        let resolver = L2Resolver::new(resolver_addr, &self.provider);

        match resolver.addr(node).call().await {
            Ok(result) => {
                let address = result._0;
                if address == Address::ZERO {
                    Err(anyhow!("Name not found (address is zero)"))
                } else {
                    Ok(address.to_string())
                }
            },
            Err(_) => {
                Err(anyhow!("Resolution failed. The name might not be registered or Resolver is unavailable."))
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