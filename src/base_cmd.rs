use crate::base_client::BaseClient;
use alloy::primitives::utils::format_units;
use anyhow::Result;

pub async fn handle_balance(rpc_url: &str, address: &str) -> Result<()> {
    let client = BaseClient::new(rpc_url)?;
    let balance = client.get_balance(address).await?;
    let eth = format_units(balance, "ether")?;
    println!("Balance: {} ETH", eth);
    Ok(())
}