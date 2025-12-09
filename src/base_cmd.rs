use crate::base_client::BaseClient;
use anyhow::Result;

pub async fn handle_balance(rpc_url: &str, address: &str) -> Result<()> {
    let client = BaseClient::new(rpc_url)?;
    let balance = client.get_balance(address).await?;
    println!("Balance: {} Wei", balance);
    Ok(())
}