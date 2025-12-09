use crate::base_client::BaseClient;
use crate::Wallet;
use alloy::primitives::utils::{format_units, parse_units};
use anyhow::Result;

pub async fn handle_balance(rpc_url: &str, address: &str) -> Result<()> {
    let client = BaseClient::new(rpc_url)?;
    let balance = client.get_balance(address).await?;
    let eth = format_units(balance, "ether")?;
    println!("Balance: {} ETH", eth);
    Ok(())
}

pub async fn handle_send(
    rpc_url: &str,
    phrase: &str,
    pass: Option<&str>,
    to: &str,
    amount_eth: &str,
) -> Result<()> {
    let client = BaseClient::new(rpc_url)?;

    let destination = if to.contains('.') {
        println!("Resolving destination: {}", to);
        client.resolve_name(to).await?
    } else {
        to.to_string()
    };

    let wallet = Wallet::from_phrase(phrase, pass.unwrap_or(""))?;
    let pk = wallet.get_private_key_bytes();

    let amount_wei = parse_units(amount_eth, "ether")?.into();

    println!("Sending {} ETH to {}...", amount_eth, destination);

    let tx_hash = client.send_eth(&pk, &destination, amount_wei).await?;
    println!("Transaction sent! Hash: {}", tx_hash);

    Ok(())
}

pub async fn handle_resolve(rpc_url: &str, name: &str) -> Result<()> {
    let client = BaseClient::new(rpc_url)?;
    println!("Resolving {}...", name);
    let address = client.resolve_name(name).await?;
    println!("{} -> {}", name, address);
    Ok(())
}