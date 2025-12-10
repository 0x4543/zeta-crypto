use crate::base_client::BaseClient;
use crate::Wallet;
use alloy::primitives::utils::{format_units, parse_units};
use anyhow::Result;

async fn resolve_if_needed(client: &BaseClient, input: &str) -> Result<String> {
    if input.contains('.') {
        println!("Resolving: {}", input);
        client.resolve_name(input).await
    } else {
        Ok(input.to_string())
    }
}

pub async fn handle_balance(rpc_url: &str, address: &str) -> Result<()> {
    let client = BaseClient::new(rpc_url)?;
    let resolved = resolve_if_needed(&client, address).await?;
    let balance = client.get_balance(&resolved).await?;
    let eth = format_units(balance, "ether")?;
    println!("Balance: {} ETH", eth);
    Ok(())
}

pub async fn handle_balance_usdc(rpc_url: &str, address: &str) -> Result<()> {
    let client = BaseClient::new(rpc_url)?;
    let resolved = resolve_if_needed(&client, address).await?;
    let balance = client.get_usdc_balance(&resolved).await?;
    let usdc = format_units(balance, 6)?;
    println!("Balance: {} USDC", usdc);
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
    let destination = resolve_if_needed(&client, to).await?;

    let wallet = Wallet::from_phrase(phrase, pass.unwrap_or(""))?;
    let pk = wallet.get_private_key_bytes();

    let amount_wei = parse_units(amount_eth, "ether")?.into();

    println!("Sending {} ETH to {}...", amount_eth, destination);

    let tx_hash = client.send_eth(&pk, &destination, amount_wei).await?;
    println!("Transaction sent! Hash: {}", tx_hash);

    Ok(())
}

pub async fn handle_send_usdc(
    rpc_url: &str,
    phrase: &str,
    pass: Option<&str>,
    to: &str,
    amount_usdc: &str,
) -> Result<()> {
    let client = BaseClient::new(rpc_url)?;
    let destination = resolve_if_needed(&client, to).await?;

    let wallet = Wallet::from_phrase(phrase, pass.unwrap_or(""))?;
    let pk = wallet.get_private_key_bytes();

    let amount_units = parse_units(amount_usdc, 6)?.into();

    println!("Sending {} USDC to {}...", amount_usdc, destination);

    let tx_hash = client.send_usdc(&pk, &destination, amount_units).await?;
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
