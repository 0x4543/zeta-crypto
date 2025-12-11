use crate::base_client::BaseClient;
use crate::Wallet;
use alloy::primitives::utils::{format_units, parse_units};
use alloy::primitives::{Address, U256};
use anyhow::{anyhow, Result};
use std::str::FromStr;

const MULTISENDER_BYTECODE: &str = "608060405260043610610041576000357c0100000000000000000000000000000000000000000000000000000000900463ffffffff168063fd6b7ef814610046578063b59d997214610090575b600080fd5b34801561005257600080fd5b5061008e600480360381019080803590602001909291905050506100e4565b005b6100e26004803603810190808035906020019092919080359060200190929190505050610197565b005b6000815183511415156100f657600080fd5b6000600090505b8251811015610193578281815181101561011457fe5b60200260200101518160020190508481815181101561012d57fe5b60200260200101518160010190508073ffffffffffffffffffffffffffffffffffffffff166108fc839081150290604051600060405180830381858888f19350505050151561018257600080fd5b8080600101915050610103565b505050565b6000815183511415156101a957600080fd5b6000600090505b8251811015610260578473ffffffffffffffffffffffffffffffffffffffff166323b872dd868281518110156101e457fe5b6020026020010151848281518110156101fb57fe5b60200260200101516040518363ffffffff167c01000000000000000000000000000000000000000000000000000000000028152600401808373ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff1681526020018273ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff1681526020018181526020019250505060206040518083038186803b151561025057600080fd5b6102c65a03f4151561026157600080fd5b50505080806001019150506101b6565b505050505600a165627a7a72305820f35306660a2290927702f232535c52670e5c92569202029352c39e25762693260029";
const BASE_CHAIN_ID: u64 = 8453;

async fn resolve_if_needed(client: &BaseClient, input: &str) -> Result<String> {
    if input.contains('.') {
        println!("Resolving: {}", input);
        client.resolve_name(input).await
    } else {
        Ok(input.to_string())
    }
}

async fn check_chain_id(client: &BaseClient) -> Result<()> {
    let chain_id = client.get_chain_id().await?;
    if chain_id != BASE_CHAIN_ID {
        return Err(anyhow!(
            "Wrong chain ID: {}. Expected Base Mainnet ({})",
            chain_id,
            BASE_CHAIN_ID
        ));
    }
    Ok(())
}

pub async fn handle_balance(rpc_url: &str, address: &str) -> Result<()> {
    let client = BaseClient::new(rpc_url)?;
    check_chain_id(&client).await?;
    let resolved = resolve_if_needed(&client, address).await?;
    let balance = client.get_balance(&resolved).await?;
    let eth = format_units(balance, "ether")?;
    println!("Balance: {} ETH", eth);
    Ok(())
}

pub async fn handle_balance_usdc(rpc_url: &str, address: &str) -> Result<()> {
    let client = BaseClient::new(rpc_url)?;
    check_chain_id(&client).await?;
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
    check_chain_id(&client).await?;
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
    check_chain_id(&client).await?;
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
    check_chain_id(&client).await?;
    println!("Resolving {}...", name);
    let address = client.resolve_name(name).await?;
    println!("{} -> {}", name, address);
    Ok(())
}

pub async fn handle_deploy(rpc_url: &str, phrase: &str, pass: Option<&str>) -> Result<()> {
    let wallet = Wallet::from_phrase(phrase, pass.unwrap_or(""))?;
    let pk = wallet.get_private_key_bytes();
    let client = BaseClient::new(rpc_url)?;
    check_chain_id(&client).await?;

    println!("Deploying ZetaMultiSender contract...");
    let contract_addr = client.deploy_contract(&pk, MULTISENDER_BYTECODE).await?;
    println!("Contract deployed successfully!");
    println!("Address: {}", contract_addr);

    Ok(())
}

pub async fn handle_disperse_eth(
    rpc_url: &str,
    phrase: &str,
    pass: Option<&str>,
    contract: &str,
    pairs: Vec<String>,
) -> Result<()> {
    let wallet = Wallet::from_phrase(phrase, pass.unwrap_or(""))?;
    let pk = wallet.get_private_key_bytes();
    let client = BaseClient::new(rpc_url)?;
    check_chain_id(&client).await?;

    let mut recipients = Vec::new();
    let mut values = Vec::new();
    let mut total_value = U256::ZERO;

    for p in pairs {
        let parts: Vec<&str> = p.split('=').collect();
        if parts.len() != 2 {
            return Err(anyhow!("Invalid format. Use address=amount"));
        }

        let addr_str = resolve_if_needed(&client, parts[0]).await?;
        let addr = Address::from_str(&addr_str)?;
        let val_wei: U256 = parse_units(parts[1], "ether")?.into();

        recipients.push(addr);
        values.push(val_wei);
        total_value += val_wei;
    }

    println!(
        "Dispersing {} ETH total to {} recipients...",
        format_units(total_value, "ether")?,
        recipients.len()
    );

    let tx_hash = client
        .disperse_eth(&pk, contract, recipients, values, total_value)
        .await?;
    println!("Batch transaction sent! Hash: {}", tx_hash);

    Ok(())
}

pub async fn handle_approve(
    rpc_url: &str,
    phrase: &str,
    pass: Option<&str>,
    token: &str,
    spender: &str,
    amount: &str,
    decimals: u8,
) -> Result<()> {
    let wallet = Wallet::from_phrase(phrase, pass.unwrap_or(""))?;
    let pk = wallet.get_private_key_bytes();
    let client = BaseClient::new(rpc_url)?;
    check_chain_id(&client).await?;

    let amount_units: U256 = parse_units(amount, decimals)?.into();

    println!("Approving {} tokens for spender {}...", amount, spender);
    let tx_hash = client
        .approve_token(&pk, token, spender, amount_units)
        .await?;
    println!("Approval sent! Hash: {}", tx_hash);

    Ok(())
}

pub async fn handle_disperse_token(
    rpc_url: &str,
    phrase: &str,
    pass: Option<&str>,
    contract: &str,
    token: &str,
    pairs: Vec<String>,
    decimals: u8,
) -> Result<()> {
    let wallet = Wallet::from_phrase(phrase, pass.unwrap_or(""))?;
    let pk = wallet.get_private_key_bytes();
    let client = BaseClient::new(rpc_url)?;
    check_chain_id(&client).await?;

    let mut recipients = Vec::new();
    let mut values = Vec::new();
    let mut total_value = U256::ZERO;

    for p in pairs {
        let parts: Vec<&str> = p.split('=').collect();
        if parts.len() != 2 {
            return Err(anyhow!("Invalid format. Use address=amount"));
        }

        let addr_str = resolve_if_needed(&client, parts[0]).await?;
        let addr = Address::from_str(&addr_str)?;
        let val_units: U256 = parse_units(parts[1], decimals)?.into();

        recipients.push(addr);
        values.push(val_units);
        total_value += val_units;
    }

    println!(
        "Dispersing {} tokens total to {} recipients...",
        format_units(total_value, decimals)?,
        recipients.len()
    );

    let tx_hash = client
        .disperse_token(&pk, contract, token, recipients, values)
        .await?;
    println!("Batch token transaction sent! Hash: {}", tx_hash);

    Ok(())
}
