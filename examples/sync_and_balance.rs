use zinc_core::{Network, WalletBuilder, ZincMnemonic};

const DEMO_MNEMONIC: &str =
    "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<(), String> {
    let esplora_url = match std::env::var("ESPLORA_URL") {
        Ok(url) => url,
        Err(_) => {
            eprintln!(
                "Set ESPLORA_URL to run this example (for example: https://mempool.space/api)"
            );
            return Ok(());
        }
    };

    let mnemonic = ZincMnemonic::parse(DEMO_MNEMONIC).map_err(|e| e.to_string())?;
    let mut wallet = WalletBuilder::from_mnemonic(Network::Bitcoin, &mnemonic).build()?;

    let events = wallet.sync(&esplora_url).await?;
    println!("Sync events: {}", events.join(", "));

    let balance = wallet.get_balance();
    println!(
        "Balance:\n{}",
        serde_json::to_string_pretty(&balance).map_err(|e| e.to_string())?
    );

    Ok(())
}
