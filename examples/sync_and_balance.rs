// Native-only example: tokio and the esplora sync path are not available on
// wasm32, and `cargo test --target wasm32-unknown-unknown` builds examples.
#[cfg(not(target_arch = "wasm32"))]
mod native {
    use zinc_core::{Network, WalletBuilder, ZincMnemonic};

    const DEMO_MNEMONIC: &str =
        "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

    pub async fn run() -> Result<(), String> {
        let Ok(esplora_url) = std::env::var("ESPLORA_URL") else {
            eprintln!(
                "Set ESPLORA_URL to run this example (for example: https://mempool.space/api)"
            );
            return Ok(());
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
}

#[cfg(not(target_arch = "wasm32"))]
#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<(), String> {
    native::run().await
}

#[cfg(target_arch = "wasm32")]
fn main() {}
