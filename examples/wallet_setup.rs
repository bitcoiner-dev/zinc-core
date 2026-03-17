use zinc_core::{AddressScheme, Network, WalletBuilder, ZincMnemonic};

const DEMO_MNEMONIC: &str =
    "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

fn main() -> Result<(), String> {
    let mnemonic = ZincMnemonic::parse(DEMO_MNEMONIC).map_err(|e| e.to_string())?;
    let mut wallet = WalletBuilder::from_mnemonic(Network::Regtest, &mnemonic)
        .with_scheme(AddressScheme::Dual)
        .with_account_index(0)
        .build()?;

    let taproot = wallet.next_taproot_address()?;
    let payment = wallet.get_payment_address()?;
    let accounts = wallet.get_accounts(3);

    println!("Taproot address: {taproot}");
    println!("Payment address: {payment}");
    println!(
        "Accounts:\n{}",
        serde_json::to_string_pretty(&accounts).map_err(|e| e.to_string())?
    );

    Ok(())
}
