use std::env;
use std::fs;
use std::path::{Path, PathBuf};

use bdk_wallet::bitcoin::bip32::Xpriv;
use bdk_wallet::bitcoin::Network as BitcoinNetwork;
use bdk_wallet::{KeychainKind, Wallet};
use bip39::Mnemonic;
use serde::Deserialize;

#[derive(Debug, Clone, Deserialize)]
struct VectorsPayload {
    vectors: Vec<ImportVector>,
}

#[derive(Debug, Clone, Deserialize)]
struct ImportVector {
    #[serde(rename = "providerId")]
    provider_id: String,
    label: Option<String>,
    mnemonic: String,
    network: Option<String>,
    #[serde(rename = "expectedAccounts")]
    expected_accounts: Vec<ExpectedAccount>,
}

#[derive(Debug, Clone, Deserialize)]
struct ExpectedAccount {
    index: u32,
    taproot: Option<String>,
    payment: Option<String>,
}

#[derive(Debug, Clone, Copy)]
enum AddressScript {
    Tr,
    Wpkh,
    ShWpkh,
    Pkh,
}

impl AddressScript {
    fn descriptor(self, xprv: &Xpriv, purpose: u32, coin_type: u32, account: u32) -> String {
        let account_path = format!("{}/{purpose}'/{coin_type}'/{account}'", xprv);
        match self {
            AddressScript::Tr => format!("tr({account_path}/0/*)"),
            AddressScript::Wpkh => format!("wpkh({account_path}/0/*)"),
            AddressScript::ShWpkh => format!("sh(wpkh({account_path}/0/*))"),
            AddressScript::Pkh => format!("pkh({account_path}/0/*)"),
        }
    }

    fn change_descriptor(self, xprv: &Xpriv, purpose: u32, coin_type: u32, account: u32) -> String {
        let account_path = format!("{}/{purpose}'/{coin_type}'/{account}'", xprv);
        match self {
            AddressScript::Tr => format!("tr({account_path}/1/*)"),
            AddressScript::Wpkh => format!("wpkh({account_path}/1/*)"),
            AddressScript::ShWpkh => format!("sh(wpkh({account_path}/1/*))"),
            AddressScript::Pkh => format!("pkh({account_path}/1/*)"),
        }
    }
}

#[derive(Debug, Clone, Copy)]
enum DerivationMode {
    Account,
    Index,
}

impl DerivationMode {
    fn label(self) -> &'static str {
        match self {
            DerivationMode::Account => "account",
            DerivationMode::Index => "index",
        }
    }

    fn account_and_index(self, account_number: u32) -> (u32, u32) {
        match self {
            DerivationMode::Account => (account_number, 0),
            DerivationMode::Index => (0, account_number),
        }
    }
}

#[derive(Debug, Clone, Copy)]
struct DerivationSpec {
    purpose: u32,
    script: AddressScript,
    mode: DerivationMode,
}

impl DerivationSpec {
    fn label(self) -> String {
        let script = match self.script {
            AddressScript::Tr => "tr",
            AddressScript::Wpkh => "wpkh",
            AddressScript::ShWpkh => "sh-wpkh",
            AddressScript::Pkh => "pkh",
        };
        let template = match self.mode {
            DerivationMode::Account => format!("m/{}'/coin'/{{account}}'/0/0", self.purpose),
            DerivationMode::Index => format!("m/{}'/coin'/0'/0/{{index}}", self.purpose),
        };
        format!("{script}:{template}")
    }
}

#[derive(Debug, Clone)]
struct Candidate {
    id: String,
    taproot: DerivationSpec,
    payment: DerivationSpec,
}

#[derive(Debug)]
struct CandidateResult {
    candidate: Candidate,
    matched: usize,
    total: usize,
    mismatches: Vec<String>,
}

fn default_vectors_path() -> PathBuf {
    PathBuf::from("../test-vectors/provider-import-vectors.local.json")
}

fn parse_network(network: Option<&str>) -> BitcoinNetwork {
    match network.unwrap_or("mainnet") {
        "mainnet" => BitcoinNetwork::Bitcoin,
        "signet" => BitcoinNetwork::Signet,
        "regtest" => BitcoinNetwork::Regtest,
        _ => BitcoinNetwork::Bitcoin,
    }
}

fn coin_type(network: BitcoinNetwork) -> u32 {
    if network == BitcoinNetwork::Bitcoin {
        0
    } else {
        1
    }
}

fn derive_address_for_account(
    xprv: &Xpriv,
    network: BitcoinNetwork,
    spec: DerivationSpec,
    account_number: u32,
) -> Result<String, String> {
    let cointype = coin_type(network);
    let (account, index) = spec.mode.account_and_index(account_number);
    let receive_desc = spec
        .script
        .descriptor(xprv, spec.purpose, cointype, account);
    let change_desc = spec
        .script
        .change_descriptor(xprv, spec.purpose, cointype, account);

    let wallet = Wallet::create(receive_desc, change_desc)
        .network(network)
        .create_wallet_no_persist()
        .map_err(|e| e.to_string())?;

    Ok(wallet
        .peek_address(KeychainKind::External, index)
        .address
        .to_string())
}

fn scan_candidate(
    candidate: Candidate,
    xprv: &Xpriv,
    network: BitcoinNetwork,
    expected_accounts: &[ExpectedAccount],
) -> CandidateResult {
    let mut matched = 0usize;
    let mut total = 0usize;
    let mut mismatches = Vec::new();

    for expected in expected_accounts.iter().take(3) {
        if let Some(expected_taproot) = expected
            .taproot
            .as_ref()
            .map(|s| s.trim())
            .filter(|s| !s.is_empty())
        {
            total += 1;
            match derive_address_for_account(xprv, network, candidate.taproot, expected.index) {
                Ok(actual) if actual == expected_taproot => matched += 1,
                Ok(actual) => mismatches.push(format!(
                    "account {} taproot expected={} actual={}",
                    expected.index + 1,
                    expected_taproot,
                    actual
                )),
                Err(err) => mismatches.push(format!(
                    "account {} taproot derivation error={}",
                    expected.index + 1,
                    err
                )),
            }
        }

        if let Some(expected_payment) = expected
            .payment
            .as_ref()
            .map(|s| s.trim())
            .filter(|s| !s.is_empty())
        {
            total += 1;
            match derive_address_for_account(xprv, network, candidate.payment, expected.index) {
                Ok(actual) if actual == expected_payment => matched += 1,
                Ok(actual) => mismatches.push(format!(
                    "account {} payment expected={} actual={}",
                    expected.index + 1,
                    expected_payment,
                    actual
                )),
                Err(err) => mismatches.push(format!(
                    "account {} payment derivation error={}",
                    expected.index + 1,
                    err
                )),
            }
        }
    }

    CandidateResult {
        candidate,
        matched,
        total,
        mismatches,
    }
}

fn candidate_set() -> Vec<Candidate> {
    let modes = [DerivationMode::Account, DerivationMode::Index];
    let mut out = Vec::new();
    let mut id_counter = 1u32;

    for taproot_mode in modes {
        for payment_mode in modes {
            for (payment_purpose, payment_script) in [
                (84u32, AddressScript::Wpkh),
                (49u32, AddressScript::ShWpkh),
                (86u32, AddressScript::Tr),
                (44u32, AddressScript::Wpkh),
                (44u32, AddressScript::Pkh),
            ] {
                let id = format!("cand_{id_counter:02}");
                id_counter += 1;
                out.push(Candidate {
                    id,
                    taproot: DerivationSpec {
                        purpose: 86,
                        script: AddressScript::Tr,
                        mode: taproot_mode,
                    },
                    payment: DerivationSpec {
                        purpose: payment_purpose,
                        script: payment_script,
                        mode: payment_mode,
                    },
                });
            }
        }
    }

    out
}

fn score_label(result: &CandidateResult) -> String {
    if result.total == 0 {
        return "0/0".to_string();
    }
    format!("{}/{}", result.matched, result.total)
}

fn main() -> Result<(), String> {
    let maybe_path_arg = env::args().nth(1);
    let vectors_path = maybe_path_arg
        .map(PathBuf::from)
        .unwrap_or_else(default_vectors_path);

    if !Path::new(&vectors_path).exists() {
        return Err(format!(
            "Vectors file not found: {}",
            vectors_path.to_string_lossy()
        ));
    }

    let raw = fs::read_to_string(&vectors_path).map_err(|e| {
        format!(
            "Failed to read vectors file {}: {e}",
            vectors_path.to_string_lossy()
        )
    })?;
    let payload: VectorsPayload =
        serde_json::from_str(&raw).map_err(|e| format!("Invalid vectors JSON: {e}"))?;

    let candidates = candidate_set();
    println!(
        "Loaded {} vectors from {}",
        payload.vectors.len(),
        vectors_path.to_string_lossy()
    );
    println!(
        "Scanning {} candidate derivation schemes...",
        candidates.len()
    );

    for vector in payload.vectors {
        let title = vector
            .label
            .as_ref()
            .map(|label| format!("{} ({})", vector.provider_id, label))
            .unwrap_or_else(|| vector.provider_id.clone());
        let network = parse_network(vector.network.as_deref());
        println!("\n=== {} ===", title);

        let mnemonic = match Mnemonic::parse(vector.mnemonic.trim()) {
            Ok(m) => m,
            Err(err) => {
                println!("Mnemonic parse error: {err}");
                continue;
            }
        };

        let seed = mnemonic.to_seed("");
        let xprv = match Xpriv::new_master(network, &seed) {
            Ok(x) => x,
            Err(err) => {
                println!("Master key derivation error: {err}");
                continue;
            }
        };

        let mut results: Vec<CandidateResult> = candidates
            .iter()
            .cloned()
            .map(|candidate| scan_candidate(candidate, &xprv, network, &vector.expected_accounts))
            .collect();

        results.sort_by(|a, b| {
            b.matched
                .cmp(&a.matched)
                .then_with(|| a.mismatches.len().cmp(&b.mismatches.len()))
        });

        for result in results.iter().take(5) {
            println!(
                "- {} score={} taproot={} payment={}",
                result.candidate.id,
                score_label(result),
                result.candidate.taproot.label(),
                result.candidate.payment.label()
            );
            if result.matched != result.total {
                for mismatch in result.mismatches.iter().take(3) {
                    println!("    {}", mismatch);
                }
            }
        }

        if let Some(best) = results.first() {
            if best.matched == best.total && best.total > 0 {
                println!(
                    "Best exact match: {} (taproot={}, payment={})",
                    best.candidate.id,
                    best.candidate.taproot.label(),
                    best.candidate.payment.label()
                );
            } else {
                println!(
                    "No exact match found. Best evidence: {} with score {}",
                    best.candidate.id,
                    score_label(best)
                );
            }
        }
    }

    Ok(())
}
