//! Offer creation helpers aligned with ord-style offer PSBT construction.
//!
//! This module builds a buyer-funded PSBT that includes one unsigned seller
//! input (the inscription outpoint) and signed buyer inputs, then wraps that
//! PSBT in `OfferEnvelopeV1` for relay publication.

use crate::builder::{AddressScheme, SignOptions, ZincWallet};
use crate::{prepare_offer_acceptance, OfferEnvelopeV1, ZincError};
use base64::Engine;
use bdk_wallet::bitcoin::address::NetworkUnchecked;
use bdk_wallet::bitcoin::psbt::Input as PsbtInput;
use bdk_wallet::bitcoin::secp256k1::XOnlyPublicKey;
use bdk_wallet::bitcoin::{Address, Amount, FeeRate, OutPoint, TxOut, Weight};
use bdk_wallet::KeychainKind;
use bdk_wallet::TxOrdering;
use serde::{Deserialize, Serialize};
use std::str::FromStr;

const DEFAULT_FOREIGN_INPUT_SATISFACTION_WEIGHT_WU: u64 = 272;

/// Input parameters for building an ord-compatible buyer offer.
#[derive(Debug, Clone)]
pub struct CreateOfferRequest {
    /// Target inscription id for the offer.
    pub inscription_id: String,
    /// Seller outpoint containing the inscription.
    pub seller_outpoint: OutPoint,
    /// Address currently controlling `seller_outpoint` (used for seller input prevout metadata).
    pub seller_input_address: String,
    /// Seller payout address receiving ask payment + postage.
    pub seller_payout_address: String,
    /// Value (postage) currently held by the inscription output.
    pub seller_output_value_sats: u64,
    /// Ask amount (in sats) offered to the seller.
    pub ask_sats: u64,
    /// Desired fee rate (sat/vB).
    pub fee_rate_sat_vb: u64,
    /// Offer creation unix timestamp.
    pub created_at_unix: i64,
    /// Offer expiration unix timestamp.
    pub expires_at_unix: i64,
    /// Caller-provided nonce.
    pub nonce: u64,
    /// Optional explicit offer publisher x-only pubkey hex.
    ///
    /// If omitted, this defaults to the active wallet account taproot pubkey at index `0`.
    pub publisher_pubkey_hex: Option<String>,
}

/// Result payload for ord-compatible offer creation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OfferCreateResultV1 {
    /// Buyer-offer PSBT base64 (same field shape as `ord wallet offer create`).
    pub psbt: String,
    /// Seller payout address included in output #1.
    pub seller_address: String,
    /// Target inscription id.
    pub inscription: String,
    /// Seller outpoint (`txid:vout`) included in the offer.
    pub seller_outpoint: String,
    /// Postage value preserved to buyer output.
    pub postage_sats: u64,
    /// Ask amount in sats.
    pub ask_sats: u64,
    /// Fee rate in sat/vB.
    pub fee_rate_sat_vb: u64,
    /// Index of the seller input in the PSBT.
    pub seller_input_index: usize,
    /// Number of buyer-owned inputs signed in the PSBT.
    pub buyer_input_count: usize,
    /// Offer envelope ready for relay publication.
    pub offer: OfferEnvelopeV1,
}

/// Build and sign a buyer offer PSBT plus envelope.
pub fn create_offer(
    wallet: &mut ZincWallet,
    request: &CreateOfferRequest,
) -> Result<OfferCreateResultV1, ZincError> {
    validate_request(wallet, request)?;

    let wallet_network = wallet.vault_wallet.network();
    let expected_seller_payout_address = wallet
        .peek_payment_address(0)
        .ok_or_else(|| ZincError::WalletError("Payment wallet not initialized".to_string()))?;
    let seller_input_address = request
        .seller_input_address
        .parse::<Address<NetworkUnchecked>>()
        .map_err(|e| ZincError::OfferError(format!("invalid seller input address: {e}")))?
        .require_network(wallet_network)
        .map_err(|e| {
            ZincError::OfferError(format!("seller input address network mismatch: {e}"))
        })?;
    let seller_payout_address = request
        .seller_payout_address
        .parse::<Address<NetworkUnchecked>>()
        .map_err(|e| ZincError::OfferError(format!("invalid seller payout address: {e}")))?
        .require_network(wallet_network)
        .map_err(|e| {
            ZincError::OfferError(format!("seller payout address network mismatch: {e}"))
        })?;
    if seller_payout_address.script_pubkey() != expected_seller_payout_address.script_pubkey() {
        return Err(ZincError::OfferError(format!(
            "seller_payout_address must match wallet main payment address {}",
            expected_seller_payout_address
        )));
    }

    let buyer_receive_address = wallet
        .vault_wallet
        .peek_address(KeychainKind::External, 0)
        .address;
    let seller_payout_sats = request
        .ask_sats
        .checked_add(request.seller_output_value_sats)
        .ok_or_else(|| ZincError::OfferError("ask_sats + postage overflows u64".to_string()))?;

    let fee_rate = FeeRate::from_sat_per_vb(request.fee_rate_sat_vb)
        .ok_or_else(|| ZincError::OfferError("invalid fee rate".to_string()))?;
    let seller_psbt_input = PsbtInput {
        witness_utxo: Some(TxOut {
            value: Amount::from_sat(request.seller_output_value_sats),
            script_pubkey: seller_input_address.script_pubkey(),
        }),
        ..Default::default()
    };

    let signing_wallet = if wallet.scheme == AddressScheme::Dual {
        wallet
            .payment_wallet
            .as_mut()
            .ok_or_else(|| ZincError::WalletError("Payment wallet not initialized".to_string()))?
    } else {
        &mut wallet.vault_wallet
    };
    let main_change_script = signing_wallet
        .peek_address(KeychainKind::External, 0)
        .script_pubkey();

    let mut builder = signing_wallet.build_tx();
    if !wallet.inscribed_utxos.is_empty() {
        builder.unspendable(wallet.inscribed_utxos.iter().copied().collect());
    }

    // Match ord's offer template invariants:
    // - preserve recipient insertion order (buyer postage, then seller payout),
    // - keep manually added seller foreign input ahead of algorithmic buyer inputs.
    builder.ordering(TxOrdering::Untouched);

    builder
        .add_recipient(
            buyer_receive_address.script_pubkey(),
            Amount::from_sat(request.seller_output_value_sats),
        )
        .add_recipient(
            seller_payout_address.script_pubkey(),
            Amount::from_sat(seller_payout_sats),
        )
        .drain_to(main_change_script)
        .fee_rate(fee_rate)
        .only_witness_utxo()
        .add_foreign_utxo(
            request.seller_outpoint,
            seller_psbt_input,
            Weight::from_wu(DEFAULT_FOREIGN_INPUT_SATISFACTION_WEIGHT_WU),
        )
        .map_err(|e| ZincError::OfferError(format!("failed adding seller input: {e}")))?;

    let unsigned_psbt = builder
        .finish()
        .map_err(|e| ZincError::OfferError(format!("failed to build offer psbt: {e}")))?;
    let unsigned_psbt_base64 =
        base64::engine::general_purpose::STANDARD.encode(unsigned_psbt.serialize());

    let seller_input_index = unsigned_psbt
        .unsigned_tx
        .input
        .iter()
        .position(|input| input.previous_output == request.seller_outpoint)
        .ok_or_else(|| {
            ZincError::OfferError(format!(
                "offer psbt is missing seller input {}",
                request.seller_outpoint
            ))
        })?;

    let buyer_input_indices: Vec<usize> = (0..unsigned_psbt.inputs.len())
        .filter(|index| *index != seller_input_index)
        .collect();
    if buyer_input_indices.is_empty() {
        return Err(ZincError::OfferError(
            "offer psbt must include at least one buyer input".to_string(),
        ));
    }

    let signed_psbt = wallet
        .sign_psbt(
            &unsigned_psbt_base64,
            Some(SignOptions {
                sign_inputs: Some(buyer_input_indices.clone()),
                sighash: None,
                finalize: true,
            }),
        )
        .map_err(ZincError::OfferError)?;

    let seller_pubkey_hex = resolve_publisher_pubkey(wallet, request)?;
    let offer = OfferEnvelopeV1 {
        version: 1,
        seller_pubkey_hex,
        network: network_name(wallet_network).to_string(),
        inscription_id: request.inscription_id.clone(),
        seller_outpoint: request.seller_outpoint.to_string(),
        ask_sats: request.ask_sats,
        fee_rate_sat_vb: request.fee_rate_sat_vb,
        psbt_base64: signed_psbt.clone(),
        created_at_unix: request.created_at_unix,
        expires_at_unix: request.expires_at_unix,
        nonce: request.nonce,
    };

    let plan = prepare_offer_acceptance(&offer, request.created_at_unix)?;
    Ok(OfferCreateResultV1 {
        psbt: signed_psbt,
        seller_address: seller_payout_address.to_string(),
        inscription: request.inscription_id.clone(),
        seller_outpoint: request.seller_outpoint.to_string(),
        postage_sats: request.seller_output_value_sats,
        ask_sats: request.ask_sats,
        fee_rate_sat_vb: request.fee_rate_sat_vb,
        seller_input_index: plan.seller_input_index,
        buyer_input_count: buyer_input_indices.len(),
        offer,
    })
}

fn validate_request(wallet: &ZincWallet, request: &CreateOfferRequest) -> Result<(), ZincError> {
    if !wallet.ordinals_verified {
        return Err(ZincError::WalletError(
            "Ordinals verification failed - safety lock engaged. Please retry sync.".to_string(),
        ));
    }

    if request.inscription_id.trim().is_empty() {
        return Err(ZincError::OfferError(
            "inscription_id must not be empty".to_string(),
        ));
    }
    if request.seller_input_address.trim().is_empty() {
        return Err(ZincError::OfferError(
            "seller_input_address must not be empty".to_string(),
        ));
    }
    if request.seller_payout_address.trim().is_empty() {
        return Err(ZincError::OfferError(
            "seller_payout_address must not be empty".to_string(),
        ));
    }
    if request.ask_sats == 0 {
        return Err(ZincError::OfferError("ask_sats must be > 0".to_string()));
    }
    if request.seller_output_value_sats == 0 {
        return Err(ZincError::OfferError(
            "seller output value must be > 0".to_string(),
        ));
    }
    if request.expires_at_unix <= request.created_at_unix {
        return Err(ZincError::OfferError(
            "offer expiration must be greater than creation time".to_string(),
        ));
    }

    Ok(())
}

fn resolve_publisher_pubkey(
    wallet: &ZincWallet,
    request: &CreateOfferRequest,
) -> Result<String, ZincError> {
    if let Some(pubkey_hex) = &request.publisher_pubkey_hex {
        XOnlyPublicKey::from_str(pubkey_hex)
            .map_err(|e| ZincError::OfferError(format!("invalid publisher_pubkey_hex: {e}")))?;
        return Ok(pubkey_hex.clone());
    }

    wallet
        .get_taproot_public_key(0)
        .map_err(ZincError::WalletError)
}

fn network_name(network: bdk_wallet::bitcoin::Network) -> &'static str {
    match network {
        bdk_wallet::bitcoin::Network::Bitcoin => "bitcoin",
        bdk_wallet::bitcoin::Network::Testnet => "testnet",
        bdk_wallet::bitcoin::Network::Signet => "signet",
        bdk_wallet::bitcoin::Network::Regtest => "regtest",
        _ => "bitcoin",
    }
}
