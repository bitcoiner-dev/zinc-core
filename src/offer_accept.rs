//! Offer acceptance validation helpers.
//!
//! These checks are intentionally aligned with ord's `wallet offer accept` safety model:
//! identify the single seller input, ensure seller input is currently unsigned, and ensure
//! all buyer inputs are already signed before seller signing proceeds.

use crate::{OfferEnvelopeV1, ZincError};
use base64::Engine;
use bdk_wallet::bitcoin::psbt::{Input, Psbt};
use bdk_wallet::bitcoin::OutPoint;
use serde::{Deserialize, Serialize};

/// Acceptance metadata derived from a validated offer payload.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OfferAcceptancePlanV1 {
    /// Canonical deterministic offer id digest (sha256 hex).
    pub offer_id: String,
    /// Input index in the PSBT that spends the seller outpoint.
    pub seller_input_index: usize,
    /// Total number of inputs in the offer PSBT.
    pub input_count: usize,
}

/// Validate offer acceptance prerequisites and return signing plan metadata.
pub fn prepare_offer_acceptance(
    offer: &OfferEnvelopeV1,
    now_unix: i64,
) -> Result<OfferAcceptancePlanV1, ZincError> {
    let offer_id = offer.offer_id_hex()?;
    if now_unix >= offer.expires_at_unix {
        return Err(ZincError::OfferError(format!(
            "offer has expired at {}",
            offer.expires_at_unix
        )));
    }

    let seller_outpoint = offer.seller_outpoint.parse::<OutPoint>().map_err(|e| {
        ZincError::OfferError(format!(
            "invalid seller_outpoint `{}`: {e}",
            offer.seller_outpoint
        ))
    })?;
    let psbt = decode_offer_psbt(offer)?;

    let seller_indices: Vec<usize> = psbt
        .unsigned_tx
        .input
        .iter()
        .enumerate()
        .filter_map(|(index, input)| (input.previous_output == seller_outpoint).then_some(index))
        .collect();

    match seller_indices.len() {
        0 => {
            return Err(ZincError::OfferError(format!(
                "offer psbt contains no seller input `{seller_outpoint}`"
            )))
        }
        1 => {}
        count => {
            return Err(ZincError::OfferError(format!(
                "offer psbt contains {count} seller inputs `{seller_outpoint}`"
            )))
        }
    }

    let seller_input_index = seller_indices[0];
    if seller_input_index != 0 {
        return Err(ZincError::OfferError(format!(
            "seller input `{seller_outpoint}` must be first input (index 0), found index {seller_input_index}"
        )));
    }

    validate_ord_layout(offer, &psbt, seller_input_index, seller_outpoint)?;

    if psbt
        .inputs
        .get(seller_input_index)
        .is_some_and(input_has_signature)
    {
        return Err(ZincError::OfferError(format!(
            "seller input `{seller_outpoint}` must be unsigned"
        )));
    }

    for (index, input) in psbt.inputs.iter().enumerate() {
        if index == seller_input_index {
            continue;
        }
        if !input_has_signature(input) {
            let outpoint = psbt.unsigned_tx.input[index].previous_output;
            return Err(ZincError::OfferError(format!(
                "buyer input `{outpoint}` must be signed"
            )));
        }
    }

    Ok(OfferAcceptancePlanV1 {
        offer_id,
        seller_input_index,
        input_count: psbt.inputs.len(),
    })
}

fn decode_offer_psbt(offer: &OfferEnvelopeV1) -> Result<Psbt, ZincError> {
    let bytes = base64::engine::general_purpose::STANDARD
        .decode(offer.psbt_base64.as_bytes())
        .map_err(|e| ZincError::OfferError(format!("invalid offer psbt base64: {e}")))?;
    Psbt::deserialize(&bytes).map_err(|e| ZincError::OfferError(format!("invalid offer psbt: {e}")))
}

fn input_has_signature(input: &Input) -> bool {
    input.final_script_sig.is_some()
        || input.final_script_witness.is_some()
        || !input.partial_sigs.is_empty()
        || input.tap_key_sig.is_some()
        || !input.tap_script_sigs.is_empty()
}

fn validate_ord_layout(
    offer: &OfferEnvelopeV1,
    psbt: &Psbt,
    seller_input_index: usize,
    seller_outpoint: OutPoint,
) -> Result<(), ZincError> {
    let seller_input = psbt
        .inputs
        .get(seller_input_index)
        .ok_or_else(|| ZincError::OfferError("seller input metadata missing".to_string()))?;
    let seller_txin = psbt
        .unsigned_tx
        .input
        .get(seller_input_index)
        .ok_or_else(|| ZincError::OfferError("seller tx input missing".to_string()))?;

    let seller_postage_sats = seller_input
        .witness_utxo
        .as_ref()
        .map(|txout| txout.value.to_sat())
        .or_else(|| {
            seller_input.non_witness_utxo.as_ref().and_then(|prev_tx| {
                prev_tx
                    .output
                    .get(seller_txin.previous_output.vout as usize)
                    .map(|txout| txout.value.to_sat())
            })
        })
        .ok_or_else(|| {
            ZincError::OfferError(format!(
                "seller input `{seller_outpoint}` is missing prevout value metadata"
            ))
        })?;

    if psbt.unsigned_tx.output.len() < 2 {
        return Err(ZincError::OfferError(
            "offer psbt must include buyer postage and seller payout outputs".to_string(),
        ));
    }

    let buyer_postage_out = &psbt.unsigned_tx.output[0];
    if buyer_postage_out.value.to_sat() != seller_postage_sats {
        return Err(ZincError::OfferError(format!(
            "buyer postage output must be first and equal seller postage {} sats; found {} sats",
            seller_postage_sats,
            buyer_postage_out.value.to_sat()
        )));
    }

    let expected_seller_payout = seller_postage_sats
        .checked_add(offer.ask_sats)
        .ok_or_else(|| ZincError::OfferError("ask_sats + postage overflows u64".to_string()))?;
    let seller_payout_out = &psbt.unsigned_tx.output[1];
    if seller_payout_out.value.to_sat() != expected_seller_payout {
        return Err(ZincError::OfferError(format!(
            "seller payout output must be second and equal ask+postage {} sats; found {} sats",
            expected_seller_payout,
            seller_payout_out.value.to_sat()
        )));
    }

    Ok(())
}
