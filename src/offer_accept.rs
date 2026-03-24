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
