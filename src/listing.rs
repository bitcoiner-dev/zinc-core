//! Fixed-price listing primitives inspired by ord.net passthrough sale PSBTs.
//!
//! This module is intentionally separate from the generic wallet signer. Listing
//! sales require `SIGHASH_SINGLE | SIGHASH_ANYONECANPAY`, which is unsafe unless
//! the exact seller payout shape is validated first.

use crate::builder::{AddressScheme, ZincWallet};
use crate::ZincError;
use base64::Engine;
use bdk_wallet::KeychainKind;
use bdk_wallet::TxOrdering;
use bitcoin::blockdata::opcodes::all::{OP_CHECKSIG, OP_CHECKSIGADD, OP_NUMEQUAL};
use bitcoin::blockdata::script::Builder;
use bitcoin::hashes::{sha256, Hash};
use bitcoin::psbt::{Input as PsbtInput, Output as PsbtOutput, Psbt};
use bitcoin::secp256k1::{Keypair, Message, Secp256k1, SecretKey, XOnlyPublicKey};
use bitcoin::sighash::{Prevouts, SighashCache, TapSighashType};
use bitcoin::taproot::TapLeafHash;
use bitcoin::taproot::{ControlBlock, LeafVersion, TaprootBuilder};
use bitcoin::{
    absolute, Amount, FeeRate, OutPoint, ScriptBuf, Sequence, Transaction, TxIn, TxOut, Weight,
    Witness,
};
use serde::{Deserialize, Serialize};
use std::str::FromStr;

/// Taproot sale-path sighash required for passive seller listings.
pub const LISTING_SALE_SIGHASH_U8: u8 = 0x83;

const DEFAULT_LISTING_FOREIGN_INPUT_SATISFACTION_WEIGHT_WU: u64 = 272;

/// Input parameters for deterministic fixed-price listing template construction.
#[derive(Debug, Clone)]
pub struct CreateListingRequest {
    /// Seller x-only Taproot public key hex.
    pub seller_pubkey_hex: String,
    /// Coordinator x-only Taproot public key hex.
    pub coordinator_pubkey_hex: String,
    /// Bitcoin network identifier.
    pub network: String,
    /// Inscription identifier.
    pub inscription_id: String,
    /// Seller-controlled outpoint holding the inscription before listing.
    pub seller_outpoint: OutPoint,
    /// Prevout metadata for `seller_outpoint`.
    pub seller_prevout: TxOut,
    /// Script receiving ask + postage in the sale transaction.
    pub seller_payout_script_pubkey: ScriptBuf,
    /// Script receiving the inscription if seller recovers/cancels the listing.
    pub recovery_script_pubkey: ScriptBuf,
    /// Ask price in sats, excluding postage.
    pub ask_sats: u64,
    /// Target fee rate for the final sale.
    pub fee_rate_sat_vb: u64,
    /// UNIX timestamp (seconds) listing creation time.
    pub created_at_unix: i64,
    /// UNIX timestamp (seconds) listing expiration time.
    pub expires_at_unix: i64,
    /// Caller-controlled nonce for uniqueness.
    pub nonce: u64,
}

/// Result payload for deterministic fixed-price listing template construction.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CreateListingResultV1 {
    /// Listing envelope ready for relay publication.
    pub listing: ListingEnvelopeV1,
    /// `TX1` output that creates the passthrough Taproot UTXO.
    pub passthrough_outpoint: OutPoint,
    /// Prevout metadata for the passthrough output.
    pub passthrough_txout: TxOut,
}

/// Fixed-price listing envelope v1.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ListingEnvelopeV1 {
    /// Envelope schema version.
    pub version: u8,
    /// Seller x-only Taproot public key hex.
    pub seller_pubkey_hex: String,
    /// Coordinator x-only Taproot public key hex.
    pub coordinator_pubkey_hex: String,
    /// Bitcoin network identifier.
    pub network: String,
    /// Inscription identifier.
    pub inscription_id: String,
    /// Original seller-controlled inscription outpoint.
    pub seller_outpoint: String,
    /// `TX1` output that moves the inscription into the passthrough Taproot output.
    pub passthrough_outpoint: String,
    /// Seller payout scriptPubKey hex committed by the sale signature.
    pub seller_payout_script_pubkey_hex: String,
    /// Ask price in sats, excluding postage.
    pub ask_sats: u64,
    /// Postage value carried by the inscription output.
    pub postage_sats: u64,
    /// Target fee rate for the final sale.
    pub fee_rate_sat_vb: u64,
    /// Listing transaction PSBT/transaction payload, base64.
    pub tx1_base64: String,
    /// Seller sale-path PSBT, base64.
    pub sale_psbt_base64: String,
    /// Seller recovery PSBT/transaction payload, base64.
    pub recovery_psbt_base64: String,
    /// UNIX timestamp (seconds) listing creation time.
    pub created_at_unix: i64,
    /// UNIX timestamp (seconds) listing expiration time.
    pub expires_at_unix: i64,
    /// Caller-controlled nonce for uniqueness.
    pub nonce: u64,
}

impl ListingEnvelopeV1 {
    fn validate(&self) -> Result<(), ZincError> {
        if self.version != 1 {
            return Err(ZincError::OfferError(format!(
                "unsupported listing version {}",
                self.version
            )));
        }

        if self.seller_pubkey_hex.is_empty()
            || self.coordinator_pubkey_hex.is_empty()
            || self.network.is_empty()
            || self.inscription_id.is_empty()
            || self.seller_outpoint.is_empty()
            || self.passthrough_outpoint.is_empty()
            || self.seller_payout_script_pubkey_hex.is_empty()
            || self.tx1_base64.is_empty()
            || self.sale_psbt_base64.is_empty()
            || self.recovery_psbt_base64.is_empty()
        {
            return Err(ZincError::OfferError(
                "listing contains empty required fields".to_string(),
            ));
        }

        XOnlyPublicKey::from_str(&self.seller_pubkey_hex)
            .map_err(|e| ZincError::OfferError(format!("invalid seller pubkey: {e}")))?;
        XOnlyPublicKey::from_str(&self.coordinator_pubkey_hex)
            .map_err(|e| ZincError::OfferError(format!("invalid coordinator pubkey: {e}")))?;
        self.seller_outpoint
            .parse::<OutPoint>()
            .map_err(|e| ZincError::OfferError(format!("invalid seller_outpoint: {e}")))?;
        self.passthrough_outpoint
            .parse::<OutPoint>()
            .map_err(|e| ZincError::OfferError(format!("invalid passthrough_outpoint: {e}")))?;
        script_from_hex(&self.seller_payout_script_pubkey_hex)?;

        if self.ask_sats == 0 {
            return Err(ZincError::OfferError("ask_sats must be > 0".to_string()));
        }
        if self.postage_sats == 0 {
            return Err(ZincError::OfferError(
                "postage_sats must be > 0".to_string(),
            ));
        }
        if self.expires_at_unix <= self.created_at_unix {
            return Err(ZincError::OfferError(
                "listing expiration must be greater than creation time".to_string(),
            ));
        }

        Ok(())
    }

    /// Serialize this envelope using canonical JSON bytes.
    pub fn canonical_json(&self) -> Result<Vec<u8>, ZincError> {
        self.validate()?;
        serde_json::to_vec(self).map_err(|e| ZincError::SerializationError(e.to_string()))
    }

    /// Compute the SHA-256 listing id digest bytes.
    pub fn listing_id_digest(&self) -> Result<[u8; 32], ZincError> {
        let canonical = self.canonical_json()?;
        let digest = sha256::Hash::hash(&canonical);
        Ok(digest.to_byte_array())
    }

    /// Compute the SHA-256 listing id hex string.
    pub fn listing_id_hex(&self) -> Result<String, ZincError> {
        let digest = self.listing_id_digest()?;
        Ok(digest.iter().map(|b| format!("{b:02x}")).collect())
    }
}

/// Sale signing metadata derived from a validated listing sale PSBT.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ListingSaleSigningPlanV1 {
    /// Canonical listing id digest (sha256 hex).
    pub listing_id: String,
    /// Seller input index in `sale_psbt_base64`.
    pub seller_input_index: usize,
    /// Required seller sale signature sighash.
    pub sighash_u8: u8,
    /// Exact seller payout amount committed by `SIGHASH_SINGLE`.
    pub seller_payout_sats: u64,
}

/// Buyer funding input metadata for completing a seller-signed listing PSBT.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ListingBuyerFundingInput {
    /// Buyer-controlled outpoint to append to the sale PSBT.
    pub previous_output: OutPoint,
    /// Prevout metadata required for signing and coordinator sighash validation.
    pub witness_utxo: TxOut,
}

/// Optional CPFP anchor output for fee bumping, per ord.net specification.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AnchorOutput {
    /// Script receiving the anchor output (buyer-controlled for CPFP spending).
    pub script_pubkey: ScriptBuf,
    /// Anchor output value in sats (typically dust limit, e.g. 330 sats).
    pub value_sats: u64,
}

/// Request to turn a seller-signed listing sale PSBT into a buyer-funded sale PSBT.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FinalizeListingPurchaseRequest {
    /// Listing envelope whose sale PSBT already contains the seller sale-path signature.
    pub listing: ListingEnvelopeV1,
    /// Buyer funding inputs to append after the passthrough inscription input.
    pub buyer_inputs: Vec<ListingBuyerFundingInput>,
    /// Script receiving the inscription postage output.
    pub buyer_receive_script_pubkey: ScriptBuf,
    /// Optional buyer change script.
    pub change_script_pubkey: Option<ScriptBuf>,
    /// Buyer change amount in sats. Set to zero for no change output.
    pub change_sats: u64,
    /// Optional CPFP anchor output for fee bumping.
    pub anchor_output: Option<AnchorOutput>,
    /// UNIX timestamp (seconds) used for listing expiration validation.
    pub now_unix: i64,
}

/// Result of buyer-side listing purchase finalization.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FinalizeListingPurchaseResultV1 {
    /// Listing envelope with `sale_psbt_base64` replaced by the buyer-funded PSBT.
    pub listing: ListingEnvelopeV1,
    /// Buyer-funded PSBT base64, ready for buyer input signing and coordinator pinning.
    pub psbt_base64: String,
    /// Computed fee in sats from PSBT prevout metadata and outputs.
    pub fee_sats: u64,
    /// Seller passthrough input index.
    pub seller_input_index: usize,
    /// Buyer inscription receive output index.
    pub buyer_receive_output_index: usize,
    /// Buyer change output index, if a change output was added.
    pub change_output_index: Option<usize>,
    /// CPFP anchor output index, if an anchor was added.
    pub anchor_output_index: Option<usize>,
}

/// Request to have the buyer wallet fund and sign buyer inputs for a listing purchase.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CreateListingPurchaseRequest {
    /// Listing envelope whose sale PSBT already contains the seller sale-path signature.
    pub listing: ListingEnvelopeV1,
    /// UNIX timestamp (seconds) used for listing expiration validation.
    pub now_unix: i64,
}

/// Result of wallet-funded buyer-side listing purchase construction.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CreateListingPurchaseResultV1 {
    /// Listing envelope with `sale_psbt_base64` replaced by the buyer-funded, buyer-signed PSBT.
    pub listing: ListingEnvelopeV1,
    /// Buyer-funded and buyer-signed PSBT base64, ready for coordinator pinning.
    pub psbt_base64: String,
    /// Computed fee in sats from PSBT prevout metadata and outputs.
    pub fee_sats: u64,
    /// Seller passthrough input index.
    pub seller_input_index: usize,
    /// Number of buyer-owned inputs signed by the wallet.
    pub buyer_input_count: usize,
    /// Buyer inscription receive output index.
    pub buyer_receive_output_index: usize,
}

/// Finalized listing sale transaction payload.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FinalizedListingSaleResultV1 {
    /// Finalized PSBT base64 with the passthrough input witness populated.
    pub finalized_psbt_base64: String,
    /// Extracted transaction hex, ready for broadcast.
    pub tx_hex: String,
    /// Extracted transaction id.
    pub txid: String,
    /// Seller passthrough input index.
    pub seller_input_index: usize,
    /// Final witness stack size for the passthrough input.
    pub passthrough_witness_items: usize,
}

/// Build the ord.net-style script-path leaf: `multi_a(2, seller, coordinator)`.
pub fn passthrough_tapscript(
    seller_pubkey: XOnlyPublicKey,
    coordinator_pubkey: XOnlyPublicKey,
) -> ScriptBuf {
    Builder::new()
        .push_x_only_key(&seller_pubkey)
        .push_opcode(OP_CHECKSIG)
        .push_x_only_key(&coordinator_pubkey)
        .push_opcode(OP_CHECKSIGADD)
        .push_int(2)
        .push_opcode(OP_NUMEQUAL)
        .into_script()
}

/// Build the passthrough Taproot scriptPubKey.
pub fn passthrough_script_pubkey(
    seller_pubkey: XOnlyPublicKey,
    coordinator_pubkey: XOnlyPublicKey,
) -> ScriptBuf {
    let spend_info = passthrough_spend_info(seller_pubkey, coordinator_pubkey);
    ScriptBuf::new_p2tr_tweaked(spend_info.output_key())
}

fn passthrough_spend_info(
    seller_pubkey: XOnlyPublicKey,
    coordinator_pubkey: XOnlyPublicKey,
) -> bitcoin::taproot::TaprootSpendInfo {
    let secp = Secp256k1::verification_only();
    let script = passthrough_tapscript(seller_pubkey, coordinator_pubkey);
    TaprootBuilder::new()
        .add_leaf(0, script)
        .expect("single-leaf taproot builder")
        .finalize(&secp, seller_pubkey)
        .expect("single-leaf taproot tree is finalizable")
}

/// Build the three PSBT templates and listing envelope for a passive fixed-price sale.
pub fn create_listing(request: &CreateListingRequest) -> Result<CreateListingResultV1, ZincError> {
    validate_create_listing_request(request)?;

    let seller_pubkey = XOnlyPublicKey::from_str(&request.seller_pubkey_hex)
        .map_err(|e| ZincError::OfferError(format!("invalid seller pubkey: {e}")))?;
    let coordinator_pubkey = XOnlyPublicKey::from_str(&request.coordinator_pubkey_hex)
        .map_err(|e| ZincError::OfferError(format!("invalid coordinator pubkey: {e}")))?;
    let passthrough_script_pubkey = passthrough_script_pubkey(seller_pubkey, coordinator_pubkey);
    let postage_sats = request.seller_prevout.value.to_sat();

    let tx1 = Transaction {
        version: bitcoin::transaction::Version(2),
        lock_time: absolute::LockTime::ZERO,
        input: vec![template_txin(request.seller_outpoint)],
        output: vec![TxOut {
            value: Amount::from_sat(postage_sats),
            script_pubkey: passthrough_script_pubkey,
        }],
    };
    let mut tx1_psbt = Psbt::from_unsigned_tx(tx1)
        .map_err(|e| ZincError::OfferError(format!("failed to build tx1 psbt: {e}")))?;
    tx1_psbt.inputs[0].witness_utxo = Some(request.seller_prevout.clone());

    let passthrough_outpoint = OutPoint::new(tx1_psbt.unsigned_tx.compute_txid(), 0);
    let passthrough_txout = tx1_psbt.unsigned_tx.output[0].clone();

    let sale_psbt = build_sale_psbt(
        request,
        seller_pubkey,
        coordinator_pubkey,
        passthrough_outpoint,
        passthrough_txout.clone(),
    )?;
    let recovery_psbt =
        build_recovery_psbt(request, passthrough_outpoint, passthrough_txout.clone())?;

    let listing = ListingEnvelopeV1 {
        version: 1,
        seller_pubkey_hex: request.seller_pubkey_hex.clone(),
        coordinator_pubkey_hex: request.coordinator_pubkey_hex.clone(),
        network: request.network.clone(),
        inscription_id: request.inscription_id.clone(),
        seller_outpoint: request.seller_outpoint.to_string(),
        passthrough_outpoint: passthrough_outpoint.to_string(),
        seller_payout_script_pubkey_hex: request.seller_payout_script_pubkey.to_hex_string(),
        ask_sats: request.ask_sats,
        postage_sats,
        fee_rate_sat_vb: request.fee_rate_sat_vb,
        tx1_base64: encode_psbt_base64(&tx1_psbt),
        sale_psbt_base64: encode_psbt_base64(&sale_psbt),
        recovery_psbt_base64: encode_psbt_base64(&recovery_psbt),
        created_at_unix: request.created_at_unix,
        expires_at_unix: request.expires_at_unix,
        nonce: request.nonce,
    };

    prepare_listing_sale_signature(&listing, request.created_at_unix)?;

    Ok(CreateListingResultV1 {
        listing,
        passthrough_outpoint,
        passthrough_txout,
    })
}

/// Sign a listing sale PSBT with the seller key using the isolated listing safety checks.
///
/// This intentionally does not relax the generic wallet signer. The sale PSBT must pass
/// `prepare_listing_sale_signature` before the `SIGHASH_SINGLE|ANYONECANPAY` signature is added.
pub fn sign_listing_sale_psbt(
    listing: &ListingEnvelopeV1,
    seller_secret_key_hex: &str,
    now_unix: i64,
) -> Result<String, ZincError> {
    let plan = prepare_listing_sale_signature(listing, now_unix)?;
    let seller_secret_key = SecretKey::from_str(seller_secret_key_hex)
        .map_err(|e| ZincError::OfferError(format!("invalid seller secret key: {e}")))?;

    let secp = Secp256k1::new();
    let keypair = Keypair::from_secret_key(&secp, &seller_secret_key);
    let (derived_seller_pubkey, _) = XOnlyPublicKey::from_keypair(&keypair);
    let listing_seller_pubkey = XOnlyPublicKey::from_str(&listing.seller_pubkey_hex)
        .map_err(|e| ZincError::OfferError(format!("invalid listing seller pubkey: {e}")))?;
    if derived_seller_pubkey != listing_seller_pubkey {
        return Err(ZincError::OfferError(
            "seller secret key does not match listing seller pubkey".to_string(),
        ));
    }

    let coordinator_pubkey = XOnlyPublicKey::from_str(&listing.coordinator_pubkey_hex)
        .map_err(|e| ZincError::OfferError(format!("invalid coordinator pubkey: {e}")))?;
    let mut psbt = decode_listing_sale_psbt(listing)?;
    let input_index = plan.seller_input_index;
    let (leaf_hash, _script) = find_passthrough_tap_leaf(
        &psbt,
        input_index,
        listing_seller_pubkey,
        coordinator_pubkey,
    )?;

    let prevouts: Vec<TxOut> = (0..psbt.inputs.len())
        .map(|index| input_prevout(&psbt, index).cloned())
        .collect::<Result<Vec<_>, _>>()?;
    let sighash = SighashCache::new(&psbt.unsigned_tx)
        .taproot_script_spend_signature_hash(
            input_index,
            &Prevouts::All(&prevouts),
            leaf_hash,
            TapSighashType::SinglePlusAnyoneCanPay,
        )
        .map_err(|e| ZincError::OfferError(format!("failed to compute sale sighash: {e}")))?;
    let message = Message::from_digest(sighash.to_byte_array());
    let signature = secp.sign_schnorr(&message, &keypair);
    psbt.inputs[input_index].tap_script_sigs.insert(
        (listing_seller_pubkey, leaf_hash),
        bitcoin::taproot::Signature {
            signature,
            sighash_type: TapSighashType::SinglePlusAnyoneCanPay,
        },
    );

    Ok(encode_psbt_base64(&psbt))
}

/// Sign a listing sale PSBT with the coordinator key using `SIGHASH_DEFAULT`.
///
/// The coordinator signature pins the final transaction after the seller has already
/// authorized the sale input with `SIGHASH_SINGLE|ANYONECANPAY`.
pub fn sign_listing_coordinator_psbt(
    listing: &ListingEnvelopeV1,
    coordinator_secret_key_hex: &str,
    now_unix: i64,
) -> Result<String, ZincError> {
    let plan = prepare_listing_sale_signature_with_policy(listing, now_unix, true)?;
    let coordinator_secret_key = SecretKey::from_str(coordinator_secret_key_hex)
        .map_err(|e| ZincError::OfferError(format!("invalid coordinator secret key: {e}")))?;

    let secp = Secp256k1::new();
    let keypair = Keypair::from_secret_key(&secp, &coordinator_secret_key);
    let (derived_coordinator_pubkey, _) = XOnlyPublicKey::from_keypair(&keypair);
    let listing_coordinator_pubkey = XOnlyPublicKey::from_str(&listing.coordinator_pubkey_hex)
        .map_err(|e| ZincError::OfferError(format!("invalid listing coordinator pubkey: {e}")))?;
    if derived_coordinator_pubkey != listing_coordinator_pubkey {
        return Err(ZincError::OfferError(
            "coordinator secret key does not match listing coordinator pubkey".to_string(),
        ));
    }

    let seller_pubkey = XOnlyPublicKey::from_str(&listing.seller_pubkey_hex)
        .map_err(|e| ZincError::OfferError(format!("invalid listing seller pubkey: {e}")))?;
    let mut psbt = decode_listing_sale_psbt(listing)?;
    let input_index = plan.seller_input_index;
    let (leaf_hash, _script) = find_passthrough_tap_leaf(
        &psbt,
        input_index,
        seller_pubkey,
        listing_coordinator_pubkey,
    )?;
    ensure_seller_sale_signature(&psbt, input_index, seller_pubkey, leaf_hash)?;

    let prevouts: Vec<TxOut> = (0..psbt.inputs.len())
        .map(|index| input_prevout(&psbt, index).cloned())
        .collect::<Result<Vec<_>, _>>()?;
    let sighash = SighashCache::new(&psbt.unsigned_tx)
        .taproot_script_spend_signature_hash(
            input_index,
            &Prevouts::All(&prevouts),
            leaf_hash,
            TapSighashType::Default,
        )
        .map_err(|e| {
            ZincError::OfferError(format!("failed to compute coordinator sighash: {e}"))
        })?;
    let message = Message::from_digest(sighash.to_byte_array());
    let signature = secp.sign_schnorr(&message, &keypair);
    psbt.inputs[input_index].tap_script_sigs.insert(
        (listing_coordinator_pubkey, leaf_hash),
        bitcoin::taproot::Signature {
            signature,
            sighash_type: TapSighashType::Default,
        },
    );

    Ok(encode_psbt_base64(&psbt))
}

/// Append buyer funding and receive/change outputs to a seller-signed listing sale PSBT.
///
/// The seller's `SIGHASH_SINGLE|ANYONECANPAY` signature commits only to the passthrough
/// input and seller payout output at the same index. This function preserves that pair
/// and appends the buyer side of the transaction without adding coordinator signatures.
pub fn finalize_listing_purchase(
    request: &FinalizeListingPurchaseRequest,
) -> Result<FinalizeListingPurchaseResultV1, ZincError> {
    if request.buyer_inputs.is_empty() {
        return Err(ZincError::OfferError(
            "listing purchase requires at least one buyer funding input".to_string(),
        ));
    }
    if request.buyer_receive_script_pubkey.is_empty() {
        return Err(ZincError::OfferError(
            "buyer receive scriptPubKey must not be empty".to_string(),
        ));
    }
    if request.change_sats > 0
        && request
            .change_script_pubkey
            .as_ref()
            .is_none_or(|script| script.as_script().is_empty())
    {
        return Err(ZincError::OfferError(
            "change scriptPubKey is required when change_sats > 0".to_string(),
        ));
    }

    let plan =
        prepare_listing_sale_signature_with_policy(&request.listing, request.now_unix, true)?;
    if plan.seller_input_index != 0 {
        return Err(ZincError::OfferError(format!(
            "listing purchase passthrough input must be index 0; found {}",
            plan.seller_input_index
        )));
    }

    let seller_pubkey = XOnlyPublicKey::from_str(&request.listing.seller_pubkey_hex)
        .map_err(|e| ZincError::OfferError(format!("invalid listing seller pubkey: {e}")))?;
    let coordinator_pubkey = XOnlyPublicKey::from_str(&request.listing.coordinator_pubkey_hex)
        .map_err(|e| ZincError::OfferError(format!("invalid coordinator pubkey: {e}")))?;
    let passthrough_outpoint = request
        .listing
        .passthrough_outpoint
        .parse::<OutPoint>()
        .map_err(|e| ZincError::OfferError(format!("invalid passthrough_outpoint: {e}")))?;

    let mut psbt = decode_listing_sale_psbt(&request.listing)?;
    let (leaf_hash, _script) = find_passthrough_tap_leaf(
        &psbt,
        plan.seller_input_index,
        seller_pubkey,
        coordinator_pubkey,
    )?;
    ensure_seller_sale_signature(&psbt, plan.seller_input_index, seller_pubkey, leaf_hash)?;
    if psbt.inputs[plan.seller_input_index]
        .tap_script_sigs
        .contains_key(&(coordinator_pubkey, leaf_hash))
    {
        return Err(ZincError::OfferError(
            "listing purchase PSBT is already coordinator signed".to_string(),
        ));
    }

    let mut buyer_input_total = 0u64;
    for buyer_input in &request.buyer_inputs {
        if buyer_input.previous_output == passthrough_outpoint {
            return Err(ZincError::OfferError(
                "buyer funding input duplicates passthrough outpoint".to_string(),
            ));
        }
        if buyer_input.witness_utxo.value.to_sat() == 0 {
            return Err(ZincError::OfferError(
                "buyer funding input value must be > 0".to_string(),
            ));
        }
        buyer_input_total = buyer_input_total
            .checked_add(buyer_input.witness_utxo.value.to_sat())
            .ok_or_else(|| ZincError::OfferError("buyer input value overflows u64".to_string()))?;
    }

    let buyer_receive_output_index = psbt.unsigned_tx.output.len();
    psbt.unsigned_tx.output.push(TxOut {
        value: Amount::from_sat(request.listing.postage_sats),
        script_pubkey: request.buyer_receive_script_pubkey.clone(),
    });
    psbt.outputs.push(PsbtOutput::default());

    let change_output_index = if request.change_sats > 0 {
        let index = psbt.unsigned_tx.output.len();
        psbt.unsigned_tx.output.push(TxOut {
            value: Amount::from_sat(request.change_sats),
            script_pubkey: request
                .change_script_pubkey
                .clone()
                .expect("validated change script"),
        });
        psbt.outputs.push(PsbtOutput::default());
        Some(index)
    } else {
        None
    };

    let anchor_output_index = if let Some(anchor) = &request.anchor_output {
        if anchor.script_pubkey.is_empty() {
            return Err(ZincError::OfferError(
                "anchor output scriptPubKey must not be empty".to_string(),
            ));
        }
        if anchor.value_sats == 0 {
            return Err(ZincError::OfferError(
                "anchor output value must be > 0".to_string(),
            ));
        }
        let index = psbt.unsigned_tx.output.len();
        psbt.unsigned_tx.output.push(TxOut {
            value: Amount::from_sat(anchor.value_sats),
            script_pubkey: anchor.script_pubkey.clone(),
        });
        psbt.outputs.push(PsbtOutput::default());
        Some(index)
    } else {
        None
    };

    for buyer_input in &request.buyer_inputs {
        psbt.unsigned_tx
            .input
            .push(template_txin(buyer_input.previous_output));
        psbt.inputs.push(PsbtInput {
            witness_utxo: Some(buyer_input.witness_utxo.clone()),
            ..PsbtInput::default()
        });
    }

    let total_input_sats = request
        .listing
        .postage_sats
        .checked_add(buyer_input_total)
        .ok_or_else(|| ZincError::OfferError("total input value overflows u64".to_string()))?;
    let total_output_sats = psbt
        .unsigned_tx
        .output
        .iter()
        .try_fold(0u64, |total, output| {
            total.checked_add(output.value.to_sat()).ok_or_else(|| {
                ZincError::OfferError("total output value overflows u64".to_string())
            })
        })?;
    let fee_sats = total_input_sats.checked_sub(total_output_sats).ok_or_else(|| {
        ZincError::OfferError(format!(
            "buyer funding is insufficient: inputs {total_input_sats} sats, outputs {total_output_sats} sats"
        ))
    })?;
    if fee_sats == 0 {
        return Err(ZincError::OfferError(
            "listing purchase fee must be > 0".to_string(),
        ));
    }

    let psbt_base64 = encode_psbt_base64(&psbt);
    let mut listing = request.listing.clone();
    listing.sale_psbt_base64 = psbt_base64.clone();

    Ok(FinalizeListingPurchaseResultV1 {
        listing,
        psbt_base64,
        fee_sats,
        seller_input_index: plan.seller_input_index,
        buyer_receive_output_index,
        change_output_index,
        anchor_output_index,
    })
}

/// Fund a seller-signed listing sale PSBT from the buyer wallet and sign buyer inputs only.
#[allow(deprecated)]
pub fn create_listing_purchase(
    wallet: &mut ZincWallet,
    request: &CreateListingPurchaseRequest,
) -> Result<CreateListingPurchaseResultV1, ZincError> {
    if !wallet.ordinals_verified {
        return Err(ZincError::WalletError(
            "Ordinals verification failed - safety lock engaged. Please retry sync.".to_string(),
        ));
    }

    let plan =
        prepare_listing_sale_signature_with_policy(&request.listing, request.now_unix, true)?;
    if plan.seller_input_index != 0 {
        return Err(ZincError::OfferError(format!(
            "listing purchase passthrough input must be index 0; found {}",
            plan.seller_input_index
        )));
    }

    let seller_pubkey = XOnlyPublicKey::from_str(&request.listing.seller_pubkey_hex)
        .map_err(|e| ZincError::OfferError(format!("invalid listing seller pubkey: {e}")))?;
    let coordinator_pubkey = XOnlyPublicKey::from_str(&request.listing.coordinator_pubkey_hex)
        .map_err(|e| ZincError::OfferError(format!("invalid coordinator pubkey: {e}")))?;
    let sale_psbt = decode_listing_sale_psbt(&request.listing)?;
    let (leaf_hash, _script) = find_passthrough_tap_leaf(
        &sale_psbt,
        plan.seller_input_index,
        seller_pubkey,
        coordinator_pubkey,
    )?;
    ensure_seller_sale_signature(
        &sale_psbt,
        plan.seller_input_index,
        seller_pubkey,
        leaf_hash,
    )?;
    if sale_psbt.inputs[plan.seller_input_index]
        .tap_script_sigs
        .contains_key(&(coordinator_pubkey, leaf_hash))
    {
        return Err(ZincError::OfferError(
            "listing purchase PSBT is already coordinator signed".to_string(),
        ));
    }

    let passthrough_outpoint = request
        .listing
        .passthrough_outpoint
        .parse::<OutPoint>()
        .map_err(|e| ZincError::OfferError(format!("invalid passthrough_outpoint: {e}")))?;
    let seller_input = sale_psbt.inputs[plan.seller_input_index].clone();
    let seller_payout_script = script_from_hex(&request.listing.seller_payout_script_pubkey_hex)?;
    let seller_payout_sats = request
        .listing
        .ask_sats
        .checked_add(request.listing.postage_sats)
        .ok_or_else(|| ZincError::OfferError("ask_sats + postage overflows u64".to_string()))?;
    let fee_rate = FeeRate::from_sat_per_vb(request.listing.fee_rate_sat_vb)
        .ok_or_else(|| ZincError::OfferError("invalid fee rate".to_string()))?;

    let buyer_receive_script = wallet
        .vault_wallet
        .peek_address(KeychainKind::External, 0)
        .script_pubkey();
    let protected_outpoints = wallet.inscribed_utxos.iter().copied().collect();
    let signing_wallet = if wallet.scheme == AddressScheme::Dual {
        wallet
            .payment_wallet
            .as_mut()
            .ok_or_else(|| ZincError::WalletError("Payment wallet not initialized".to_string()))?
    } else {
        &mut wallet.vault_wallet
    };
    let change_script = signing_wallet
        .peek_address(KeychainKind::External, 0)
        .script_pubkey();

    let mut builder = signing_wallet.build_tx();
    if !wallet.inscribed_utxos.is_empty() {
        builder.unspendable(protected_outpoints);
    }
    builder.ordering(TxOrdering::Untouched);
    builder
        .add_recipient(seller_payout_script, Amount::from_sat(seller_payout_sats))
        .add_recipient(
            buyer_receive_script,
            Amount::from_sat(request.listing.postage_sats),
        )
        .drain_to(change_script)
        .fee_rate(fee_rate)
        .only_witness_utxo()
        .add_foreign_utxo(
            passthrough_outpoint,
            seller_input,
            Weight::from_wu(DEFAULT_LISTING_FOREIGN_INPUT_SATISFACTION_WEIGHT_WU),
        )
        .map_err(|e| ZincError::OfferError(format!("failed adding passthrough input: {e}")))?;

    let mut psbt = builder.finish().map_err(|e| {
        ZincError::OfferError(format!("failed to build listing purchase psbt: {e}"))
    })?;
    let seller_input_index = psbt
        .unsigned_tx
        .input
        .iter()
        .position(|input| input.previous_output == passthrough_outpoint)
        .ok_or_else(|| {
            ZincError::OfferError(format!(
                "listing purchase psbt is missing passthrough input {passthrough_outpoint}"
            ))
        })?;
    if seller_input_index != 0 {
        return Err(ZincError::OfferError(format!(
            "listing purchase passthrough input must be index 0; found {seller_input_index}"
        )));
    }

    validate_seller_input(
        &request.listing,
        &psbt,
        seller_input_index,
        passthrough_outpoint,
        true,
    )?;
    ensure_seller_sale_signature(&psbt, seller_input_index, seller_pubkey, leaf_hash)?;

    let original_seller_input = psbt.inputs[seller_input_index].clone();
    psbt.inputs[seller_input_index].sighash_type = None;
    let buyer_input_indices: Vec<usize> = (0..psbt.inputs.len())
        .filter(|index| *index != seller_input_index)
        .collect();
    if buyer_input_indices.is_empty() {
        return Err(ZincError::OfferError(
            "listing purchase must include at least one buyer input".to_string(),
        ));
    }

    signing_wallet
        .sign(
            &mut psbt,
            bdk_wallet::SignOptions {
                trust_witness_utxo: true,
                try_finalize: true,
                ..Default::default()
            },
        )
        .map_err(|e| ZincError::OfferError(format!("failed to sign buyer inputs: {e}")))?;
    psbt.inputs[seller_input_index] = original_seller_input;

    for index in &buyer_input_indices {
        if !input_has_signature(&psbt.inputs[*index]) {
            return Err(ZincError::OfferError(format!(
                "buyer input #{} was not signed by this wallet",
                index
            )));
        }
    }

    let fee_sats = psbt_fee_sats(&psbt)?;
    if fee_sats == 0 {
        return Err(ZincError::OfferError(
            "listing purchase fee must be > 0".to_string(),
        ));
    }

    let psbt_base64 = encode_psbt_base64(&psbt);
    let mut listing = request.listing.clone();
    listing.sale_psbt_base64 = psbt_base64.clone();
    prepare_listing_sale_signature_with_policy(&listing, request.now_unix, true)?;

    Ok(CreateListingPurchaseResultV1 {
        listing,
        psbt_base64,
        fee_sats,
        seller_input_index,
        buyer_input_count: buyer_input_indices.len(),
        buyer_receive_output_index: 1,
    })
}

/// Finalize a coordinator-signed listing sale PSBT and extract the broadcast transaction.
pub fn finalize_listing_sale(
    listing: &ListingEnvelopeV1,
    now_unix: i64,
) -> Result<FinalizedListingSaleResultV1, ZincError> {
    let plan = prepare_listing_sale_signature_with_policy(listing, now_unix, true)?;
    let seller_pubkey = XOnlyPublicKey::from_str(&listing.seller_pubkey_hex)
        .map_err(|e| ZincError::OfferError(format!("invalid listing seller pubkey: {e}")))?;
    let coordinator_pubkey = XOnlyPublicKey::from_str(&listing.coordinator_pubkey_hex)
        .map_err(|e| ZincError::OfferError(format!("invalid coordinator pubkey: {e}")))?;
    let mut psbt = decode_listing_sale_psbt(listing)?;
    let (control_block, leaf_hash, script) = find_passthrough_tap_leaf_entry(
        &psbt,
        plan.seller_input_index,
        seller_pubkey,
        coordinator_pubkey,
    )?;
    ensure_seller_sale_signature(&psbt, plan.seller_input_index, seller_pubkey, leaf_hash)?;
    ensure_coordinator_default_signature(
        &psbt,
        plan.seller_input_index,
        coordinator_pubkey,
        leaf_hash,
    )?;

    let input = psbt
        .inputs
        .get_mut(plan.seller_input_index)
        .ok_or_else(|| ZincError::OfferError("seller input metadata missing".to_string()))?;
    let seller_sig = *input
        .tap_script_sigs
        .get(&(seller_pubkey, leaf_hash))
        .expect("validated seller signature");
    let coordinator_sig = *input
        .tap_script_sigs
        .get(&(coordinator_pubkey, leaf_hash))
        .expect("validated coordinator signature");
    input.final_script_witness = Some(Witness::from_slice(&[
        coordinator_sig.to_vec(),
        seller_sig.to_vec(),
        script.to_bytes(),
        control_block.serialize(),
    ]));

    for (index, input) in psbt.inputs.iter().enumerate() {
        if input.final_script_witness.is_none() && input.final_script_sig.is_none() {
            return Err(ZincError::OfferError(format!(
                "input #{index} is not finalized"
            )));
        }
    }

    let finalized_psbt_base64 = encode_psbt_base64(&psbt);
    let passthrough_witness_items = psbt.inputs[plan.seller_input_index]
        .final_script_witness
        .as_ref()
        .expect("set witness")
        .len();
    let tx = psbt
        .extract_tx()
        .map_err(|e| ZincError::OfferError(format!("failed to extract finalized sale tx: {e}")))?;
    let txid = tx.compute_txid().to_string();
    let tx_hex = hex::encode(bitcoin::consensus::serialize(&tx));

    Ok(FinalizedListingSaleResultV1 {
        finalized_psbt_base64,
        tx_hex,
        txid,
        seller_input_index: plan.seller_input_index,
        passthrough_witness_items,
    })
}

fn validate_create_listing_request(request: &CreateListingRequest) -> Result<(), ZincError> {
    XOnlyPublicKey::from_str(&request.seller_pubkey_hex)
        .map_err(|e| ZincError::OfferError(format!("invalid seller pubkey: {e}")))?;
    XOnlyPublicKey::from_str(&request.coordinator_pubkey_hex)
        .map_err(|e| ZincError::OfferError(format!("invalid coordinator pubkey: {e}")))?;

    if request.network.trim().is_empty()
        || request.inscription_id.trim().is_empty()
        || request.seller_payout_script_pubkey.is_empty()
        || request.recovery_script_pubkey.is_empty()
    {
        return Err(ZincError::OfferError(
            "listing request contains empty required fields".to_string(),
        ));
    }
    if request.ask_sats == 0 {
        return Err(ZincError::OfferError("ask_sats must be > 0".to_string()));
    }
    if request.seller_prevout.value.to_sat() == 0 {
        return Err(ZincError::OfferError(
            "seller prevout value must be > 0".to_string(),
        ));
    }
    if request.expires_at_unix <= request.created_at_unix {
        return Err(ZincError::OfferError(
            "listing expiration must be greater than creation time".to_string(),
        ));
    }

    Ok(())
}

fn build_sale_psbt(
    request: &CreateListingRequest,
    seller_pubkey: XOnlyPublicKey,
    coordinator_pubkey: XOnlyPublicKey,
    passthrough_outpoint: OutPoint,
    passthrough_txout: TxOut,
) -> Result<Psbt, ZincError> {
    let seller_payout_sats = request
        .ask_sats
        .checked_add(passthrough_txout.value.to_sat())
        .ok_or_else(|| ZincError::OfferError("ask_sats + postage overflows u64".to_string()))?;
    let tx = Transaction {
        version: bitcoin::transaction::Version(2),
        lock_time: absolute::LockTime::ZERO,
        input: vec![template_txin(passthrough_outpoint)],
        output: vec![TxOut {
            value: Amount::from_sat(seller_payout_sats),
            script_pubkey: request.seller_payout_script_pubkey.clone(),
        }],
    };
    let mut psbt = Psbt::from_unsigned_tx(tx)
        .map_err(|e| ZincError::OfferError(format!("failed to build sale psbt: {e}")))?;
    psbt.inputs[0].witness_utxo = Some(passthrough_txout);
    psbt.inputs[0].sighash_type = Some(bitcoin::psbt::PsbtSighashType::from_u32(u32::from(
        LISTING_SALE_SIGHASH_U8,
    )));
    let tapscript = passthrough_tapscript(seller_pubkey, coordinator_pubkey);
    let spend_info = passthrough_spend_info(seller_pubkey, coordinator_pubkey);
    let control_block = spend_info
        .control_block(&(tapscript.clone(), LeafVersion::TapScript))
        .ok_or_else(|| ZincError::OfferError("missing passthrough control block".to_string()))?;
    psbt.inputs[0]
        .tap_scripts
        .insert(control_block, (tapscript, LeafVersion::TapScript));
    Ok(psbt)
}

fn build_recovery_psbt(
    request: &CreateListingRequest,
    passthrough_outpoint: OutPoint,
    passthrough_txout: TxOut,
) -> Result<Psbt, ZincError> {
    let tx = Transaction {
        version: bitcoin::transaction::Version(2),
        lock_time: absolute::LockTime::ZERO,
        input: vec![template_txin(passthrough_outpoint)],
        output: vec![TxOut {
            value: passthrough_txout.value,
            script_pubkey: request.recovery_script_pubkey.clone(),
        }],
    };
    let mut psbt = Psbt::from_unsigned_tx(tx)
        .map_err(|e| ZincError::OfferError(format!("failed to build recovery psbt: {e}")))?;
    psbt.inputs[0].witness_utxo = Some(passthrough_txout);
    Ok(psbt)
}

fn template_txin(previous_output: OutPoint) -> TxIn {
    TxIn {
        previous_output,
        script_sig: ScriptBuf::new(),
        sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
        witness: Witness::new(),
    }
}

fn encode_psbt_base64(psbt: &Psbt) -> String {
    base64::engine::general_purpose::STANDARD.encode(psbt.serialize())
}

/// Validate that a listing sale PSBT is safe for the seller's sale-path signature.
pub fn prepare_listing_sale_signature(
    listing: &ListingEnvelopeV1,
    now_unix: i64,
) -> Result<ListingSaleSigningPlanV1, ZincError> {
    prepare_listing_sale_signature_with_policy(listing, now_unix, false)
}

fn prepare_listing_sale_signature_with_policy(
    listing: &ListingEnvelopeV1,
    now_unix: i64,
    allow_existing_signature: bool,
) -> Result<ListingSaleSigningPlanV1, ZincError> {
    let listing_id = listing.listing_id_hex()?;
    if now_unix >= listing.expires_at_unix {
        return Err(ZincError::OfferError(format!(
            "listing has expired at {}",
            listing.expires_at_unix
        )));
    }

    let passthrough_outpoint = listing
        .passthrough_outpoint
        .parse::<OutPoint>()
        .map_err(|e| {
            ZincError::OfferError(format!(
                "invalid passthrough_outpoint `{}`: {e}",
                listing.passthrough_outpoint
            ))
        })?;
    let psbt = decode_listing_sale_psbt(listing)?;

    let seller_indices: Vec<usize> = psbt
        .unsigned_tx
        .input
        .iter()
        .enumerate()
        .filter_map(|(index, input)| {
            (input.previous_output == passthrough_outpoint).then_some(index)
        })
        .collect();

    match seller_indices.len() {
        0 => {
            return Err(ZincError::OfferError(format!(
                "sale psbt contains no passthrough input `{passthrough_outpoint}`"
            )))
        }
        1 => {}
        count => {
            return Err(ZincError::OfferError(format!(
                "sale psbt contains {count} passthrough inputs `{passthrough_outpoint}`"
            )))
        }
    }

    let seller_input_index = seller_indices[0];
    validate_seller_input(
        listing,
        &psbt,
        seller_input_index,
        passthrough_outpoint,
        allow_existing_signature,
    )?;

    Ok(ListingSaleSigningPlanV1 {
        listing_id,
        seller_input_index,
        sighash_u8: LISTING_SALE_SIGHASH_U8,
        seller_payout_sats: listing
            .ask_sats
            .checked_add(listing.postage_sats)
            .ok_or_else(|| ZincError::OfferError("ask_sats + postage overflows u64".to_string()))?,
    })
}

fn decode_listing_sale_psbt(listing: &ListingEnvelopeV1) -> Result<Psbt, ZincError> {
    let bytes = base64::engine::general_purpose::STANDARD
        .decode(listing.sale_psbt_base64.as_bytes())
        .map_err(|e| ZincError::OfferError(format!("invalid sale psbt base64: {e}")))?;
    Psbt::deserialize(&bytes).map_err(|e| ZincError::OfferError(format!("invalid sale psbt: {e}")))
}

fn validate_seller_input(
    listing: &ListingEnvelopeV1,
    psbt: &Psbt,
    seller_input_index: usize,
    passthrough_outpoint: OutPoint,
    allow_existing_signature: bool,
) -> Result<(), ZincError> {
    let seller_input = psbt
        .inputs
        .get(seller_input_index)
        .ok_or_else(|| ZincError::OfferError("seller input metadata missing".to_string()))?;

    if !allow_existing_signature && input_has_signature(seller_input) {
        return Err(ZincError::OfferError(format!(
            "passthrough input `{passthrough_outpoint}` must be unsigned"
        )));
    }

    let sighash_u8 = seller_input
        .sighash_type
        .map(|sighash| sighash.to_u32() as u8)
        .ok_or_else(|| {
            ZincError::OfferError(
                "sale psbt seller input must request SIGHASH_SINGLE|SIGHASH_ANYONECANPAY"
                    .to_string(),
            )
        })?;
    if sighash_u8 != LISTING_SALE_SIGHASH_U8 {
        return Err(ZincError::OfferError(format!(
            "sale psbt seller input must request SIGHASH_SINGLE|SIGHASH_ANYONECANPAY ({LISTING_SALE_SIGHASH_U8:#x}); found {sighash_u8:#x}"
        )));
    }

    let seller_prevout = input_prevout(psbt, seller_input_index)?;
    if seller_prevout.value.to_sat() != listing.postage_sats {
        return Err(ZincError::OfferError(format!(
            "passthrough input postage must equal {} sats; found {} sats",
            listing.postage_sats,
            seller_prevout.value.to_sat()
        )));
    }

    let seller_output = psbt
        .unsigned_tx
        .output
        .get(seller_input_index)
        .ok_or_else(|| {
            ZincError::OfferError(
                "sale psbt missing seller payout output required by SIGHASH_SINGLE".to_string(),
            )
        })?;
    let expected_seller_payout = listing
        .ask_sats
        .checked_add(listing.postage_sats)
        .ok_or_else(|| ZincError::OfferError("ask_sats + postage overflows u64".to_string()))?;
    if seller_output.value.to_sat() != expected_seller_payout {
        return Err(ZincError::OfferError(format!(
            "seller payout output must equal ask+postage {} sats; found {} sats",
            expected_seller_payout,
            seller_output.value.to_sat()
        )));
    }

    let expected_script = script_from_hex(&listing.seller_payout_script_pubkey_hex)?;
    if seller_output.script_pubkey != expected_script {
        return Err(ZincError::OfferError(
            "seller payout script does not match listing".to_string(),
        ));
    }

    Ok(())
}

fn find_passthrough_tap_leaf(
    psbt: &Psbt,
    input_index: usize,
    seller_pubkey: XOnlyPublicKey,
    coordinator_pubkey: XOnlyPublicKey,
) -> Result<(TapLeafHash, ScriptBuf), ZincError> {
    let (_control_block, leaf_hash, script) =
        find_passthrough_tap_leaf_entry(psbt, input_index, seller_pubkey, coordinator_pubkey)?;
    Ok((leaf_hash, script))
}

fn find_passthrough_tap_leaf_entry(
    psbt: &Psbt,
    input_index: usize,
    seller_pubkey: XOnlyPublicKey,
    coordinator_pubkey: XOnlyPublicKey,
) -> Result<(ControlBlock, TapLeafHash, ScriptBuf), ZincError> {
    let expected_script = passthrough_tapscript(seller_pubkey, coordinator_pubkey);
    let input = psbt
        .inputs
        .get(input_index)
        .ok_or_else(|| ZincError::OfferError("seller input metadata missing".to_string()))?;
    for (control_block, (script, leaf_version)) in &input.tap_scripts {
        if *leaf_version == LeafVersion::TapScript && *script == expected_script {
            return Ok((
                control_block.clone(),
                TapLeafHash::from_script(script, *leaf_version),
                script.clone(),
            ));
        }
    }

    Err(ZincError::OfferError(
        "missing passthrough tap leaf metadata".to_string(),
    ))
}

fn ensure_seller_sale_signature(
    psbt: &Psbt,
    input_index: usize,
    seller_pubkey: XOnlyPublicKey,
    leaf_hash: TapLeafHash,
) -> Result<(), ZincError> {
    let input = psbt
        .inputs
        .get(input_index)
        .ok_or_else(|| ZincError::OfferError("seller input metadata missing".to_string()))?;
    let Some(signature) = input.tap_script_sigs.get(&(seller_pubkey, leaf_hash)) else {
        return Err(ZincError::OfferError(
            "missing seller sale signature".to_string(),
        ));
    };
    if signature.sighash_type != TapSighashType::SinglePlusAnyoneCanPay {
        return Err(ZincError::OfferError(format!(
            "seller sale signature must use SIGHASH_SINGLE|SIGHASH_ANYONECANPAY; found {}",
            signature.sighash_type
        )));
    }
    Ok(())
}

fn ensure_coordinator_default_signature(
    psbt: &Psbt,
    input_index: usize,
    coordinator_pubkey: XOnlyPublicKey,
    leaf_hash: TapLeafHash,
) -> Result<(), ZincError> {
    let input = psbt
        .inputs
        .get(input_index)
        .ok_or_else(|| ZincError::OfferError("seller input metadata missing".to_string()))?;
    let Some(signature) = input.tap_script_sigs.get(&(coordinator_pubkey, leaf_hash)) else {
        return Err(ZincError::OfferError(
            "missing coordinator signature".to_string(),
        ));
    };
    if signature.sighash_type != TapSighashType::Default {
        return Err(ZincError::OfferError(format!(
            "coordinator signature must use SIGHASH_DEFAULT; found {}",
            signature.sighash_type
        )));
    }
    Ok(())
}

fn input_prevout(psbt: &Psbt, index: usize) -> Result<&TxOut, ZincError> {
    let input = psbt
        .inputs
        .get(index)
        .ok_or_else(|| ZincError::OfferError("input metadata missing".to_string()))?;
    input
        .witness_utxo
        .as_ref()
        .or_else(|| {
            input.non_witness_utxo.as_ref().and_then(|prev_tx| {
                psbt.unsigned_tx
                    .input
                    .get(index)
                    .and_then(|txin| prev_tx.output.get(txin.previous_output.vout as usize))
            })
        })
        .ok_or_else(|| ZincError::OfferError(format!("input #{index} is missing prevout metadata")))
}

fn input_has_signature(input: &PsbtInput) -> bool {
    input.final_script_sig.is_some()
        || input.final_script_witness.is_some()
        || !input.partial_sigs.is_empty()
        || input.tap_key_sig.is_some()
        || !input.tap_script_sigs.is_empty()
}

fn psbt_fee_sats(psbt: &Psbt) -> Result<u64, ZincError> {
    let total_input_sats = (0..psbt.inputs.len()).try_fold(0u64, |total, index| {
        total
            .checked_add(input_prevout(psbt, index)?.value.to_sat())
            .ok_or_else(|| ZincError::OfferError("total input value overflows u64".to_string()))
    })?;
    let total_output_sats = psbt
        .unsigned_tx
        .output
        .iter()
        .try_fold(0u64, |total, output| {
            total.checked_add(output.value.to_sat()).ok_or_else(|| {
                ZincError::OfferError("total output value overflows u64".to_string())
            })
        })?;
    total_input_sats.checked_sub(total_output_sats).ok_or_else(|| {
        ZincError::OfferError(format!(
            "buyer funding is insufficient: inputs {total_input_sats} sats, outputs {total_output_sats} sats"
        ))
    })
}

fn script_from_hex(hex_script: &str) -> Result<ScriptBuf, ZincError> {
    let bytes = hex::decode(hex_script)
        .map_err(|e| ZincError::OfferError(format!("invalid scriptPubKey hex: {e}")))?;
    Ok(ScriptBuf::from_bytes(bytes))
}
