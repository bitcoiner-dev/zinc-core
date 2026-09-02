use crate::backend_error::{BackendDependencyV1, BackendFailureV1, BackendOperationV1};
use crate::ordinals::error::OrdError;
use crate::ordinals::types::{Inscription, RuneBalance, RuneInfo};
use bitcoin::OutPoint;
use futures_util::{stream, StreamExt, TryStreamExt};
use ordinals::{Epoch, Rarity, Sat};
use reqwest::Client;
use serde::{Deserialize, Deserializer};
use std::collections::{BTreeMap, HashMap, HashSet};

const OUTPUTS_BATCH: usize = 100;
const OUTPUTS_MAX_CONCURRENCY: usize = 4;

async fn send_ord_request(
    request: reqwest::RequestBuilder,
    operation: BackendOperationV1,
) -> Result<reqwest::Response, OrdError> {
    request.send().await.map_err(|error| {
        BackendFailureV1::from_reqwest(&error, BackendDependencyV1::Ord, operation).into()
    })
}

fn ensure_ord_success(
    response: &reqwest::Response,
    operation: BackendOperationV1,
) -> Result<(), OrdError> {
    if response.status().is_success() {
        return Ok(());
    }
    let retry_after = response
        .headers()
        .get(reqwest::header::RETRY_AFTER)
        .and_then(|value| value.to_str().ok());
    Err(BackendFailureV1::from_http_status(
        BackendDependencyV1::Ord,
        operation,
        response.status().as_u16(),
        retry_after,
    )
    .into())
}

async fn parse_ord_json<T: serde::de::DeserializeOwned>(
    response: reqwest::Response,
    operation: BackendOperationV1,
) -> Result<T, OrdError> {
    response
        .json::<T>()
        .await
        .map_err(|_| OrdError::invalid_response(operation))
}

async fn parse_ord_text(
    response: reqwest::Response,
    operation: BackendOperationV1,
) -> Result<String, OrdError> {
    response
        .text()
        .await
        .map_err(|_| OrdError::invalid_response(operation))
}

#[derive(Clone, Debug)]
/// Lightweight client for ord-compatible REST APIs.
pub struct OrdClient {
    base_url: String,
    http_client: Client,
}

#[derive(Deserialize)]
struct AddressResponse {
    #[serde(default)]
    inscriptions: Vec<String>,
    #[serde(default)]
    outputs: Vec<String>,
    #[serde(default, deserialize_with = "deserialize_json_value_or_default")]
    runes_balances: serde_json::Value,
}

#[derive(Clone, Debug)]
/// Address-level view of inscription ids and related output references.
pub struct AddressAssetSnapshot {
    /// Inscription IDs reported for the address.
    pub inscription_ids: Vec<String>,
    /// Outpoint strings potentially carrying protected assets.
    pub outputs: Vec<String>,
    /// Aggregated rune balances for the address, when provided by the ord endpoint.
    pub rune_balances: Vec<RuneBalance>,
}

#[derive(Deserialize)]
struct OutputResponse {
    #[serde(default)]
    indexed: Option<bool>,
    #[serde(default)]
    address: Option<String>,
    #[serde(default)]
    outpoint: Option<String>,
    #[serde(default)]
    transaction: Option<String>,
    #[serde(default)]
    value: Option<u64>,
    #[serde(default)]
    sat_ranges: Option<Vec<(u64, u64)>>,
    #[serde(default, deserialize_with = "deserialize_string_vec_or_default")]
    inscriptions: Vec<String>,
    #[serde(default, deserialize_with = "deserialize_json_value_or_default")]
    runes: serde_json::Value,
}

#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
/// Exact non-common sat position within one wallet output.
pub struct RareSatLocation {
    /// Absolute ordinal sat number.
    pub number: u64,
    /// Zero-based sat offset inside the output.
    pub offset: u64,
    /// Ordinal rarity (`uncommon` through `mythic`).
    pub rarity: String,
}

#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
/// Non-common sat summary for one wallet output.
pub struct RareSatSummary {
    /// Number of non-common sats in the output.
    pub count: u64,
    /// Highest Ordinal rarity present (`uncommon` through `mythic`).
    pub highest_rarity: String,
    /// Exact positions used by sat-aware builders and Ordinal Shield.
    pub sats: Vec<RareSatLocation>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
/// Full output details for ord-compatible `/output/<outpoint>` responses.
pub struct OutputDetails {
    /// Canonical outpoint string (`txid:vout`).
    pub outpoint: String,
    /// Encoded output address.
    pub address: String,
    /// Output value in satoshis.
    pub value: u64,
    /// Inscriptions currently attached to this output.
    pub inscriptions: Vec<String>,
    /// Runes payload as returned by ord.
    pub runes: serde_json::Value,
}

#[derive(Clone, Debug, PartialEq, Eq)]
/// Raw inscription content payload fetched from `/content/<id>`.
pub struct InscriptionContent {
    /// Best-effort content type from HTTP response headers.
    pub content_type: Option<String>,
    /// Raw content bytes.
    pub bytes: Vec<u8>,
}

/// All ordinal assets resolved for a set of wallet outpoints in one bulk pass.
#[derive(Debug, Default)]
pub struct ResolvedAssets {
    /// Inscriptions held by the wallet (with display metadata + satpoint offsets).
    pub inscriptions: Vec<Inscription>,
    /// Outpoints holding an inscription or rune — the shield's protected (unspendable) set.
    pub protected_outpoints: HashSet<OutPoint>,
    /// Non-common sat summaries keyed by their protected outpoint.
    pub rare_sat_outpoints: HashMap<OutPoint, RareSatSummary>,
    /// Aggregated rune balances.
    pub rune_balances: Vec<RuneBalance>,
    /// Per-outpoint rune holdings keyed by rune ID `"block:tx"` (base units).
    pub outpoint_runes: std::collections::HashMap<OutPoint, Vec<(String, u128)>>,
    /// Metadata for each distinct rune seen, keyed by rune ID.
    pub rune_infos: std::collections::HashMap<String, RuneInfo>,
}

#[derive(Deserialize)]
struct RuneInfoTermsResponse {
    #[serde(default, deserialize_with = "deserialize_json_value_or_default")]
    amount: serde_json::Value,
    #[serde(default, deserialize_with = "deserialize_json_value_or_default")]
    cap: serde_json::Value,
}

#[derive(Deserialize)]
struct RuneInfoEntryResponse {
    #[serde(default)]
    spaced_rune: Option<String>,
    #[serde(default)]
    divisibility: Option<u8>,
    #[serde(default)]
    symbol: Option<String>,
    #[serde(default)]
    terms: Option<RuneInfoTermsResponse>,
}

#[derive(Deserialize)]
struct RuneInfoResponse {
    #[serde(default)]
    id: Option<String>,
    #[serde(default)]
    entry: Option<RuneInfoEntryResponse>,
    #[serde(default)]
    mintable: Option<bool>,
    #[serde(default, deserialize_with = "deserialize_json_value_or_default")]
    parent: serde_json::Value,
}

/// Renders a JSON number-or-string amount as a decimal string, tolerating both
/// shapes ord has used across versions. Returns `None` for anything else.
fn json_amount_to_decimal_string(value: &serde_json::Value) -> Option<String> {
    match value {
        serde_json::Value::Number(number) => Some(number.to_string()),
        serde_json::Value::String(text) if !text.trim().is_empty() => Some(text.clone()),
        _ => None,
    }
}

fn json_parent_to_inscription_id(value: &serde_json::Value) -> Option<String> {
    match value {
        serde_json::Value::String(text) if !text.trim().is_empty() => Some(text.clone()),
        serde_json::Value::Object(map) => map
            .get("id")
            .and_then(serde_json::Value::as_str)
            .map(ToString::to_string),
        _ => None,
    }
}

#[derive(Deserialize)]
#[serde(untagged)]
enum OffersResponse {
    Wrapped { offers: Vec<String> },
    Bare(Vec<String>),
}

impl OutputResponse {
    fn has_protected_assets(&self) -> bool {
        !self.inscriptions.is_empty()
            || value_has_entries(&self.runes)
            || self
                .sat_ranges
                .as_deref()
                .and_then(classify_rare_sats)
                .is_some()
    }

    fn into_output_details(self, requested_outpoint: &str) -> Result<OutputDetails, OrdError> {
        let address = self
            .address
            .filter(|value| !value.trim().is_empty())
            .ok_or_else(|| OrdError::invalid_response(BackendOperationV1::Outputs))?;
        let value = self
            .value
            .ok_or_else(|| OrdError::invalid_response(BackendOperationV1::Outputs))?;
        let outpoint = self
            .outpoint
            .filter(|value| !value.trim().is_empty())
            .unwrap_or_else(|| requested_outpoint.to_string());

        Ok(OutputDetails {
            outpoint,
            address,
            value,
            inscriptions: self.inscriptions,
            runes: self.runes,
        })
    }
}

fn checked_ceil_div(value: u64, divisor: u64) -> Option<u64> {
    value
        .checked_add(divisor.checked_sub(1)?)?
        .checked_div(divisor)
}

fn first_multiple_at_or_after(value: u64, period: u64) -> Option<u64> {
    checked_ceil_div(value, period)?.checked_mul(period)
}

/// Classify non-common sats without iterating over every sat in an output.
/// A non-common sat is the first sat of a block, so each epoch can be reduced
/// to a closed interval of block heights and checked arithmetically.
fn classify_rare_sats(ranges: &[(u64, u64)]) -> Option<RareSatSummary> {
    let mut count = 0u64;
    let mut highest = Rarity::Common;
    let mut sats = Vec::new();
    let mut range_base_offset = 0u64;

    for &(range_start, range_end) in ranges {
        for epoch_number in 0..33u32 {
            let epoch = Epoch(epoch_number);
            let epoch_start = epoch.starting_sat().n();
            let epoch_end = Epoch(epoch_number + 1).starting_sat().n();
            let start = range_start.max(epoch_start);
            let end = range_end.min(epoch_end);
            if start >= end {
                continue;
            }

            let subsidy = epoch.subsidy();
            if subsidy == 0 {
                continue;
            }
            let first_index = checked_ceil_div(start - epoch_start, subsidy)?;
            let last_index = (end - 1 - epoch_start) / subsidy;
            if first_index > last_index {
                continue;
            }
            count = count.checked_add(last_index - first_index + 1)?;

            let first_height = u64::from(epoch.starting_height().n()) + first_index;
            let last_height = u64::from(epoch.starting_height().n()) + last_index;
            let candidate_rarity = if first_height == 0 {
                Rarity::Mythic
            } else if first_multiple_at_or_after(first_height, 1_260_000)? <= last_height {
                Rarity::Legendary
            } else if first_multiple_at_or_after(first_height, 210_000)? <= last_height {
                Rarity::Epic
            } else if first_multiple_at_or_after(first_height, 2_016)? <= last_height {
                Rarity::Rare
            } else {
                Rarity::Uncommon
            };
            if candidate_rarity > highest {
                highest = candidate_rarity;
            }

            for index in first_index..=last_index {
                let number = epoch_start.checked_add(index.checked_mul(subsidy)?)?;
                let offset = range_base_offset.checked_add(number.checked_sub(range_start)?)?;
                let rarity = Sat(number).rarity();
                sats.push(RareSatLocation {
                    number,
                    offset,
                    rarity: rarity.to_string(),
                });
            }
        }
        range_base_offset = range_base_offset.checked_add(range_end.checked_sub(range_start)?)?;
    }

    (count > 0).then(|| RareSatSummary {
        count,
        highest_rarity: highest.to_string(),
        sats,
    })
}

pub(crate) fn validate_sat_ranges(
    outpoint: &str,
    ranges: Option<&[(u64, u64)]>,
    returned_value: Option<u64>,
    trusted_value: u64,
) -> Result<RareSatSummary, OrdError> {
    let value = returned_value.ok_or_else(|| {
        let _ = outpoint;
        OrdError::RareSatProtectionUnverified {
            reason: "missing-output-value",
        }
    })?;
    if value != trusted_value {
        return Err(OrdError::RareSatProtectionUnverified {
            reason: "wallet-value-mismatch",
        });
    }
    let ranges = ranges.ok_or(OrdError::RareSatProtectionUnverified {
        reason: "sat-ranges-missing",
    })?;
    if trusted_value > 0 && ranges.is_empty() {
        return Err(OrdError::RareSatProtectionUnverified {
            reason: "sat-ranges-empty",
        });
    }

    let mut sorted = ranges.to_vec();
    sorted.sort_unstable_by_key(|range| range.0);
    let mut total = 0u64;
    let mut previous_end = None;
    for &(start, end) in &sorted {
        if start >= end || end > Sat::SUPPLY {
            return Err(OrdError::RareSatProtectionUnverified {
                reason: "sat-range-invalid",
            });
        }
        if previous_end.is_some_and(|previous| start < previous) {
            return Err(OrdError::RareSatProtectionUnverified {
                reason: "sat-ranges-overlap",
            });
        }
        total = total
            .checked_add(end - start)
            .ok_or(OrdError::RareSatProtectionUnverified {
                reason: "sat-range-size-overflow",
            })?;
        previous_end = Some(end);
    }
    if total != trusted_value {
        return Err(OrdError::RareSatProtectionUnverified {
            reason: "sat-range-coverage-mismatch",
        });
    }

    // `sat_ranges` are ordered by their position in the output's sat stream.
    // The sorted copy above is only for overlap validation; classification
    // must retain the source order so every reported offset stays exact.
    Ok(classify_rare_sats(ranges).unwrap_or(RareSatSummary {
        count: 0,
        highest_rarity: Rarity::Common.to_string(),
        sats: Vec::new(),
    }))
}

fn deserialize_string_vec_or_default<'de, D>(deserializer: D) -> Result<Vec<String>, D::Error>
where
    D: Deserializer<'de>,
{
    Ok(Option::<Vec<String>>::deserialize(deserializer)?.unwrap_or_default())
}

fn deserialize_json_value_or_default<'de, D>(deserializer: D) -> Result<serde_json::Value, D::Error>
where
    D: Deserializer<'de>,
{
    Ok(Option::<serde_json::Value>::deserialize(deserializer)?.unwrap_or(serde_json::Value::Null))
}

fn value_has_entries(value: &serde_json::Value) -> bool {
    match value {
        serde_json::Value::Null => false,
        serde_json::Value::Array(items) => !items.is_empty(),
        serde_json::Value::Object(map) => !map.is_empty(),
        serde_json::Value::String(s) => !s.is_empty(),
        serde_json::Value::Bool(flag) => *flag,
        serde_json::Value::Number(_) => true,
    }
}

fn parse_offers_payload(body: &str) -> Result<Vec<String>, OrdError> {
    let parsed: OffersResponse = serde_json::from_str(body)
        .map_err(|_| OrdError::invalid_response(BackendOperationV1::Offers))?;

    Ok(match parsed {
        OffersResponse::Wrapped { offers } | OffersResponse::Bare(offers) => offers,
    })
}

fn canonical_decimal_digits(value: &str) -> Option<String> {
    if value.is_empty() || !value.bytes().all(|byte| byte.is_ascii_digit()) {
        return None;
    }
    let trimmed = value.trim_start_matches('0');
    if trimmed.is_empty() {
        Some("0".to_string())
    } else {
        Some(trimmed.to_string())
    }
}

fn amount_value_to_string(value: &serde_json::Value) -> Option<String> {
    match value {
        serde_json::Value::String(raw) => canonical_decimal_digits(raw.trim()),
        serde_json::Value::Number(number) => canonical_decimal_digits(&number.to_string()),
        _ => None,
    }
}

fn add_decimal_strings(lhs: &str, rhs: &str) -> Option<String> {
    let lhs_digits = canonical_decimal_digits(lhs)?;
    let rhs_digits = canonical_decimal_digits(rhs)?;

    let lhs_bytes = lhs_digits.as_bytes();
    let rhs_bytes = rhs_digits.as_bytes();
    let mut i = lhs_bytes.len();
    let mut j = rhs_bytes.len();
    let mut carry: u8 = 0;
    let mut output: Vec<u8> = Vec::with_capacity(lhs_bytes.len().max(rhs_bytes.len()) + 1);

    while i > 0 || j > 0 || carry > 0 {
        let left = if i > 0 {
            i -= 1;
            lhs_bytes[i] - b'0'
        } else {
            0
        };
        let right = if j > 0 {
            j -= 1;
            rhs_bytes[j] - b'0'
        } else {
            0
        };
        let sum = left + right + carry;
        output.push((sum % 10) + b'0');
        carry = sum / 10;
    }

    output.reverse();
    String::from_utf8(output).ok()
}

fn merge_rune_balances(entries: impl IntoIterator<Item = RuneBalance>) -> Vec<RuneBalance> {
    let mut merged: BTreeMap<String, RuneBalance> = BTreeMap::new();

    for entry in entries {
        if entry.rune.trim().is_empty() {
            continue;
        }
        let Some(normalized_amount) = canonical_decimal_digits(&entry.amount) else {
            continue;
        };

        if let Some(existing) = merged.get_mut(&entry.rune) {
            if let Some(sum) = add_decimal_strings(&existing.amount, &normalized_amount) {
                existing.amount = sum;
            }
            if existing.divisibility.is_none() {
                existing.divisibility = entry.divisibility;
            }
            if existing.symbol.is_none() {
                existing.symbol = entry.symbol;
            }
            if existing.id.is_none() {
                existing.id = entry.id;
            }
            continue;
        }

        merged.insert(
            entry.rune.clone(),
            RuneBalance {
                rune: entry.rune,
                amount: normalized_amount,
                divisibility: entry.divisibility,
                symbol: entry.symbol,
                id: entry.id,
            },
        );
    }

    merged.into_values().collect()
}

fn parse_runes_balances_value(value: &serde_json::Value) -> Vec<RuneBalance> {
    match value {
        serde_json::Value::Null
        | serde_json::Value::Bool(_)
        | serde_json::Value::Number(_)
        | serde_json::Value::String(_) => Vec::new(),
        serde_json::Value::Array(items) => {
            let parsed =
                items
                    .iter()
                    .filter_map(|item| match item {
                        serde_json::Value::Array(tuple) if tuple.len() >= 2 => {
                            let rune = tuple.first().and_then(serde_json::Value::as_str)?.trim();
                            if rune.is_empty() {
                                return None;
                            }
                            let amount = amount_value_to_string(tuple.get(1)?)?;
                            let symbol = tuple.get(2).and_then(serde_json::Value::as_str).and_then(
                                |value| {
                                    let trimmed = value.trim();
                                    if trimmed.is_empty() {
                                        None
                                    } else {
                                        Some(trimmed.to_string())
                                    }
                                },
                            );
                            Some(RuneBalance {
                                rune: rune.to_string(),
                                amount,
                                divisibility: None,
                                symbol,
                                id: None,
                            })
                        }
                        _ => None,
                    })
                    .collect::<Vec<_>>();
            merge_rune_balances(parsed)
        }
        serde_json::Value::Object(map) => {
            let parsed = map
                .iter()
                .filter_map(|(rune, meta)| {
                    let rune_name = rune.trim();
                    if rune_name.is_empty() {
                        return None;
                    }

                    match meta {
                        serde_json::Value::Object(obj) => {
                            let amount = obj.get("amount").and_then(amount_value_to_string)?;
                            let divisibility = obj
                                .get("divisibility")
                                .and_then(serde_json::Value::as_u64)
                                .and_then(|value| u8::try_from(value).ok());
                            let symbol = obj
                                .get("symbol")
                                .and_then(serde_json::Value::as_str)
                                .and_then(|value| {
                                    let trimmed = value.trim();
                                    if trimmed.is_empty() {
                                        None
                                    } else {
                                        Some(trimmed.to_string())
                                    }
                                });
                            Some(RuneBalance {
                                rune: rune_name.to_string(),
                                amount,
                                divisibility,
                                symbol,
                                id: None,
                            })
                        }
                        other => {
                            let amount = amount_value_to_string(other)?;
                            Some(RuneBalance {
                                rune: rune_name.to_string(),
                                amount,
                                divisibility: None,
                                symbol: None,
                                id: None,
                            })
                        }
                    }
                })
                .collect::<Vec<_>>();
            merge_rune_balances(parsed)
        }
    }
}

impl OrdClient {
    /// Create a new client with the given base URL.
    pub fn new(base_url: String) -> Self {
        Self {
            base_url,
            // reqwest::Client::new() works on both native and WASM
            http_client: Client::new(),
        }
    }

    /// Fetch inscription ids and output references for an address.
    pub async fn get_address_asset_snapshot(
        &self,
        address: &str,
    ) -> Result<AddressAssetSnapshot, OrdError> {
        let url = format!("{}/address/{}", self.base_url, address);

        let response = send_ord_request(
            self.http_client
                .get(&url)
                .header("Accept", "application/json"),
            BackendOperationV1::AddressAssets,
        )
        .await?;

        if !response.status().is_success() {
            // 404 is fine, just empty
            if response.status() == reqwest::StatusCode::NOT_FOUND {
                return Ok(AddressAssetSnapshot {
                    inscription_ids: Vec::new(),
                    outputs: Vec::new(),
                    rune_balances: Vec::new(),
                });
            }
            ensure_ord_success(&response, BackendOperationV1::AddressAssets)?;
        }

        let data: AddressResponse =
            parse_ord_json(response, BackendOperationV1::AddressAssets).await?;

        Ok(AddressAssetSnapshot {
            inscription_ids: data.inscriptions,
            outputs: data.outputs,
            rune_balances: parse_runes_balances_value(&data.runes_balances),
        })
    }

    /// Fetch full inscription details for a single inscription id.
    pub async fn get_inscription_details(&self, id: &str) -> Result<Inscription, OrdError> {
        let details_url = format!("{}/inscription/{}", self.base_url, id);
        let details_resp = send_ord_request(
            self.http_client
                .get(&details_url)
                .header("Accept", "application/json"),
            BackendOperationV1::InscriptionDetails,
        )
        .await?;
        ensure_ord_success(&details_resp, BackendOperationV1::InscriptionDetails)?;
        parse_ord_json(details_resp, BackendOperationV1::InscriptionDetails).await
    }

    /// Fetch raw inscription content bytes for one inscription id.
    pub async fn get_inscription_content(&self, id: &str) -> Result<InscriptionContent, OrdError> {
        let url = format!("{}/content/{}", self.base_url, id);
        let response = send_ord_request(
            self.http_client.get(&url),
            BackendOperationV1::InscriptionContent,
        )
        .await?;
        ensure_ord_success(&response, BackendOperationV1::InscriptionContent)?;

        let content_type = response
            .headers()
            .get(reqwest::header::CONTENT_TYPE)
            .and_then(|value| value.to_str().ok())
            .map(ToString::to_string);

        let bytes = response
            .bytes()
            .await
            .map_err(|_| OrdError::invalid_response(BackendOperationV1::InscriptionContent))?;

        Ok(InscriptionContent {
            content_type,
            bytes: bytes.to_vec(),
        })
    }

    /// Fetch and resolve all inscriptions currently attached to `address`.
    pub async fn get_inscriptions(&self, address: &str) -> Result<Vec<Inscription>, OrdError> {
        let snapshot = self.get_address_asset_snapshot(address).await?;

        let mut inscriptions = Vec::new();

        for id in snapshot.inscription_ids {
            inscriptions.push(self.get_inscription_details(&id).await?);
        }

        Ok(inscriptions)
    }

    /// Resolve rune balances for a single address.
    ///
    /// Prefers aggregated balances from `/address/<addr>` and falls back to
    /// deriving balances from each listed output when needed.
    pub async fn get_rune_balances(&self, address: &str) -> Result<Vec<RuneBalance>, OrdError> {
        let snapshot = self.get_address_asset_snapshot(address).await?;
        if !snapshot.rune_balances.is_empty() {
            return Ok(snapshot.rune_balances);
        }

        let mut collected = Vec::new();
        for outpoint_str in &snapshot.outputs {
            let output = self.get_output_response(outpoint_str).await?;
            collected.extend(parse_runes_balances_value(&output.runes));
        }

        Ok(merge_rune_balances(collected))
    }

    /// Resolve and aggregate rune balances across multiple addresses.
    pub async fn get_rune_balances_for_addresses(
        &self,
        addresses: &[String],
    ) -> Result<Vec<RuneBalance>, OrdError> {
        // Fetch per-address rune balances concurrently in bounded batches (was one address at a time,
        // which serialized in front of the inscription pass and delayed artifacts from showing).
        const RUNE_FETCH_BATCH: usize = 8;
        let mut collected = Vec::new();
        for batch in addresses.chunks(RUNE_FETCH_BATCH) {
            let futures = batch
                .iter()
                .map(|address| self.get_rune_balances(address.as_str()));
            for result in futures_util::future::join_all(futures).await {
                collected.extend(result?);
            }
        }
        Ok(merge_rune_balances(collected))
    }

    /// Fetch rune metadata from ord-compatible `/rune/<id-or-name>`.
    ///
    /// Accepts either the canonical `"block:tx"` ID or the (spaced or
    /// unspaced) rune name. Fails when the response carries no rune ID, since
    /// ID-less metadata cannot be joined to runestone edicts.
    pub async fn get_rune_info(&self, id_or_name: &str) -> Result<RuneInfo, OrdError> {
        let url = format!("{}/rune/{}", self.base_url, id_or_name);
        let response = send_ord_request(
            self.http_client
                .get(&url)
                .header("Accept", "application/json"),
            BackendOperationV1::RuneInfo,
        )
        .await?;
        ensure_ord_success(&response, BackendOperationV1::RuneInfo)?;
        let parsed: RuneInfoResponse =
            parse_ord_json(response, BackendOperationV1::RuneInfo).await?;

        let id = parsed
            .id
            .filter(|value| !value.trim().is_empty())
            .ok_or_else(|| OrdError::invalid_response(BackendOperationV1::RuneInfo))?;
        let entry = parsed.entry;
        let spaced_rune = entry
            .as_ref()
            .and_then(|e| e.spaced_rune.clone())
            .filter(|value| !value.trim().is_empty())
            .unwrap_or_else(|| id_or_name.to_string());
        let terms = entry.as_ref().and_then(|e| e.terms.as_ref());

        Ok(RuneInfo {
            id,
            spaced_rune,
            divisibility: entry.as_ref().and_then(|e| e.divisibility).unwrap_or(0),
            symbol: entry.as_ref().and_then(|e| e.symbol.clone()),
            parent: json_parent_to_inscription_id(&parsed.parent),
            terms_amount: terms.and_then(|t| json_amount_to_decimal_string(&t.amount)),
            terms_cap: terms.and_then(|t| json_amount_to_decimal_string(&t.cap)),
            mintable: parsed.mintable.unwrap_or(false),
        })
    }

    /// Bulk-fetch output metadata for many outpoints in ONE request via ord's `POST /outputs`.
    /// Each returned entry carries its own `outpoint`, so callers can match results to requests.
    /// Internal helper for `resolve_assets_for_outpoints` (returns the crate-private response type).
    async fn get_outputs_bulk(
        &self,
        outpoints: &[String],
    ) -> Result<Vec<OutputResponse>, OrdError> {
        if outpoints.is_empty() {
            return Ok(Vec::new());
        }
        let url = format!("{}/outputs", self.base_url);
        let response = send_ord_request(
            self.http_client
                .post(&url)
                .header("Accept", "application/json")
                .json(outpoints),
            BackendOperationV1::Outputs,
        )
        .await?;
        ensure_ord_success(&response, BackendOperationV1::Outputs)?;
        parse_ord_json(response, BackendOperationV1::Outputs).await
    }

    /// Resolve all ordinal assets for the given wallet outpoints in as few requests as possible:
    /// one bulk `/outputs` pass (batched, concurrent) for inscription ids + runes + protected status,
    /// then a parallel per-inscription detail fetch for display metadata + satpoint offsets.
    ///
    /// Fails closed: if the bulk response does not cover every requested outpoint, returns an error so
    /// the ordinals state is never marked verified on partial data (a silently-missing output could
    /// hide a protected/inscribed UTXO from the send-safety set).
    #[allow(clippy::too_many_lines)] // One cohesive bulk-resolution pass.
    pub async fn resolve_assets_for_outpoints(
        &self,
        outpoints: &[String],
    ) -> Result<ResolvedAssets, OrdError> {
        self.resolve_assets_for_outpoints_inner(outpoints, None)
            .await
    }

    /// Resolve assets and rare-sat protection for wallet-owned UTXOs.
    ///
    /// Unlike the legacy outpoint-only API, this compares ord's output value
    /// and sat ranges with the wallet engine's trusted BDK value. Missing,
    /// duplicate, unexpected, or malformed results fail closed.
    pub async fn resolve_assets_for_utxos(
        &self,
        utxos: &[(String, u64)],
    ) -> Result<ResolvedAssets, OrdError> {
        let mut expected = HashMap::with_capacity(utxos.len());
        for (outpoint, value) in utxos {
            if expected.insert(outpoint.clone(), *value).is_some() {
                return Err(OrdError::RareSatProtectionUnverified {
                    reason: "duplicate-wallet-outpoint",
                });
            }
        }
        let outpoints: Vec<String> = utxos.iter().map(|(outpoint, _)| outpoint.clone()).collect();
        self.resolve_assets_for_outpoints_inner(&outpoints, Some(&expected))
            .await
    }

    #[allow(clippy::too_many_lines)] // One cohesive bulk-resolution pass.
    async fn resolve_assets_for_outpoints_inner(
        &self,
        outpoints: &[String],
        expected_values: Option<&HashMap<String, u64>>,
    ) -> Result<ResolvedAssets, OrdError> {
        if outpoints.is_empty() {
            return Ok(ResolvedAssets::default());
        }

        // 1. Bulk outputs, batched + concurrent.
        // Own each small request batch so the bounded stream's future remains
        // `Send` for native Tauri commands (borrowed slice futures are not
        // higher-ranked over every input lifetime).
        let batches: Vec<Vec<String>> = outpoints
            .chunks(OUTPUTS_BATCH)
            .map(<[String]>::to_vec)
            .collect();
        let chunks: Vec<Vec<OutputResponse>> = stream::iter(
            batches
                .into_iter()
                .map(|batch| async move { self.get_outputs_bulk(&batch).await }),
        )
        .buffer_unordered(OUTPUTS_MAX_CONCURRENCY)
        .try_collect()
        .await?;
        let entries: Vec<OutputResponse> = chunks.into_iter().flatten().collect();

        // Coverage check (fail closed): every requested outpoint must be present in the response.
        let returned: HashSet<&str> = entries
            .iter()
            .filter_map(|e| e.outpoint.as_deref())
            .collect();
        for requested in outpoints {
            if !returned.contains(requested.as_str()) {
                if expected_values.is_some() {
                    return Err(OrdError::RareSatProtectionUnverified {
                        reason: "bulk-result-outpoint-missing",
                    });
                }
                return Err(OrdError::invalid_response(BackendOperationV1::Outputs));
            }
        }
        if expected_values.is_some() {
            if entries.len() != outpoints.len() || returned.len() != outpoints.len() {
                return Err(OrdError::RareSatProtectionUnverified {
                    reason: "bulk-result-cardinality-mismatch",
                });
            }
            for entry in &entries {
                let outpoint =
                    entry
                        .outpoint
                        .as_deref()
                        .ok_or(OrdError::RareSatProtectionUnverified {
                            reason: "bulk-result-outpoint-missing",
                        })?;
                let expected_value = expected_values
                    .and_then(|values| values.get(outpoint))
                    .copied()
                    .ok_or(OrdError::RareSatProtectionUnverified {
                        reason: "bulk-result-outpoint-unexpected",
                    })?;
                if entry.indexed != Some(true) {
                    return Err(OrdError::RareSatProtectionUnverified {
                        reason: "output-not-indexed",
                    });
                }
                let parsed = outpoint.parse::<OutPoint>().map_err(|_| {
                    OrdError::RareSatProtectionUnverified {
                        reason: "output-outpoint-invalid",
                    }
                })?;
                if entry.transaction.as_deref() != Some(&parsed.txid.to_string()) {
                    return Err(OrdError::RareSatProtectionUnverified {
                        reason: "output-transaction-mismatch",
                    });
                }
                validate_sat_ranges(
                    outpoint,
                    entry.sat_ranges.as_deref(),
                    entry.value,
                    expected_value,
                )?;
            }
        }

        // 2. Derive protected set + inscription ids + rune balances from the bulk entries.
        let mut protected_outpoints = HashSet::new();
        let mut rare_sat_outpoints = HashMap::new();
        let mut inscription_ids: Vec<String> = Vec::new();
        let mut rune_balances: Vec<RuneBalance> = Vec::new();
        // Per-outpoint rune amounts, still keyed by NAME (ord's /outputs shape).
        let mut outpoint_rune_names: Vec<(OutPoint, Vec<(String, u128)>)> = Vec::new();
        for e in &entries {
            let outpoint = e
                .outpoint
                .as_deref()
                .and_then(|s| s.parse::<OutPoint>().ok());
            if e.has_protected_assets() {
                if let Some(op) = outpoint {
                    protected_outpoints.insert(op);
                }
            }
            if let (Some(values), Some(op), Some(outpoint_str)) =
                (expected_values, outpoint, e.outpoint.as_deref())
            {
                let expected_value = values.get(outpoint_str).copied().ok_or(
                    OrdError::RareSatProtectionUnverified {
                        reason: "trusted-wallet-value-missing",
                    },
                )?;
                let summary = validate_sat_ranges(
                    outpoint_str,
                    e.sat_ranges.as_deref(),
                    e.value,
                    expected_value,
                )?;
                if summary.count > 0 {
                    protected_outpoints.insert(op);
                    rare_sat_outpoints.insert(op, summary);
                }
            }
            inscription_ids.extend(e.inscriptions.iter().cloned());
            let entry_balances = parse_runes_balances_value(&e.runes);
            if let Some(op) = outpoint {
                let mut held: Vec<(String, u128)> = Vec::new();
                for balance in &entry_balances {
                    let Ok(amount) = balance.amount.parse::<u128>() else {
                        return Err(OrdError::invalid_response(BackendOperationV1::Outputs));
                    };
                    held.push((balance.rune.clone(), amount));
                }
                if !held.is_empty() {
                    outpoint_rune_names.push((op, held));
                }
            }
            rune_balances.extend(entry_balances);
        }

        // 2b. Resolve metadata (incl. the ID the runestone protocol uses) for
        // every distinct rune name seen. Fails closed: a rune UTXO whose ID
        // cannot be resolved would otherwise simulate as rune-free, which is
        // the burn-masking failure mode.
        let mut distinct_names: Vec<String> = Vec::new();
        for (_, held) in &outpoint_rune_names {
            for (name, _) in held {
                if !distinct_names.contains(name) {
                    distinct_names.push(name.clone());
                }
            }
        }
        const RUNE_INFO_BATCH: usize = 8;
        let mut rune_infos: std::collections::HashMap<String, RuneInfo> =
            std::collections::HashMap::new();
        let mut id_by_name: std::collections::HashMap<String, String> =
            std::collections::HashMap::new();
        for chunk in distinct_names.chunks(RUNE_INFO_BATCH) {
            let info_futures = chunk.iter().map(|name| self.get_rune_info(name.as_str()));
            for result in futures_util::future::join_all(info_futures).await {
                let info = result?;
                id_by_name.insert(info.spaced_rune.clone(), info.id.clone());
                rune_infos.insert(info.id.clone(), info);
            }
        }
        // Some ord deployments key /outputs runes by unspaced name; bridge by
        // comparing names with spacers stripped when the direct match misses.
        let mut outpoint_runes: std::collections::HashMap<OutPoint, Vec<(String, u128)>> =
            std::collections::HashMap::new();
        for (op, held) in outpoint_rune_names {
            let mut resolved: Vec<(String, u128)> = Vec::new();
            for (name, amount) in held {
                let id = id_by_name.get(&name).cloned().or_else(|| {
                    let normalized: String = name.chars().filter(|c| *c != '•').collect();
                    id_by_name
                        .iter()
                        .find(|(candidate, _)| {
                            candidate.chars().filter(|c| *c != '•').collect::<String>()
                                == normalized
                        })
                        .map(|(_, id)| id.clone())
                });
                let Some(id) = id else {
                    return Err(OrdError::invalid_response(BackendOperationV1::RuneInfo));
                };
                resolved.push((id, amount));
            }
            outpoint_runes.insert(op, resolved);
        }

        // 3. Parallel per-inscription details (number/content_type/satpoint offset for display + shield).
        const INS_BATCH: usize = 8;
        let mut inscriptions = Vec::new();
        for chunk in inscription_ids.chunks(INS_BATCH) {
            let detail_futures = chunk
                .iter()
                .map(|id| self.get_inscription_details(id.as_str()));
            for result in futures_util::future::join_all(detail_futures).await {
                inscriptions.push(result?);
            }
        }

        // Back-fill canonical IDs onto the aggregated balances.
        let mut merged_balances = merge_rune_balances(rune_balances);
        for balance in &mut merged_balances {
            if balance.id.is_none() {
                balance.id = id_by_name.get(&balance.rune).cloned();
            }
        }

        Ok(ResolvedAssets {
            inscriptions,
            protected_outpoints,
            rare_sat_outpoints,
            rune_balances: merged_balances,
            outpoint_runes,
            rune_infos,
        })
    }

    /// Resolve protected outpoints for assets referenced by an address.
    pub async fn get_protected_outpoints(
        &self,
        address: &str,
    ) -> Result<HashSet<OutPoint>, OrdError> {
        let snapshot = self.get_address_asset_snapshot(address).await?;
        self.get_protected_outpoints_from_outputs(&snapshot.outputs)
            .await
    }

    /// Resolve protected outpoints from explicit outpoint strings.
    pub async fn get_protected_outpoints_from_outputs(
        &self,
        outputs: &[String],
    ) -> Result<HashSet<OutPoint>, OrdError> {
        let mut protected = HashSet::new();

        for outpoint_str in outputs {
            let output = self.get_output_response(outpoint_str).await?;

            if !output.has_protected_assets() {
                continue;
            }

            let outpoint = outpoint_str
                .as_str()
                .parse::<OutPoint>()
                .map_err(|_| OrdError::invalid_response(BackendOperationV1::Outputs))?;
            protected.insert(outpoint);
        }

        Ok(protected)
    }

    /// Fetch full output metadata for one outpoint from `/output/<outpoint>`.
    pub async fn get_output_details(&self, outpoint: &OutPoint) -> Result<OutputDetails, OrdError> {
        let requested_outpoint = outpoint.to_string();
        let response = self.get_output_response(&requested_outpoint).await?;
        response.into_output_details(&requested_outpoint)
    }

    /// Query ord server indexing height via `/blockheight`.
    pub async fn get_indexing_height(&self) -> Result<u32, OrdError> {
        let url = format!("{}/blockheight", self.base_url);
        let response =
            send_ord_request(self.http_client.get(&url), BackendOperationV1::BlockHeight).await?;
        ensure_ord_success(&response, BackendOperationV1::BlockHeight)?;
        let text = parse_ord_text(response, BackendOperationV1::BlockHeight).await?;
        text.trim()
            .parse::<u32>()
            .map_err(|_| OrdError::invalid_response(BackendOperationV1::BlockHeight))
    }

    /// Submit an offer PSBT to an ord-compatible `/offer` endpoint.
    pub async fn submit_offer_psbt(&self, psbt_base64: &str) -> Result<(), OrdError> {
        if psbt_base64.trim().is_empty() {
            return Err(OrdError::InvalidRequest);
        }

        let url = format!("{}/offer", self.base_url);
        let response = send_ord_request(
            self.http_client.post(&url).body(psbt_base64.to_string()),
            BackendOperationV1::Offers,
        )
        .await?;
        ensure_ord_success(&response, BackendOperationV1::Offers)?;

        Ok(())
    }

    /// Fetch submitted offer PSBTs from an ord-compatible `/offers` endpoint.
    pub async fn get_offer_psbts(&self) -> Result<Vec<String>, OrdError> {
        let url = format!("{}/offers", self.base_url);
        let response = send_ord_request(
            self.http_client
                .get(&url)
                .header("Accept", "application/json"),
            BackendOperationV1::Offers,
        )
        .await?;
        ensure_ord_success(&response, BackendOperationV1::Offers)?;
        let text = parse_ord_text(response, BackendOperationV1::Offers).await?;

        parse_offers_payload(&text)
    }

    async fn get_output_response(&self, outpoint: &str) -> Result<OutputResponse, OrdError> {
        let details_url = format!("{}/output/{}", self.base_url, outpoint);
        let details_resp = send_ord_request(
            self.http_client
                .get(&details_url)
                .header("Accept", "application/json"),
            BackendOperationV1::Outputs,
        )
        .await?;
        ensure_ord_success(&details_resp, BackendOperationV1::Outputs)?;
        parse_ord_json(details_resp, BackendOperationV1::Outputs).await
    }
}

// These are native-only tests (mockito has no wasm32 target); exclude them from the wasm
// test build so `wasm-pack test --node` can compile the crate.
#[cfg(all(test, not(target_arch = "wasm32")))]
mod tests {
    use super::{
        classify_rare_sats, parse_offers_payload, parse_runes_balances_value, validate_sat_ranges,
        OrdClient, OrdError, OutputResponse, OUTPUTS_MAX_CONCURRENCY,
    };
    use crate::backend_error::{BackendFailureCategoryV1, BackendOperationV1};
    use futures_util::{StreamExt, TryStreamExt};

    async fn try_collect_bounded<I, F, Fut, T, E>(
        items: I,
        max_concurrency: usize,
        fetch: F,
    ) -> Result<Vec<T>, E>
    where
        I: IntoIterator,
        F: FnMut(I::Item) -> Fut,
        Fut: std::future::Future<Output = Result<T, E>>,
    {
        futures_util::stream::iter(items)
            .map(fetch)
            .buffer_unordered(max_concurrency.max(1))
            .try_collect()
            .await
    }

    #[tokio::test]
    async fn outputs_scheduler_never_exceeds_its_request_bound() {
        let (started_tx, mut started_rx) = tokio::sync::mpsc::unbounded_channel();
        let collector = tokio::spawn(async move {
            try_collect_bounded(0_u8..10, OUTPUTS_MAX_CONCURRENCY, move |item| {
                let started_tx = started_tx.clone();
                async move {
                    let (release_tx, release_rx) = tokio::sync::oneshot::channel();
                    started_tx.send(release_tx).expect("observer remains alive");
                    release_rx.await.expect("request released");
                    Ok::<u8, ()>(item)
                }
            })
            .await
        });

        let mut active = Vec::new();
        for _ in 0..OUTPUTS_MAX_CONCURRENCY {
            active.push(started_rx.recv().await.expect("initial request starts"));
        }
        assert!(matches!(
            started_rx.try_recv(),
            Err(tokio::sync::mpsc::error::TryRecvError::Empty)
        ));

        for _ in OUTPUTS_MAX_CONCURRENCY..10 {
            active
                .pop()
                .expect("active request")
                .send(())
                .expect("release succeeds");
            active.push(started_rx.recv().await.expect("one replacement starts"));
            assert!(active.len() <= OUTPUTS_MAX_CONCURRENCY);
        }
        for release in active {
            release.send(()).expect("release succeeds");
        }

        let mut values = collector
            .await
            .expect("collector task joins")
            .expect("requests succeed");
        values.sort_unstable();
        assert_eq!(values, (0_u8..10).collect::<Vec<_>>());
    }

    #[tokio::test]
    async fn address_404_is_characterized_as_an_empty_asset_snapshot() {
        let mut server = mockito::Server::new_async().await;
        let mock = server
            .mock("GET", "/address/bc1ptest")
            .with_status(404)
            .expect(1)
            .create_async()
            .await;

        let snapshot = OrdClient::new(server.url())
            .get_address_asset_snapshot("bc1ptest")
            .await
            .expect("address 404 is currently treated as empty");

        assert!(snapshot.inscription_ids.is_empty());
        assert!(snapshot.outputs.is_empty());
        assert!(snapshot.rune_balances.is_empty());
        mock.assert_async().await;
    }

    #[tokio::test]
    async fn ord_rate_limit_preserves_status_and_bounded_retry_after() {
        let mut server = mockito::Server::new_async().await;
        let mock = server
            .mock("GET", "/blockheight")
            .with_status(429)
            .with_header("retry-after", "90")
            .expect(1)
            .create_async()
            .await;

        let error = OrdClient::new(server.url())
            .get_indexing_height()
            .await
            .expect_err("429 must fail");

        let OrdError::Backend(failure) = error else {
            panic!("expected typed backend failure");
        };
        assert_eq!(failure.category, BackendFailureCategoryV1::RateLimited);
        assert_eq!(failure.operation, BackendOperationV1::BlockHeight);
        assert_eq!(failure.upstream_status, Some(429));
        assert_eq!(failure.retry_after_ms, Some(90_000));
        mock.assert_async().await;
    }

    #[tokio::test]
    async fn ord_service_unavailable_is_not_retried_by_the_client() {
        let mut server = mockito::Server::new_async().await;
        let mock = server
            .mock("GET", "/blockheight")
            .with_status(503)
            .expect(1)
            .create_async()
            .await;

        let error = OrdClient::new(server.url())
            .get_indexing_height()
            .await
            .expect_err("503 must fail");

        let OrdError::Backend(failure) = error else {
            panic!("expected typed backend failure");
        };
        assert_eq!(failure.category, BackendFailureCategoryV1::Unavailable);
        assert_eq!(failure.upstream_status, Some(503));
        mock.assert_async().await;
    }

    #[tokio::test]
    async fn malformed_blockheight_is_typed_invalid_response() {
        let mut server = mockito::Server::new_async().await;
        let mock = server
            .mock("GET", "/blockheight")
            .with_status(200)
            .with_body("not-a-height")
            .expect(1)
            .create_async()
            .await;

        let error = OrdClient::new(server.url())
            .get_indexing_height()
            .await
            .expect_err("invalid height must fail");

        let OrdError::Backend(failure) = error else {
            panic!("expected typed backend failure");
        };
        assert_eq!(failure.category, BackendFailureCategoryV1::InvalidResponse);
        mock.assert_async().await;
    }

    #[tokio::test]
    async fn malformed_address_json_is_typed_invalid_response() {
        let mut server = mockito::Server::new_async().await;
        let mock = server
            .mock("GET", "/address/bc1ptest")
            .with_status(200)
            .with_body("not-json")
            .expect(1)
            .create_async()
            .await;

        let error = OrdClient::new(server.url())
            .get_address_asset_snapshot("bc1ptest")
            .await
            .expect_err("malformed JSON must fail");

        let OrdError::Backend(failure) = error else {
            panic!("expected typed backend failure");
        };
        assert_eq!(failure.category, BackendFailureCategoryV1::InvalidResponse);
        mock.assert_async().await;
    }

    #[tokio::test]
    async fn incomplete_bulk_outputs_fail_closed() {
        let outpoint = "6fb976ab49dcec017f1e201e84395983204ae1a7c2abf7ced0a85d692e442799:0";
        let mut server = mockito::Server::new_async().await;
        let mock = server
            .mock("POST", "/outputs")
            .with_status(200)
            .with_body("[]")
            .expect(1)
            .create_async()
            .await;

        let error = OrdClient::new(server.url())
            .resolve_assets_for_outpoints(&[outpoint.to_string()])
            .await
            .expect_err("missing requested output must fail closed");

        let OrdError::Backend(failure) = error else {
            panic!("expected typed backend failure");
        };
        assert_eq!(failure.category, BackendFailureCategoryV1::InvalidResponse);
        mock.assert_async().await;
    }

    #[tokio::test]
    async fn ord_transport_failure_is_typed_offline() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("ephemeral listener");
        let address = listener.local_addr().expect("listener address");
        drop(listener);
        let base_url = format!("http://{address}");

        let error = OrdClient::new(base_url)
            .get_indexing_height()
            .await
            .expect_err("closed server must fail");

        let OrdError::Backend(failure) = error else {
            panic!("expected typed backend failure");
        };
        assert_eq!(failure.category, BackendFailureCategoryV1::Offline);
    }

    #[test]
    fn classifies_non_common_sats_without_scanning_the_range() {
        let uncommon = classify_rare_sats(&[(5_000_000_000, 10_000_000_000)])
            .expect("block-one first sat is uncommon");
        assert_eq!(uncommon.count, 1);
        assert_eq!(uncommon.highest_rarity, "uncommon");

        let mixed = classify_rare_sats(&[(0, 10_000_000_001)])
            .expect("genesis and later block boundaries are protected");
        assert_eq!(mixed.count, 3);
        assert_eq!(mixed.highest_rarity, "mythic");

        assert!(classify_rare_sats(&[(1, 5_000_000_000)]).is_none());
    }

    #[test]
    fn strict_sat_range_validation_matches_the_wallet_value() {
        let summary = validate_sat_ranges(
            "0e3e2357e806b6cdb1f70b54c3a3a17b6714ee1f0e68bebb44a74b1efd512098:0",
            Some(&[(5_000_000_000, 10_000_000_000)]),
            Some(5_000_000_000),
            5_000_000_000,
        )
        .expect("complete ranges");
        assert_eq!(summary.highest_rarity, "uncommon");

        for (ranges, returned, trusted, expected_reason) in [
            (None, Some(330), 330, "sat-ranges-missing"),
            (Some(&[][..]), Some(330), 330, "sat-ranges-empty"),
            (Some(&[(10, 20)][..]), Some(9), 10, "wallet-value-mismatch"),
            (
                Some(&[(10, 19)][..]),
                Some(10),
                10,
                "sat-range-coverage-mismatch",
            ),
            (
                Some(&[(10, 20), (19, 21)][..]),
                Some(12),
                12,
                "sat-ranges-overlap",
            ),
        ] {
            let error = validate_sat_ranges("00:0", ranges, returned, trusted)
                .expect_err("unsafe response must fail closed");
            assert_eq!(error.to_string(), "ORD_RARE_SAT_PROTECTION_UNVERIFIED");
            match error {
                OrdError::RareSatProtectionUnverified { reason } => {
                    assert_eq!(reason, expected_reason);
                }
                other => panic!("unexpected error: {other:?}"),
            }
        }
    }

    #[test]
    fn output_response_accepts_null_asset_fields() {
        let output: OutputResponse =
            serde_json::from_str(r#"{"inscriptions":null,"runes":null}"#).unwrap();

        assert!(output.inscriptions.is_empty());
        assert!(!output.has_protected_assets());
    }

    #[test]
    fn output_response_treats_non_empty_runes_array_as_protected() {
        let output: OutputResponse =
            serde_json::from_str(r#"{"inscriptions":[],"runes":["abc"]}"#).unwrap();

        assert!(output.has_protected_assets());
    }

    #[test]
    fn offers_payload_supports_wrapped_object_shape() {
        let offers = parse_offers_payload(r#"{"offers":["bG...==","aG...=="]}"#)
            .expect("wrapped payload should parse");

        assert_eq!(offers, vec!["bG...==".to_string(), "aG...==".to_string()]);
    }

    #[test]
    fn offers_payload_supports_bare_array_shape() {
        let offers =
            parse_offers_payload(r#"["bG...==","aG...=="]"#).expect("bare payload should parse");

        assert_eq!(offers, vec!["bG...==".to_string(), "aG...==".to_string()]);
    }

    #[test]
    fn offers_payload_rejects_non_string_entries() {
        let err = parse_offers_payload(r#"{"offers":["ok", 1]}"#).expect_err("must fail");
        let OrdError::Backend(failure) = err else {
            panic!("expected typed backend failure");
        };
        assert_eq!(failure.category, BackendFailureCategoryV1::InvalidResponse);
        assert_eq!(failure.operation, BackendOperationV1::Offers);
    }

    #[test]
    fn output_response_maps_to_output_details() {
        let output: OutputResponse = serde_json::from_str(
            r#"{
                "address":"bcrt1pqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq8m3djv",
                "value":330,
                "outpoint":"6fb976ab49dcec017f1e201e84395983204ae1a7c2abf7ced0a85d692e442799:0",
                "inscriptions":["abc123i0"],
                "runes":{}
            }"#,
        )
        .expect("valid output");

        let details = output
            .into_output_details(
                "6fb976ab49dcec017f1e201e84395983204ae1a7c2abf7ced0a85d692e442799:0",
            )
            .expect("details");
        assert_eq!(
            details.outpoint,
            "6fb976ab49dcec017f1e201e84395983204ae1a7c2abf7ced0a85d692e442799:0"
        );
        assert_eq!(details.value, 330);
        assert_eq!(
            details.address,
            "bcrt1pqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq8m3djv"
        );
        assert_eq!(details.inscriptions, vec!["abc123i0".to_string()]);
    }

    #[test]
    fn output_response_requires_address_and_value_for_details() {
        let output: OutputResponse =
            serde_json::from_str(r#"{"inscriptions":[],"runes":[]}"#).expect("parse response");
        let err = output
            .into_output_details(
                "6fb976ab49dcec017f1e201e84395983204ae1a7c2abf7ced0a85d692e442799:0",
            )
            .expect_err("must fail");
        let OrdError::Backend(failure) = err else {
            panic!("expected typed backend failure");
        };
        assert_eq!(failure.category, BackendFailureCategoryV1::InvalidResponse);
        assert_eq!(failure.operation, BackendOperationV1::Outputs);
    }

    #[test]
    fn parse_runes_balances_supports_address_tuple_shape() {
        let value: serde_json::Value = serde_json::json!([
            ["NO•ORDINARY•KIND", "150000", "🚪"],
            ["NO•ORDINARY•KIND", "50000", "🚪"],
            ["SECOND", 5]
        ]);

        let balances = parse_runes_balances_value(&value);
        assert_eq!(balances.len(), 2);
        assert_eq!(balances[0].rune, "NO•ORDINARY•KIND");
        assert_eq!(balances[0].amount, "200000");
        assert_eq!(balances[0].symbol.as_deref(), Some("🚪"));
        assert_eq!(balances[1].rune, "SECOND");
        assert_eq!(balances[1].amount, "5");
    }

    #[test]
    fn parse_runes_balances_supports_output_object_shape() {
        let value: serde_json::Value = serde_json::json!({
            "NO•ORDINARY•KIND": {
                "amount": 150_000,
                "divisibility": 0,
                "symbol": "🚪"
            },
            "SECOND": {
                "amount": "42"
            }
        });

        let balances = parse_runes_balances_value(&value);
        assert_eq!(balances.len(), 2);
        assert_eq!(balances[0].rune, "NO•ORDINARY•KIND");
        assert_eq!(balances[0].amount, "150000");
        assert_eq!(balances[0].divisibility, Some(0));
        assert_eq!(balances[0].symbol.as_deref(), Some("🚪"));
        assert_eq!(balances[1].rune, "SECOND");
        assert_eq!(balances[1].amount, "42");
    }

    #[test]
    fn parse_runes_balances_handles_null_and_empty_shapes() {
        let null_balances = parse_runes_balances_value(&serde_json::Value::Null);
        assert!(null_balances.is_empty());

        let empty_array_balances = parse_runes_balances_value(&serde_json::json!([]));
        assert!(empty_array_balances.is_empty());

        let empty_object_balances = parse_runes_balances_value(&serde_json::json!({}));
        assert!(empty_object_balances.is_empty());
    }

    #[test]
    fn parse_runes_balances_ignores_malformed_entries() {
        let tuple_shape: serde_json::Value = serde_json::json!([
            ["NO•ORDINARY•KIND", "not-a-number", "🚪"],
            ["", "10"],
            ["GOOD•RUNE", "25"]
        ]);

        let tuple_balances = parse_runes_balances_value(&tuple_shape);
        assert_eq!(tuple_balances.len(), 1);
        assert_eq!(tuple_balances[0].rune, "GOOD•RUNE");
        assert_eq!(tuple_balances[0].amount, "25");

        let object_shape: serde_json::Value = serde_json::json!({
            "BAD•RUNE": { "amount": "oops" },
            "": { "amount": "10" },
            "GOOD•RUNE": { "amount": 7, "divisibility": 0 }
        });

        let object_balances = parse_runes_balances_value(&object_shape);
        assert_eq!(object_balances.len(), 1);
        assert_eq!(object_balances[0].rune, "GOOD•RUNE");
        assert_eq!(object_balances[0].amount, "7");
        assert_eq!(object_balances[0].divisibility, Some(0));
    }

    #[cfg(not(target_arch = "wasm32"))]
    #[tokio::test]
    async fn get_inscription_content_fetches_body_and_content_type() {
        let mut server = mockito::Server::new_async().await;
        let _mock = server
            .mock("GET", "/content/abc123i0")
            .with_status(200)
            .with_header("content-type", "image/png")
            .with_body(vec![0u8, 1, 2, 3])
            .create_async()
            .await;

        let client = OrdClient::new(server.url());
        let content = client
            .get_inscription_content("abc123i0")
            .await
            .expect("content");

        assert_eq!(content.content_type.as_deref(), Some("image/png"));
        assert_eq!(content.bytes, vec![0u8, 1, 2, 3]);
    }
}
