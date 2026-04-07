use crate::ordinals::error::OrdError;
use crate::ordinals::types::{Inscription, RuneBalance};
use bitcoin::OutPoint;
use reqwest::Client;
use serde::{Deserialize, Deserializer};
use std::collections::{BTreeMap, HashSet};

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
    address: Option<String>,
    #[serde(default)]
    outpoint: Option<String>,
    #[serde(default)]
    value: Option<u64>,
    #[serde(default, deserialize_with = "deserialize_string_vec_or_default")]
    inscriptions: Vec<String>,
    #[serde(default, deserialize_with = "deserialize_json_value_or_default")]
    runes: serde_json::Value,
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

#[derive(Deserialize)]
#[serde(untagged)]
enum OffersResponse {
    Wrapped { offers: Vec<String> },
    Bare(Vec<String>),
}

impl OutputResponse {
    fn has_protected_assets(&self) -> bool {
        !self.inscriptions.is_empty() || value_has_entries(&self.runes)
    }

    fn into_output_details(self, requested_outpoint: &str) -> Result<OutputDetails, OrdError> {
        let address = self
            .address
            .filter(|value| !value.trim().is_empty())
            .ok_or_else(|| {
                OrdError::RequestFailed(format!(
                    "Output {requested_outpoint} is missing required address field"
                ))
            })?;
        let value = self.value.ok_or_else(|| {
            OrdError::RequestFailed(format!(
                "Output {requested_outpoint} is missing required value field"
            ))
        })?;
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
        .map_err(|e| OrdError::RequestFailed(format!("Failed to parse offers JSON: {e}")))?;

    Ok(match parsed {
        OffersResponse::Wrapped { offers } => offers,
        OffersResponse::Bare(offers) => offers,
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
            continue;
        }

        merged.insert(
            entry.rune.clone(),
            RuneBalance {
                rune: entry.rune,
                amount: normalized_amount,
                divisibility: entry.divisibility,
                symbol: entry.symbol,
            },
        );
    }

    merged.into_values().collect()
}

fn parse_runes_balances_value(value: &serde_json::Value) -> Vec<RuneBalance> {
    match value {
        serde_json::Value::Null => Vec::new(),
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
                            })
                        }
                        other => {
                            let amount = amount_value_to_string(other)?;
                            Some(RuneBalance {
                                rune: rune_name.to_string(),
                                amount,
                                divisibility: None,
                                symbol: None,
                            })
                        }
                    }
                })
                .collect::<Vec<_>>();
            merge_rune_balances(parsed)
        }
        _ => Vec::new(),
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

        let response = self
            .http_client
            .get(&url)
            .header("Accept", "application/json")
            .send()
            .await
            .map_err(|e| OrdError::RequestFailed(e.to_string()))?;

        if !response.status().is_success() {
            // 404 is fine, just empty
            if response.status() == reqwest::StatusCode::NOT_FOUND {
                return Ok(AddressAssetSnapshot {
                    inscription_ids: Vec::new(),
                    outputs: Vec::new(),
                    rune_balances: Vec::new(),
                });
            }
            return Err(OrdError::RequestFailed(format!(
                "API Error (Address): {}",
                response.status()
            )));
        }

        let data: AddressResponse = response
            .json()
            .await
            .map_err(|e| OrdError::RequestFailed(format!("Failed to parse Address JSON: {e}")))?;

        Ok(AddressAssetSnapshot {
            inscription_ids: data.inscriptions,
            outputs: data.outputs,
            rune_balances: parse_runes_balances_value(&data.runes_balances),
        })
    }

    /// Fetch full inscription details for a single inscription id.
    pub async fn get_inscription_details(&self, id: &str) -> Result<Inscription, OrdError> {
        let details_url = format!("{}/inscription/{}", self.base_url, id);
        let details_resp = self
            .http_client
            .get(&details_url)
            .header("Accept", "application/json")
            .send()
            .await
            .map_err(|e| {
                OrdError::RequestFailed(format!("Failed to fetch details for {id}: {e}"))
            })?;

        if !details_resp.status().is_success() {
            return Err(OrdError::RequestFailed(format!(
                "API Error (Details {}): {}",
                id,
                details_resp.status()
            )));
        }

        details_resp.json().await.map_err(|e| {
            OrdError::RequestFailed(format!("Failed to parse Details JSON for {id}: {e}"))
        })
    }

    /// Fetch raw inscription content bytes for one inscription id.
    pub async fn get_inscription_content(&self, id: &str) -> Result<InscriptionContent, OrdError> {
        let url = format!("{}/content/{}", self.base_url, id);
        let response = self.http_client.get(&url).send().await.map_err(|e| {
            OrdError::RequestFailed(format!("Failed to fetch content for {id}: {e}"))
        })?;

        if !response.status().is_success() {
            return Err(OrdError::RequestFailed(format!(
                "API Error (Content {}): {}",
                id,
                response.status()
            )));
        }

        let content_type = response
            .headers()
            .get(reqwest::header::CONTENT_TYPE)
            .and_then(|value| value.to_str().ok())
            .map(ToString::to_string);

        let bytes = response.bytes().await.map_err(|e| {
            OrdError::RequestFailed(format!("Failed to read content body for {id}: {e}"))
        })?;

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
        let mut collected = Vec::new();
        for address in addresses {
            collected.extend(self.get_rune_balances(address).await?);
        }
        Ok(merge_rune_balances(collected))
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

            let outpoint = outpoint_str.as_str().parse::<OutPoint>().map_err(|e| {
                OrdError::RequestFailed(format!("Invalid outpoint {outpoint_str}: {e}"))
            })?;
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
        let response = self
            .http_client
            .get(&url)
            .send()
            .await
            .map_err(|e| OrdError::RequestFailed(e.to_string()))?;

        if !response.status().is_success() {
            return Err(OrdError::RequestFailed(format!(
                "Status API Error: {}",
                response.status()
            )));
        }

        let text = response
            .text()
            .await
            .map_err(|e| OrdError::RequestFailed(e.to_string()))?;
        text.trim()
            .parse::<u32>()
            .map_err(|e| OrdError::RequestFailed(format!("Invalid blockheight: {e}")))
    }

    /// Submit an offer PSBT to an ord-compatible `/offer` endpoint.
    pub async fn submit_offer_psbt(&self, psbt_base64: &str) -> Result<(), OrdError> {
        if psbt_base64.trim().is_empty() {
            return Err(OrdError::RequestFailed(
                "Offer PSBT payload cannot be empty".to_string(),
            ));
        }

        let url = format!("{}/offer", self.base_url);
        let response = self
            .http_client
            .post(&url)
            .body(psbt_base64.to_string())
            .send()
            .await
            .map_err(|e| OrdError::RequestFailed(e.to_string()))?;

        if !response.status().is_success() {
            let status = response.status();
            let text = response.text().await.unwrap_or_else(|_| String::new());
            return Err(OrdError::RequestFailed(format!(
                "Offer submission failed: {status} {text}"
            )));
        }

        Ok(())
    }

    /// Fetch submitted offer PSBTs from an ord-compatible `/offers` endpoint.
    pub async fn get_offer_psbts(&self) -> Result<Vec<String>, OrdError> {
        let url = format!("{}/offers", self.base_url);
        let response = self
            .http_client
            .get(&url)
            .header("Accept", "application/json")
            .send()
            .await
            .map_err(|e| OrdError::RequestFailed(e.to_string()))?;

        if !response.status().is_success() {
            return Err(OrdError::RequestFailed(format!(
                "Offers API Error: {}",
                response.status()
            )));
        }

        let text = response
            .text()
            .await
            .map_err(|e| OrdError::RequestFailed(format!("Failed to read offers body: {e}")))?;

        parse_offers_payload(&text)
    }

    async fn get_output_response(&self, outpoint: &str) -> Result<OutputResponse, OrdError> {
        let details_url = format!("{}/output/{}", self.base_url, outpoint);
        let details_resp = self
            .http_client
            .get(&details_url)
            .header("Accept", "application/json")
            .send()
            .await
            .map_err(|e| {
                OrdError::RequestFailed(format!(
                    "Failed to fetch output details for {outpoint}: {e}"
                ))
            })?;

        if !details_resp.status().is_success() {
            return Err(OrdError::RequestFailed(format!(
                "API Error (Output {}): {}",
                outpoint,
                details_resp.status()
            )));
        }

        details_resp.json().await.map_err(|e| {
            OrdError::RequestFailed(format!("Failed to parse Output JSON for {outpoint}: {e}"))
        })
    }
}

#[cfg(test)]
mod tests {
    use super::{parse_offers_payload, parse_runes_balances_value, OrdClient, OutputResponse};

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
        assert!(err.to_string().contains("Failed to parse offers JSON"));
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
        assert!(err.to_string().contains("missing required address field"));
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
                "amount": 150000,
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
