use crate::ordinals::error::OrdError;
use crate::ordinals::types::Inscription;
use bitcoin::OutPoint;
use reqwest::Client;
use serde::{Deserialize, Deserializer};
use std::collections::HashSet;

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
}

#[derive(Clone, Debug)]
/// Address-level view of inscription ids and related output references.
pub struct AddressAssetSnapshot {
    /// Inscription IDs reported for the address.
    pub inscription_ids: Vec<String>,
    /// Outpoint strings potentially carrying protected assets.
    pub outputs: Vec<String>,
}

#[derive(Deserialize)]
struct OutputResponse {
    #[serde(default, deserialize_with = "deserialize_string_vec_or_default")]
    inscriptions: Vec<String>,
    #[serde(default, deserialize_with = "deserialize_json_value_or_default")]
    runes: serde_json::Value,
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
            .map_err(|e| OrdError::RequestFailed(format!("Failed to parse Address JSON: {}", e)))?;

        Ok(AddressAssetSnapshot {
            inscription_ids: data.inscriptions,
            outputs: data.outputs,
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
                OrdError::RequestFailed(format!("Failed to fetch details for {}: {}", id, e))
            })?;

        if !details_resp.status().is_success() {
            return Err(OrdError::RequestFailed(format!(
                "API Error (Details {}): {}",
                id,
                details_resp.status()
            )));
        }

        details_resp.json().await.map_err(|e| {
            OrdError::RequestFailed(format!("Failed to parse Details JSON for {}: {}", id, e))
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
            let details_url = format!("{}/output/{}", self.base_url, outpoint_str);
            let details_resp = self
                .http_client
                .get(&details_url)
                .header("Accept", "application/json")
                .send()
                .await
                .map_err(|e| {
                    OrdError::RequestFailed(format!(
                        "Failed to fetch output details for {}: {}",
                        outpoint_str, e
                    ))
                })?;

            if !details_resp.status().is_success() {
                return Err(OrdError::RequestFailed(format!(
                    "API Error (Output {}): {}",
                    outpoint_str,
                    details_resp.status()
                )));
            }

            let output: OutputResponse = details_resp.json().await.map_err(|e| {
                OrdError::RequestFailed(format!(
                    "Failed to parse Output JSON for {}: {}",
                    outpoint_str, e
                ))
            })?;

            if !output.has_protected_assets() {
                continue;
            }

            let outpoint = outpoint_str.as_str().parse::<OutPoint>().map_err(|e| {
                OrdError::RequestFailed(format!("Invalid outpoint {}: {}", outpoint_str, e))
            })?;
            protected.insert(outpoint);
        }

        Ok(protected)
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
            .map_err(|e| OrdError::RequestFailed(format!("Invalid blockheight: {}", e)))
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
            let text = response.text().await.unwrap_or_else(|_| "".to_string());
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
}

#[cfg(test)]
mod tests {
    use super::{parse_offers_payload, OutputResponse};

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
}
