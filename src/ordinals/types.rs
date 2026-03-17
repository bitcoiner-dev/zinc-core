use crate::ordinals::error::OrdError;
use bitcoin::{OutPoint, Txid};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::str::FromStr;

/// a unique location for an ordinal, defined by an OutPoint and an offset.
/// Format: `txid:vout:offset`
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Satpoint {
    /// Transaction outpoint containing the inscription.
    pub outpoint: OutPoint,
    /// Byte offset within the outpoint where the sat resides.
    pub offset: u64,
}

impl std::fmt::Display for Satpoint {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{}:{}:{}",
            self.outpoint.txid, self.outpoint.vout, self.offset
        )
    }
}

impl FromStr for Satpoint {
    type Err = OrdError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let parts: Vec<&str> = s.split(':').collect();
        if parts.len() < 3 {
            return Err(OrdError::RequestFailed(format!(
                "Invalid satpoint format: {}",
                s
            )));
        }

        let txid = parts[0]
            .parse::<Txid>()
            .map_err(|e| OrdError::RequestFailed(format!("Invalid txid in satpoint: {}", e)))?;
        let vout = parts[1]
            .parse::<u32>()
            .map_err(|e| OrdError::RequestFailed(format!("Invalid vout in satpoint: {}", e)))?;
        let offset = parts[2]
            .parse::<u64>()
            .map_err(|e| OrdError::RequestFailed(format!("Invalid offset in satpoint: {}", e)))?;

        Ok(Satpoint {
            outpoint: OutPoint { txid, vout },
            offset,
        })
    }
}

/// Serialize `Satpoint` using canonical `txid:vout:offset` string format.
pub fn serialize_satpoint<S>(satpoint: &Satpoint, serializer: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    serializer.serialize_str(&satpoint.to_string())
}

/// Deserialize `Satpoint` from canonical `txid:vout:offset` string format.
pub fn deserialize_satpoint<'de, D>(deserializer: D) -> Result<Satpoint, D::Error>
where
    D: Deserializer<'de>,
{
    let s = String::deserialize(deserializer)?;
    Satpoint::from_str(&s).map_err(serde::de::Error::custom)
}

/// Core Inscription data model.
/// We map standard API fields to this struct.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Inscription {
    /// The unique inscription ID (txid + i + index)
    pub id: String,

    /// The inscription number (sequential)
    pub number: i64,

    /// The location of the inscription
    #[serde(
        deserialize_with = "deserialize_satpoint",
        serialize_with = "serialize_satpoint"
    )]
    pub satpoint: Satpoint,

    /// MIME type of the content
    #[serde(default, rename = "content_type")]
    // Some APIs use "content_type", some "mime_type" - handler logic might be needed if they differ widely
    pub content_type: Option<String>,

    /// Postage value in sats (optional, usually inferred from output)
    pub value: Option<u64>,

    /// Content length in bytes
    pub content_length: Option<u64>,

    /// Creation timestamp
    pub timestamp: Option<u64>,
}

// Fallback for missing Satpoints (default to all zeros? Or option?)
// For now, in our tests, we provide it.
impl Default for Satpoint {
    fn default() -> Self {
        Satpoint {
            outpoint: OutPoint::null(),
            offset: 0,
        }
    }
}
