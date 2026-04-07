//! Nostr relay transport helpers for decentralized offer publication/discovery.
//!
//! This module intentionally excludes PoW and relay auth for now. It focuses on
//! baseline multi-relay fanout and discovery semantics.

use crate::{NostrOfferEvent, ZincError, OFFER_EVENT_KIND};
use futures_util::{SinkExt, StreamExt};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::HashSet;
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::time::{timeout, Duration};
use tokio_tungstenite::{connect_async, tungstenite::Message};

const OFFER_SCHEMA_TAG_VALUE: &str = "zinc-offer-v1";

/// Publish result for one relay.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RelayPublishResult {
    pub relay_url: String,
    pub accepted: bool,
    pub message: String,
}

/// Query options for relay discovery.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RelayQueryOptions {
    /// Maximum number of events requested from each relay.
    pub limit: usize,
    /// Per-relay timeout in milliseconds.
    pub timeout_ms: u64,
}

impl Default for RelayQueryOptions {
    fn default() -> Self {
        Self {
            limit: 256,
            timeout_ms: 5_000,
        }
    }
}

/// Stateless helper for Nostr relay framing, publishing, and discovery.
pub struct NostrRelayClient;

impl NostrRelayClient {
    /// Build an `["EVENT", <event>]` frame.
    pub fn event_frame(event: &NostrOfferEvent) -> Result<String, ZincError> {
        serde_json::to_string(&serde_json::json!(["EVENT", event]))
            .map_err(|e| ZincError::SerializationError(e.to_string()))
    }

    /// Build a `["REQ", sub_id, filter]` frame for offer discovery.
    pub fn req_frame(subscription_id: &str, limit: usize) -> Result<String, ZincError> {
        serde_json::to_string(&serde_json::json!([
            "REQ",
            subscription_id,
            {
                "kinds": [OFFER_EVENT_KIND],
                "#z": [OFFER_SCHEMA_TAG_VALUE],
                "limit": limit
            }
        ]))
        .map_err(|e| ZincError::SerializationError(e.to_string()))
    }

    /// Build a `["CLOSE", sub_id]` frame.
    pub fn close_frame(subscription_id: &str) -> Result<String, ZincError> {
        serde_json::to_string(&serde_json::json!(["CLOSE", subscription_id]))
            .map_err(|e| ZincError::SerializationError(e.to_string()))
    }

    /// Parse relay `["OK", event_id, accepted, message]` frames.
    pub fn parse_ok_frame(frame: &str, event_id: &str) -> Option<(bool, String)> {
        let value: Value = serde_json::from_str(frame).ok()?;
        let arr = value.as_array()?;
        if arr.len() != 4 {
            return None;
        }
        if arr.first()?.as_str()? != "OK" {
            return None;
        }
        if arr.get(1)?.as_str()? != event_id {
            return None;
        }
        let accepted = arr.get(2)?.as_bool()?;
        let message = arr.get(3)?.as_str()?.to_string();
        Some((accepted, message))
    }

    /// Parse relay `["EVENT", sub_id, event]` frames for the specified subscription.
    pub fn parse_event_frame(frame: &str, subscription_id: &str) -> Option<NostrOfferEvent> {
        let value: Value = serde_json::from_str(frame).ok()?;
        let arr = value.as_array()?;
        if arr.len() != 3 {
            return None;
        }
        if arr.first()?.as_str()? != "EVENT" {
            return None;
        }
        if arr.get(1)?.as_str()? != subscription_id {
            return None;
        }

        let event: NostrOfferEvent = serde_json::from_value(arr.get(2)?.clone()).ok()?;
        event.verify().ok()?;
        Some(event)
    }

    /// Publish one signed offer event to one relay and wait for relay `OK`.
    pub async fn publish_offer(
        relay_url: &str,
        event: &NostrOfferEvent,
        timeout_ms: u64,
    ) -> Result<RelayPublishResult, ZincError> {
        event.verify()?;
        let (mut socket, _) = connect_async(relay_url).await.map_err(|e| {
            ZincError::OfferError(format!("failed to connect relay {relay_url}: {e}"))
        })?;

        let event_frame = Self::event_frame(event)?;
        socket
            .send(Message::Text(event_frame))
            .await
            .map_err(|e| ZincError::OfferError(format!("failed to send event frame: {e}")))?;

        let relay_url_owned = relay_url.to_string();
        let event_id = event.id.clone();
        let ack = timeout(Duration::from_millis(timeout_ms), async move {
            while let Some(message) = socket.next().await {
                match message {
                    Ok(Message::Text(text)) => {
                        if let Some((accepted, msg)) =
                            Self::parse_ok_frame(text.as_ref(), &event_id)
                        {
                            return Ok(RelayPublishResult {
                                relay_url: relay_url_owned.clone(),
                                accepted,
                                message: msg,
                            });
                        }
                    }
                    Ok(Message::Binary(bin)) => {
                        if let Ok(text) = std::str::from_utf8(&bin) {
                            if let Some((accepted, msg)) = Self::parse_ok_frame(text, &event_id) {
                                return Ok(RelayPublishResult {
                                    relay_url: relay_url_owned.clone(),
                                    accepted,
                                    message: msg,
                                });
                            }
                        }
                    }
                    Ok(Message::Close(_)) => {
                        break;
                    }
                    Ok(_) => {}
                    Err(e) => {
                        return Err(ZincError::OfferError(format!(
                            "relay read error for {relay_url_owned}: {e}"
                        )));
                    }
                }
            }

            Err(ZincError::OfferError(format!(
                "relay {relay_url_owned} closed before acknowledging event"
            )))
        })
        .await
        .map_err(|_| {
            ZincError::OfferError(format!("relay {relay_url} timed out waiting for OK"))
        })?;

        ack
    }

    /// Publish one event to multiple relays concurrently.
    pub async fn publish_offer_multi(
        relay_urls: &[String],
        event: &NostrOfferEvent,
        timeout_ms: u64,
    ) -> Vec<RelayPublishResult> {
        let mut tasks = Vec::new();
        for relay_url in relay_urls {
            let relay = relay_url.clone();
            let event = event.clone();
            tasks.push(tokio::spawn(async move {
                match Self::publish_offer(&relay, &event, timeout_ms).await {
                    Ok(result) => result,
                    Err(err) => RelayPublishResult {
                        relay_url: relay,
                        accepted: false,
                        message: err.to_string(),
                    },
                }
            }));
        }

        let mut results = Vec::new();
        for task in tasks {
            if let Ok(result) = task.await {
                results.push(result);
            }
        }
        results
    }

    /// Discover valid offer events from a single relay.
    pub async fn discover_offer_events(
        relay_url: &str,
        options: RelayQueryOptions,
    ) -> Result<Vec<NostrOfferEvent>, ZincError> {
        let (mut socket, _) = connect_async(relay_url).await.map_err(|e| {
            ZincError::OfferError(format!("failed to connect relay {relay_url}: {e}"))
        })?;

        let subscription_id = format!(
            "zinc-offers-{}",
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_nanos()
        );
        let req_frame = Self::req_frame(&subscription_id, options.limit)?;
        socket
            .send(Message::Text(req_frame))
            .await
            .map_err(|e| ZincError::OfferError(format!("failed to send req frame: {e}")))?;

        let mut events = Vec::new();
        let mut seen_ids = HashSet::new();
        let sid = subscription_id.clone();
        timeout(Duration::from_millis(options.timeout_ms), async {
            while let Some(message) = socket.next().await {
                match message {
                    Ok(Message::Text(text)) => {
                        if let Some(event) = Self::parse_event_frame(text.as_ref(), &sid) {
                            if seen_ids.insert(event.id.clone()) {
                                events.push(event);
                            }
                            continue;
                        }
                        if is_eose_frame(text.as_ref(), &sid) {
                            break;
                        }
                    }
                    Ok(Message::Binary(bin)) => {
                        if let Ok(text) = std::str::from_utf8(&bin) {
                            if let Some(event) = Self::parse_event_frame(text, &sid) {
                                if seen_ids.insert(event.id.clone()) {
                                    events.push(event);
                                }
                                continue;
                            }
                            if is_eose_frame(text, &sid) {
                                break;
                            }
                        }
                    }
                    Ok(Message::Close(_)) => {
                        break;
                    }
                    Ok(_) => {}
                    Err(e) => {
                        return Err(ZincError::OfferError(format!(
                            "relay read error for {relay_url}: {e}"
                        )));
                    }
                }
            }

            Ok::<(), ZincError>(())
        })
        .await
        .map_err(|_| {
            ZincError::OfferError(format!(
                "relay {relay_url} timed out while discovering offers"
            ))
        })??;

        let close = Self::close_frame(&subscription_id)?;
        let _ = socket.send(Message::Text(close)).await;
        Ok(events)
    }

    /// Discover valid events across multiple relays and dedupe by event id.
    pub async fn discover_offer_events_multi(
        relay_urls: &[String],
        options: RelayQueryOptions,
    ) -> Vec<NostrOfferEvent> {
        let mut tasks = Vec::new();
        for relay_url in relay_urls {
            let relay = relay_url.clone();
            let options = options.clone();
            tasks.push(tokio::spawn(async move {
                Self::discover_offer_events(&relay, options)
                    .await
                    .unwrap_or_default()
            }));
        }

        let mut merged = Vec::new();
        let mut seen_ids = HashSet::new();
        for task in tasks {
            if let Ok(events) = task.await {
                for event in events {
                    if seen_ids.insert(event.id.clone()) {
                        merged.push(event);
                    }
                }
            }
        }
        merged
    }
}

fn is_eose_frame(frame: &str, subscription_id: &str) -> bool {
    let value: Value = match serde_json::from_str(frame) {
        Ok(v) => v,
        Err(_) => return false,
    };
    let arr = match value.as_array() {
        Some(items) => items,
        None => return false,
    };
    if arr.len() != 2 {
        return false;
    }
    arr.first().and_then(Value::as_str) == Some("EOSE")
        && arr.get(1).and_then(Value::as_str) == Some(subscription_id)
}
