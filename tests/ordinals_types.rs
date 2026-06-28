#[cfg(test)]
mod tests {
    use serde_json::{from_str, to_string};
    use zinc_core::ordinals::{Inscription, RuneBalance, Satpoint};

    const TXID: &str = "6fb976ab49dcec017f1e201e84395983204ae1a7c2abf7ced0a85d692e442799";

    #[test]
    fn test_deserialize_inscription_info() {
        // Example response from Hiros/Ord API
        let json = r#"{
            "id": "6fb976ab49dcec017f1e201e84395983204ae1a7c2abf7ced0a85d692e442799i0",
            "number": 3534343,
            "address": "bc1p5d7rjq7g6rdk2y6876ndge59123232nsq68efq",
            "genesis_address": "bc1p5d7rjq7g6rdk2y6876ndge59123232nsq68efq",
            "genesis_block_height": 767430,
            "genesis_block_hash": "000000000000000000020b6605a6669fec8933e14c11307e596df2d72ce607f2",
            "genesis_tx_id": "6fb976ab49dcec017f1e201e84395983204ae1a7c2abf7ced0a85d692e442799",
            "genesis_fee": 3179,
            "genesis_timestamp": 1670928000,
            "tx_id": "6fb976ab49dcec017f1e201e84395983204ae1a7c2abf7ced0a85d692e442799",
            "satpoint": "6fb976ab49dcec017f1e201e84395983204ae1a7c2abf7ced0a85d692e442799:0:0",
            "output": "6fb976ab49dcec017f1e201e84395983204ae1a7c2abf7ced0a85d692e442799:0",
            "value": 10000,
            "offset": 0,
            "sat_ordinal": 1234567890,
            "sat_rarity": "common",
            "sat_coinbase_height": 767430,
            "mime_type": "text/plain",
            "content_type": "text/plain",
            "content_length": 59,
            "timestamp": 1670928000
        }"#;

        let inscription: Inscription = from_str(json).expect("Failed to deserialize Inscription");

        assert_eq!(
            inscription.id,
            "6fb976ab49dcec017f1e201e84395983204ae1a7c2abf7ced0a85d692e442799i0"
        );
        assert_eq!(inscription.number, 3534343);
        assert_eq!(inscription.content_type, Some("text/plain".to_string()));
        assert_eq!(inscription.value, Some(10000));
        assert_eq!(
            inscription.satpoint.to_string(),
            "6fb976ab49dcec017f1e201e84395983204ae1a7c2abf7ced0a85d692e442799:0:0"
        );
    }

    #[test]
    fn test_satpoint_parsing() {
        // Valid satpoint
        let s1 = "6fb976ab49dcec017f1e201e84395983204ae1a7c2abf7ced0a85d692e442799:0:0";
        let satpoint: Satpoint = s1.parse().expect("Should parse valid satpoint");
        assert_eq!(
            satpoint.outpoint.txid.to_string(),
            "6fb976ab49dcec017f1e201e84395983204ae1a7c2abf7ced0a85d692e442799"
        );
        assert_eq!(satpoint.outpoint.vout, 0);
        assert_eq!(satpoint.offset, 0);

        // Satpoint with non-zero offset
        let s2 = "6fb976ab49dcec017f1e201e84395983204ae1a7c2abf7ced0a85d692e442799:0:100";
        let satpoint2: Satpoint = s2.parse().expect("Should parse offset satpoint");
        assert_eq!(satpoint2.offset, 100);
    }

    #[test]
    fn satpoint_display_fromstr_roundtrip() {
        let canonical = format!("{TXID}:3:42");
        let sp: Satpoint = canonical.parse().expect("valid satpoint");
        assert_eq!(sp.outpoint.vout, 3);
        assert_eq!(sp.offset, 42);
        // Display must reproduce the canonical input exactly.
        assert_eq!(sp.to_string(), canonical);
    }

    #[test]
    fn satpoint_rejects_too_few_parts() {
        let r: Result<Satpoint, _> = format!("{TXID}:0").parse();
        assert!(r.is_err());
    }

    #[test]
    fn satpoint_rejects_bad_txid() {
        let r = "not_a_txid:0:0".parse::<Satpoint>();
        assert!(r.is_err());
    }

    #[test]
    fn satpoint_rejects_non_numeric_vout() {
        let r = format!("{TXID}:x:0").parse::<Satpoint>();
        assert!(r.is_err());
    }

    #[test]
    fn satpoint_rejects_non_numeric_offset() {
        let r = format!("{TXID}:0:x").parse::<Satpoint>();
        assert!(r.is_err());
    }

    #[test]
    fn satpoint_default_is_null_outpoint() {
        let sp = Satpoint::default();
        assert!(sp.outpoint.is_null());
        assert_eq!(sp.offset, 0);
    }

    #[test]
    fn inscription_serde_roundtrip_uses_canonical_satpoint() {
        let satpoint: Satpoint = format!("{TXID}:1:7").parse().unwrap();
        let insc = Inscription {
            id: format!("{TXID}i0"),
            number: 42,
            satpoint,
            content_type: Some("text/plain".to_string()),
            value: Some(10_000),
            content_length: Some(59),
            timestamp: Some(1_670_928_000),
        };

        let json = to_string(&insc).expect("serialize");
        // Exercises the custom `serialize_satpoint`: emitted as a canonical string.
        assert!(json.contains(&format!("{TXID}:1:7")));

        let back: Inscription = from_str(&json).expect("deserialize");
        assert_eq!(insc, back);
    }

    #[test]
    fn rune_balance_serde_roundtrip_preserves_precision() {
        let rb = RuneBalance {
            rune: "NO•ORDINARY•KIND".to_string(),
            // Larger than u128 to prove the string-typed amount preserves precision.
            amount: "340282366920938463463374607431768211456".to_string(),
            divisibility: Some(8),
            symbol: Some("¤".to_string()),
        };

        let json = to_string(&rb).expect("serialize");
        let back: RuneBalance = from_str(&json).expect("deserialize");
        assert_eq!(rb, back);
        assert_eq!(back.amount, rb.amount);
    }
}
