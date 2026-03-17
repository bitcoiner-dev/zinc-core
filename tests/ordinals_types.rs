#[cfg(test)]
mod tests {
    use serde_json::from_str;
    use zinc_core::ordinals::{Inscription, Satpoint};

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
}
