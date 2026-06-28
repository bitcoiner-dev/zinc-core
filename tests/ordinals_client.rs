#[cfg(test)]
#[cfg(not(target_arch = "wasm32"))] // mockito only works on native
mod tests {
    use mockito::Server;
    use zinc_core::ordinals::OrdClient;

    #[tokio::test]
    async fn test_get_inscriptions() {
        let mut server = Server::new_async().await;
        let url = server.url();
        let address = "bc1p5d7rjq7g6rdk2y6876ndge59123232nsq68efq";

        // Mock response
        // 1. Mock List Response
        let _m1 = server
            .mock("GET", format!("/address/{address}").as_str())
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(
                r#"{
                "inscriptions": [
                    "6fb976ab49dcec017f1e201e84395983204ae1a7c2abf7ced0a85d692e442799i0"
                ]
            }"#,
            )
            .create_async()
            .await;

        // 2. Mock Details Response
        let _m2 = server
            .mock(
                "GET",
                "/inscription/6fb976ab49dcec017f1e201e84395983204ae1a7c2abf7ced0a85d692e442799i0",
            )
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(
                r#"{
                "id": "6fb976ab49dcec017f1e201e84395983204ae1a7c2abf7ced0a85d692e442799i0",
                "number": 100,
                "address": "bc1p5d7rjq7g6rdk2y6876ndge59123232nsq68efq",
                "genesis_height": 770000,
                "genesis_fee": 1000,
                "output_value": 546,
                "location": "6fb976ab49dcec017f1e201e84395983204ae1a7c2abf7ced0a85d692e442799:0:0",
                "output": "6fb976ab49dcec017f1e201e84395983204ae1a7c2abf7ced0a85d692e442799:0",
                "offset": 0,
                "sat": 1234567890,
                "satpoint": "6fb976ab49dcec017f1e201e84395983204ae1a7c2abf7ced0a85d692e442799:0:0",
                "content_type": "text/plain",
                "content_length": 5,
                "timestamp": 1670000000
            }"#,
            )
            .create_async()
            .await;

        let client = OrdClient::new(url);
        let inscriptions = client
            .get_inscriptions(address)
            .await
            .expect("Failed to get inscriptions");

        assert_eq!(inscriptions.len(), 1);
        assert_eq!(
            inscriptions[0].id,
            "6fb976ab49dcec017f1e201e84395983204ae1a7c2abf7ced0a85d692e442799i0"
        );
        assert_eq!(inscriptions[0].number, 100);

        _m1.assert_async().await;
        _m2.assert_async().await;
    }

    const ADDR: &str = "bc1p5d7rjq7g6rdk2y6876ndge59123232nsq68efq";

    #[tokio::test]
    async fn snapshot_returns_empty_on_404() {
        let mut server = Server::new_async().await;
        let _m = server
            .mock("GET", format!("/address/{ADDR}").as_str())
            .with_status(404)
            .create_async()
            .await;

        let client = OrdClient::new(server.url());
        let snap = client
            .get_address_asset_snapshot(ADDR)
            .await
            .expect("404 is treated as an empty snapshot");
        assert!(snap.inscription_ids.is_empty());
        assert!(snap.outputs.is_empty());
    }

    #[tokio::test]
    async fn snapshot_errors_on_server_error() {
        let mut server = Server::new_async().await;
        let _m = server
            .mock("GET", format!("/address/{ADDR}").as_str())
            .with_status(500)
            .create_async()
            .await;

        let client = OrdClient::new(server.url());
        let err = client
            .get_address_asset_snapshot(ADDR)
            .await
            .err()
            .expect("500 must error");
        assert!(err.to_string().contains("API Error (Address)"), "{err}");
    }

    #[tokio::test]
    async fn snapshot_errors_on_malformed_json() {
        let mut server = Server::new_async().await;
        let _m = server
            .mock("GET", format!("/address/{ADDR}").as_str())
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body("this is not json")
            .create_async()
            .await;

        let client = OrdClient::new(server.url());
        let err = client
            .get_address_asset_snapshot(ADDR)
            .await
            .err()
            .expect("malformed json must error");
        assert!(err.to_string().contains("Failed to parse Address JSON"), "{err}");
    }

    #[tokio::test]
    async fn inscription_details_errors_on_404() {
        let mut server = Server::new_async().await;
        let _m = server
            .mock("GET", "/inscription/abc123i0")
            .with_status(404)
            .create_async()
            .await;

        let client = OrdClient::new(server.url());
        let err = client
            .get_inscription_details("abc123i0")
            .await
            .err()
            .expect("404 details must error");
        assert!(err.to_string().contains("API Error (Details"), "{err}");
    }

    #[tokio::test]
    async fn inscription_content_returns_bytes_and_type() {
        let mut server = Server::new_async().await;
        let _m = server
            .mock("GET", "/content/abc123i0")
            .with_status(200)
            .with_header("content-type", "text/plain")
            .with_body("hello")
            .create_async()
            .await;

        let client = OrdClient::new(server.url());
        let content = client
            .get_inscription_content("abc123i0")
            .await
            .expect("content fetch");
        assert_eq!(content.bytes, b"hello");
        assert!(content
            .content_type
            .as_deref()
            .unwrap_or_default()
            .contains("text/plain"));
    }

    #[tokio::test]
    async fn inscription_content_errors_on_server_error() {
        let mut server = Server::new_async().await;
        let _m = server
            .mock("GET", "/content/abc123i0")
            .with_status(500)
            .create_async()
            .await;

        let client = OrdClient::new(server.url());
        let err = client
            .get_inscription_content("abc123i0")
            .await
            .err()
            .expect("500 content must error");
        assert!(err.to_string().contains("API Error (Content"), "{err}");
    }

    #[tokio::test]
    async fn indexing_height_parses_plaintext_number() {
        let mut server = Server::new_async().await;
        let _m = server
            .mock("GET", "/blockheight")
            .with_status(200)
            .with_body("850123\n")
            .create_async()
            .await;

        let client = OrdClient::new(server.url());
        let height = client.get_indexing_height().await.expect("height");
        assert_eq!(height, 850_123);
    }

    #[tokio::test]
    async fn indexing_height_errors_on_non_numeric_body() {
        let mut server = Server::new_async().await;
        let _m = server
            .mock("GET", "/blockheight")
            .with_status(200)
            .with_body("not-a-number")
            .create_async()
            .await;

        let client = OrdClient::new(server.url());
        let err = client
            .get_indexing_height()
            .await
            .err()
            .expect("non-numeric height must error");
        assert!(err.to_string().contains("Invalid blockheight"), "{err}");
    }

    #[tokio::test]
    async fn submit_offer_rejects_empty_payload_without_network() {
        // No server needed: empty payload is rejected before any request.
        let client = OrdClient::new("http://127.0.0.1:1".to_string());
        let err = client
            .submit_offer_psbt("   ")
            .await
            .err()
            .expect("empty payload must error");
        assert!(err.to_string().contains("cannot be empty"), "{err}");
    }

    #[tokio::test]
    async fn submit_offer_posts_payload_and_succeeds() {
        let mut server = Server::new_async().await;
        let m = server
            .mock("POST", "/offer")
            .with_status(200)
            .create_async()
            .await;

        let client = OrdClient::new(server.url());
        client
            .submit_offer_psbt("cHNidP8BAA==")
            .await
            .expect("offer submission succeeds");
        m.assert_async().await;
    }
}
