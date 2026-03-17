#[cfg(test)]
#[cfg(not(target_arch = "wasm32"))] // mockito only works on native
mod tests {
    use mockito::Server;
    use zinc_core::ordinals::OrdClient;

    #[tokio::test]
    #[ignore = "requires loopback mock server permissions (mockito)"]
    async fn test_get_inscriptions() {
        let mut server = Server::new_async().await;
        let url = server.url();
        let address = "bc1p5d7rjq7g6rdk2y6876ndge59123232nsq68efq";

        // Mock response
        // 1. Mock List Response
        let _m1 = server
            .mock("GET", format!("/address/{}", address).as_str())
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
}
