use std::{future, time::Duration};

use esplora_client::{Error, Sleeper};

#[derive(Debug, Clone, Copy)]
struct NoopSleeper;

impl Sleeper for NoopSleeper {
    type Sleep = future::Ready<()>;

    fn sleep(_duration: Duration) -> Self::Sleep {
        future::ready(())
    }
}

async fn assert_default_attempt_count(status: usize, body: &str, expected_attempts: usize) {
    let mut server = mockito::Server::new_async().await;
    let mock = server
        .mock("GET", "/blocks/tip/height")
        .with_status(status)
        .with_body(body)
        .expect(expected_attempts)
        .create_async()
        .await;

    let client = esplora_client::Builder::new(&server.url())
        .build_async_with_sleeper::<NoopSleeper>()
        .expect("client");
    let error = client
        .get_height()
        .await
        .expect_err("HTTP failure must fail");

    assert!(matches!(
        error,
        Error::HttpResponse {
            status: observed,
            ..
        } if usize::from(observed) == status
    ));
    mock.assert_async().await;
}

#[tokio::test]
async fn esplora_default_retries_rate_limit_six_times_and_drops_retry_after() {
    let mut server = mockito::Server::new_async().await;
    let mock = server
        .mock("GET", "/blocks/tip/height")
        .with_status(429)
        .with_header("retry-after", "120")
        .with_body("rate limited")
        .expect(7)
        .create_async()
        .await;

    let client = esplora_client::Builder::new(&server.url())
        .build_async_with_sleeper::<NoopSleeper>()
        .expect("client");
    let error = client.get_height().await.expect_err("429 must fail");

    assert!(matches!(error, Error::HttpResponse { status: 429, .. }));
    mock.assert_async().await;
}

#[tokio::test]
async fn esplora_default_retries_service_unavailable_six_times() {
    assert_default_attempt_count(503, "not ready", 7).await;
}

#[tokio::test]
async fn esplora_default_does_not_retry_bad_request() {
    assert_default_attempt_count(400, "bad request", 1).await;
}

#[tokio::test]
async fn esplora_malformed_height_is_a_parsing_error_after_one_response() {
    let mut server = mockito::Server::new_async().await;
    let mock = server
        .mock("GET", "/blocks/tip/height")
        .with_status(200)
        .with_body("not-a-height")
        .expect(1)
        .create_async()
        .await;

    let client = esplora_client::Builder::new(&server.url())
        .build_async_with_sleeper::<NoopSleeper>()
        .expect("client");
    let error = client
        .get_height()
        .await
        .expect_err("malformed height must fail");

    assert!(matches!(error, Error::Parsing(_)));
    mock.assert_async().await;
}

#[tokio::test]
async fn esplora_transport_failure_is_not_wrapped_as_an_http_status() {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("ephemeral listener");
    let address = listener.local_addr().expect("listener address");
    drop(listener);
    let base_url = format!("http://{address}");

    let client = esplora_client::Builder::new(&base_url)
        .build_async_with_sleeper::<NoopSleeper>()
        .expect("client");
    let error = client
        .get_height()
        .await
        .expect_err("closed server must fail");

    assert!(!matches!(error, Error::HttpResponse { .. }));
}
