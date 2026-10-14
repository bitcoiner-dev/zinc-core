//! TLS connection handling functionality when using the `rustls` crate for
//! handling TLS.

use rustls::pki_types::ServerName;
use rustls::{self, ClientConfig, ClientConnection, RootCertStore, StreamOwned};
use std::convert::TryFrom;
use std::io::{self, Write};
use std::net::TcpStream;
use std::sync::Arc;
#[cfg(feature = "rustls-webpki")]
use webpki_roots::TLS_SERVER_ROOTS;

use crate::Error;

use super::{Connection, HttpStream};

pub type SecuredStream = StreamOwned<ClientConnection, TcpStream>;

static CONFIG: std::sync::LazyLock<Result<Arc<ClientConfig>, rustls::Error>> =
    std::sync::LazyLock::new(|| {
        let mut root_certificates = RootCertStore::empty();

        // Try to load native certs
        #[cfg(feature = "https-rustls-probe")]
        {
            for root_cert in rustls_native_certs::load_native_certs().certs {
                // Ignore erroneous OS certificates, there's nothing
                // to do differently in that situation anyways.
                let _ = root_certificates.add(root_cert);
            }
        }

        #[cfg(feature = "rustls-webpki")]
        root_certificates
            .roots
            .extend(TLS_SERVER_ROOTS.iter().cloned());

        client_config(root_certificates)
    });

fn client_config(root_certificates: RootCertStore) -> Result<Arc<ClientConfig>, rustls::Error> {
    // Keep provider selection local to this client. Consumers may enable more
    // than one Rustls provider or install their own process-wide default.
    let config =
        ClientConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
            .with_safe_default_protocol_versions()?
            .with_root_certificates(root_certificates)
            .with_no_client_auth();
    Ok(Arc::new(config))
}

pub fn create_secured_stream(conn: &Connection) -> Result<HttpStream, Error> {
    // Rustls setup
    #[cfg(feature = "log")]
    log::trace!("Setting up TLS parameters for {}.", conn.request.url.host);
    let dns_name = match ServerName::try_from(conn.request.url.host.clone()) {
        Ok(result) => result,
        Err(err) => return Err(Error::IoError(io::Error::new(io::ErrorKind::Other, err))),
    };
    let config = CONFIG.clone().map_err(Error::RustlsCreateConnection)?;
    let sess = ClientConnection::new(config, dns_name).map_err(Error::RustlsCreateConnection)?;

    // Connect
    #[cfg(feature = "log")]
    log::trace!("Establishing TCP connection to {}.", conn.request.url.host);
    let tcp = conn.connect()?;

    // Send request
    #[cfg(feature = "log")]
    log::trace!("Establishing TLS session to {}.", conn.request.url.host);
    let mut tls = StreamOwned::new(sess, tcp); // I don't think this actually does any communication.
    #[cfg(feature = "log")]
    log::trace!("Writing HTTPS request to {}.", conn.request.url.host);
    let _ = tls.get_ref().set_write_timeout(conn.timeout()?);
    tls.write_all(&conn.request.as_bytes())?;

    Ok(HttpStream::create_secured(tls, conn.timeout_at))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Read;
    use std::net::TcpListener;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::thread;

    type TestServer = (
        std::net::SocketAddr,
        rustls::pki_types::CertificateDer<'static>,
        Arc<AtomicBool>,
        thread::JoinHandle<()>,
    );

    fn test_server() -> TestServer {
        let rcgen::CertifiedKey { cert, signing_key } =
            rcgen::generate_simple_self_signed(vec!["localhost".to_owned()]).unwrap();
        let der = cert.der().clone();
        let key = rustls::pki_types::PrivatePkcs8KeyDer::from(signing_key.serialize_der());
        let config = rustls::ServerConfig::builder_with_provider(Arc::new(
            rustls::crypto::ring::default_provider(),
        ))
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(vec![der.clone()], key.into())
        .unwrap();
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let address = listener.local_addr().unwrap();
        let received = Arc::new(AtomicBool::new(false));
        let observed = Arc::clone(&received);
        let worker = thread::spawn(move || {
            let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
            let tcp = loop {
                match listener.accept() {
                    Ok((tcp, _)) => break tcp,
                    Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                        assert!(
                            std::time::Instant::now() < deadline,
                            "client did not connect"
                        );
                        thread::sleep(std::time::Duration::from_millis(5));
                    }
                    Err(error) => panic!("accept failed: {}", error),
                }
            };
            tcp.set_nonblocking(false).unwrap();
            tcp.set_read_timeout(Some(std::time::Duration::from_secs(5)))
                .unwrap();
            tcp.set_write_timeout(Some(std::time::Duration::from_secs(5)))
                .unwrap();
            let session = rustls::ServerConnection::new(Arc::new(config)).unwrap();
            let mut stream = StreamOwned::new(session, tcp);
            let mut bytes = [0; 1024];
            if let Ok(count) = stream.read(&mut bytes) {
                if count > 0 {
                    observed.store(true, Ordering::SeqCst);
                    stream
                        .write_all(
                            b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok",
                        )
                        .unwrap();
                    stream.conn.send_close_notify();
                    stream.flush().unwrap();
                }
            }
        });
        (address, der, received, worker)
    }

    #[test]
    fn explicit_provider_works_with_both_providers_without_global_install() {
        // The dev dependency deliberately enables Ring and AWS-LC. An implicit
        // Rustls builder would panic without a process-wide provider.
        assert!(rustls::crypto::CryptoProvider::get_default().is_none());
        let config = client_config(RootCertStore::empty()).unwrap();
        let _ = ClientConnection::new(config, ServerName::try_from("localhost").unwrap()).unwrap();
        assert!(rustls::crypto::CryptoProvider::get_default().is_none());
    }

    #[test]
    fn trusted_local_server_completes_handshake_and_http() {
        let (address, cert, received, worker) = test_server();
        let mut roots = RootCertStore::empty();
        roots.add(cert).unwrap();
        let session = ClientConnection::new(
            client_config(roots).unwrap(),
            ServerName::try_from("localhost").unwrap(),
        )
        .unwrap();
        let tcp = TcpStream::connect(address).unwrap();
        tcp.set_read_timeout(Some(std::time::Duration::from_secs(5)))
            .unwrap();
        let mut stream = StreamOwned::new(session, tcp);
        stream
            .write_all(b"GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
            .unwrap();
        stream.flush().unwrap();
        let mut response = [0; 1024];
        let count = stream.read(&mut response).unwrap();
        assert!(response[..count].ends_with(b"ok"));
        worker.join().unwrap();
        assert!(received.load(Ordering::SeqCst));
    }

    #[cfg(feature = "rustls-webpki")]
    #[test]
    fn actual_http_client_refuses_untrusted_certificate_before_sending_payload() {
        let (address, _, received, worker) = test_server();
        let result = crate::get(format!("https://localhost:{}/", address.port()))
            .with_timeout(5)
            .send();
        assert!(result.is_err());
        worker.join().unwrap();
        assert!(!received.load(Ordering::SeqCst));
    }
}
