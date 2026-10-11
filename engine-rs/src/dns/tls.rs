// Copyright (c) 2026 RethinkDNS and its authors.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

//! TLS client settings for DoH and DoT: rustls on ring, TLS 1.2 or 1.3 as
//! Go's MinVersion, server certificates checked by Windows (as Go's
//! crypto/x509 does on Windows), session resumption on.

use std::sync::Arc;

use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::CryptoProvider;
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{ClientConfig, DigitallySignedStruct, RootCertStore, SignatureScheme};

/// Whom to trust for server certificates.
#[derive(Clone, Default)]
pub enum Trust {
    /// The system's roots and checks (rustls-platform-verifier).
    #[default]
    System,
    /// Only these roots (tests).
    Roots(Vec<CertificateDer<'static>>),
}

pub fn provider() -> Arc<CryptoProvider> {
    Arc::new(rustls::crypto::ring::default_provider())
}

/// A client config. `skip_verify` is firestack's no-PKI mode (an http://
/// DoH URL, a DoT server without tls:), which checks nothing.
pub fn client_config(trust: &Trust, skip_verify: bool, alpn: &[&[u8]]) -> Result<Arc<ClientConfig>, String> {
    let p = provider();
    let b = ClientConfig::builder_with_provider(p.clone())
        .with_protocol_versions(&[&rustls::version::TLS13, &rustls::version::TLS12])
        .map_err(|e| format!("tls: {e}"))?;
    let mut c = if skip_verify {
        b.dangerous().with_custom_certificate_verifier(Arc::new(NoVerify(p))).with_no_client_auth()
    } else {
        match trust {
            Trust::System => {
                let v = rustls_platform_verifier::Verifier::new(p).map_err(|e| format!("tls: {e}"))?;
                b.dangerous().with_custom_certificate_verifier(Arc::new(v)).with_no_client_auth()
            }
            Trust::Roots(certs) => {
                let mut roots = RootCertStore::empty();
                for c in certs {
                    roots.add(c.clone()).map_err(|e| format!("tls: root: {e}"))?;
                }
                b.with_root_certificates(roots).with_no_client_auth()
            }
        }
    };
    c.alpn_protocols = alpn.iter().map(|a| a.to_vec()).collect();
    Ok(Arc::new(c))
}

/// The server name for SNI and the certificate check: a DNS name, or an IP
/// (rustls sends no SNI for IPs, like Go).
pub fn server_name(host: &str) -> Result<ServerName<'static>, String> {
    let h = host.trim_matches(|c| c == '[' || c == ']');
    ServerName::try_from(h.to_string()).map_err(|_| format!("tls: bad server name {}", crate::golike::quote(host)))
}

#[derive(Debug)]
struct NoVerify(Arc<CryptoProvider>);

impl ServerCertVerifier for NoVerify {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.0.signature_verification_algorithms.supported_schemes()
    }
}

#[cfg(test)]
pub(crate) mod testcert {
    //! A test CA and a leaf for dns.test and 127.0.0.1, valid to 2126,
    //! trusted only by tests that ask for it.

    use std::sync::Arc;

    use rustls::ServerConfig;
    use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};

    use super::Trust;

    pub const CA: &[u8] = include_bytes!("testdata/ca.der");
    pub const LEAF: &[u8] = include_bytes!("testdata/leaf.der");
    const KEY: &[u8] = include_bytes!("testdata/leaf.key.der");

    pub fn trust() -> Trust {
        Trust::Roots(vec![CertificateDer::from(CA.to_vec())])
    }

    pub fn server_config(alpn: &[&[u8]]) -> Arc<ServerConfig> {
        let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(KEY.to_vec()));
        let mut c = ServerConfig::builder_with_provider(super::provider())
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_no_client_auth()
            .with_single_cert(vec![CertificateDer::from(LEAF.to_vec())], key)
            .unwrap();
        c.alpn_protocols = alpn.iter().map(|a| a.to_vec()).collect();
        Arc::new(c)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The test certificate must be trusted by a client that asks for
    /// its CA, and refused by one that does not: every DoH and DoT test
    /// rests on this. The handshake runs over a pipe, never a socket,
    /// so a TLS-inspecting antivirus cannot re-sign the certificate
    /// (see `dns::pipe`).
    #[tokio::test]
    async fn the_test_ca_is_trusted_when_asked_for() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        async fn serve(c: tokio::io::DuplexStream) {
            let acceptor = tokio_rustls::TlsAcceptor::from(testcert::server_config(&[]));
            if let Ok(mut tls) = acceptor.accept(c).await {
                let _ = tls.write_all(b"hi").await;
                let _ = tls.flush().await;
            }
        }

        // a client that trusts the test CA gets through
        let (client, server) = tokio::io::duplex(16 * 1024);
        tokio::spawn(serve(server));
        let c = client_config(&testcert::trust(), false, &[]).unwrap();
        let r = tokio_rustls::TlsConnector::from(c).connect(server_name("dns.test").unwrap(), client).await;
        let mut tls = r.expect("the test CA was not trusted");
        let mut buf = [0u8; 2];
        tls.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"hi");

        // one that trusts only the system's roots does not
        let (client, server) = tokio::io::duplex(16 * 1024);
        tokio::spawn(serve(server));
        let c = client_config(&Trust::System, false, &[]).unwrap();
        let e = tokio_rustls::TlsConnector::from(c).connect(server_name("dns.test").unwrap(), client).await;
        assert!(e.is_err(), "the system must not trust the test CA");

        // and no-PKI mode checks nothing
        let (client, server) = tokio::io::duplex(16 * 1024);
        tokio::spawn(serve(server));
        let c = client_config(&Trust::System, true, &[]).unwrap();
        assert!(tokio_rustls::TlsConnector::from(c).connect(server_name("dns.test").unwrap(), client).await.is_ok());
    }

    #[test]
    fn configs() {
        let c = client_config(&testcert::trust(), false, &[b"h2", b"http/1.1"]).unwrap();
        assert_eq!(c.alpn_protocols, vec![b"h2".to_vec(), b"http/1.1".to_vec()]);
        assert!(client_config(&Trust::System, false, &[]).is_ok());
        assert!(client_config(&Trust::System, true, &[]).is_ok());
        assert!(server_name("dns.test").is_ok());
        assert!(server_name("127.0.0.1").is_ok());
        assert!(server_name("[::1]").is_ok());
        assert!(server_name("bad name").is_err());
    }
}
