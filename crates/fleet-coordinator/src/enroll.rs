//! Coordinator-side bootstrap enrollment.
//!
//! Bootstrap enrollment lets an agent or client obtain a CA-signed client
//! certificate using a one-time secret. The secret is validated and consumed
//! (single-use + TTL) against the `SQLite` store; the client's locally-generated
//! CSR is then signed with the coordinator's built-in client CA. The issued
//! cert's fingerprint is recorded as a DB-backed agent pin so the manual
//! `[pinned_agents]` edit disappears.
//!
//! Runtime authentication is unchanged: the issued client certificate is used
//! for full mTLS, exactly as before.

use std::sync::Arc;

use rcgen::{
    CertificateParams, CertificateSigningRequestParams, DnType, ExtendedKeyUsagePurpose,
    KeyUsagePurpose,
};
use rustls::pki_types::CertificateDer;

use fleet_proto::enroll::{EnrollRequest, EnrollResponse};

use crate::core::Coordinator;
use crate::error::{CoordinatorError, Result};

/// Compute the lowercase-hex SHA-256 of a secret (the stored credential).
#[must_use]
pub fn hash_secret(secret: &[u8; 32]) -> String {
    use sha2::{Digest, Sha256};
    let digest = Sha256::digest(secret);
    let mut out = String::with_capacity(digest.len() * 2);
    for byte in digest {
        use std::fmt::Write as _;
        let _ = write!(out, "{byte:02x}");
    }
    out
}

/// Sign a client CSR with the client CA, overriding the subject so the issued
/// cert's CN is `principal` and it carries the `ClientAuth` EKU.
///
/// Returns the issued leaf certificate (PEM).
///
/// # Errors
///
/// Returns [`CoordinatorError::Config`] if the CA material cannot be parsed or
/// signing fails.
pub fn sign_csr(
    csr_pem: &str,
    principal: &str,
    ca_cert_pem: &str,
    ca_key_pem: &str,
) -> Result<String> {
    let ca_params = CertificateParams::from_ca_cert_pem(ca_cert_pem)
        .map_err(|e| CoordinatorError::Config(format!("parsing client CA cert: {e}")))?;
    let ca_key = rcgen::KeyPair::from_pem(ca_key_pem)
        .map_err(|e| CoordinatorError::Config(format!("parsing client CA key: {e}")))?;
    let issuer = ca_params
        .self_signed(&ca_key)
        .map_err(|e| CoordinatorError::Config(format!("reconstructing issuer from CA: {e}")))?;

    let mut csr = CertificateSigningRequestParams::from_pem(csr_pem)
        .map_err(|e| CoordinatorError::Protocol(format!("parsing CSR: {e}")))?;

    // The coordinator controls identity, not the client: override the subject.
    csr.params.distinguished_name = rcgen::DistinguishedName::new();
    csr.params
        .distinguished_name
        .push(DnType::CommonName, principal);
    // A DNS SAN matching the principal keeps `principal_from_cert` /
    // `agent_id_from_cert` (which fall back to the first DNS SAN) consistent.
    if let Ok(san) = principal.to_owned().try_into() {
        csr.params.subject_alt_names = vec![rcgen::SanType::DnsName(san)];
    }
    csr.params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
    csr.params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ClientAuth];

    let cert = csr
        .signed_by(&issuer, &ca_key)
        .map_err(|e| CoordinatorError::Config(format!("signing CSR with client CA: {e}")))?;
    Ok(cert.pem())
}

/// Handle a bootstrap [`EnrollRequest`]: validate + consume the secret, sign
/// the CSR, auto-pin the issued cert, and return an [`EnrollResponse`].
pub async fn handle_enroll(coord: &Arc<Coordinator>, req: EnrollRequest) -> EnrollResponse {
    match handle_enroll_inner(coord, req).await {
        Ok(resp) => resp,
        Err(e) => EnrollResponse::Rejected {
            reason: e.to_string(),
        },
    }
}

async fn handle_enroll_inner(
    coord: &Arc<Coordinator>,
    req: EnrollRequest,
) -> Result<EnrollResponse> {
    let secret_hash = hash_secret(&req.secret);
    let now = i64::try_from(coord.now()).unwrap_or(i64::MAX);

    let Some((principal, kind)) = coord.db().consume_enroll_token(&secret_hash, now).await? else {
        return Ok(EnrollResponse::Rejected {
            reason: "invalid, expired, or already-used enrollment secret".to_owned(),
        });
    };

    let ca_cert_pem = std::fs::read_to_string(&coord.config().client_ca)
        .map_err(|e| CoordinatorError::Config(format!("reading client CA cert: {e}")))?;
    let ca_key_pem = std::fs::read_to_string(&coord.config().client_ca_key)
        .map_err(|e| CoordinatorError::Config(format!("reading client CA key: {e}")))?;

    let client_cert_pem = sign_csr(&req.csr_pem, &principal, &ca_cert_pem, &ca_key_pem)?;

    // Auto-pin agents by the issued cert's fingerprint so the manual
    // `[pinned_agents]` edit is unnecessary. (Non-agent clients are not pinned.)
    if kind == "agent" {
        let der = first_cert_der(&client_cert_pem)?;
        let fingerprint = fleet_tls::cert_fingerprint(&der);
        coord
            .db()
            .insert_agent_pin(&fingerprint, &principal, now)
            .await?;
    }

    let coordinator_token_pubkey = hex32(&coord.signer().public_key_bytes());

    Ok(EnrollResponse::Accepted {
        client_cert_pem,
        ca_cert_pem,
        coordinator_token_pubkey,
    })
}

/// Parse the first certificate's DER out of a PEM string.
fn first_cert_der(pem: &str) -> Result<CertificateDer<'static>> {
    let mut reader = std::io::BufReader::new(pem.as_bytes());
    let first = rustls_pemfile::certs(&mut reader)
        .next()
        .ok_or_else(|| CoordinatorError::Config("issued cert PEM had no certificate".to_owned()))?
        .map_err(|e| CoordinatorError::Config(format!("parsing issued cert PEM: {e}")))?;
    Ok(first)
}

/// Lowercase-hex encode a 32-byte array.
fn hex32(bytes: &[u8; 32]) -> String {
    let mut out = String::with_capacity(64);
    for byte in bytes {
        use std::fmt::Write as _;
        let _ = write!(out, "{byte:02x}");
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use rcgen::{BasicConstraints, IsCa, KeyPair};

    fn mint_ca() -> (String, String) {
        let mut ca_params = CertificateParams::new(Vec::<String>::new()).unwrap();
        ca_params
            .distinguished_name
            .push(DnType::CommonName, "probe-rs-fleet client CA");
        ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        ca_params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
        let ca_key = KeyPair::generate().unwrap();
        let ca_cert = ca_params.self_signed(&ca_key).unwrap();
        (ca_cert.pem(), ca_key.serialize_pem())
    }

    fn make_csr() -> String {
        let key = KeyPair::generate().unwrap();
        CertificateParams::default()
            .serialize_request(&key)
            .unwrap()
            .pem()
            .unwrap()
    }

    #[test]
    fn hash_secret_is_64_hex() {
        let h = hash_secret(&[0u8; 32]);
        assert_eq!(h.len(), 64);
        assert!(h.chars().all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase()));
    }

    #[test]
    fn signed_csr_cn_maps_to_principal() {
        let (ca_cert, ca_key) = mint_ca();
        let csr = make_csr();
        let leaf_pem = sign_csr(&csr, "rpi-lab-1", &ca_cert, &ca_key).unwrap();
        let der = first_cert_der(&leaf_pem).unwrap();
        let agent_id = fleet_tls::agent_id_from_cert(&der).unwrap();
        assert_eq!(agent_id.0, "rpi-lab-1");
    }
}
