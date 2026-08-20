// SPDX-License-Identifier: Apache-2.0

//! AMD Root Key (ARK) and AMD Signing Key (ASK) pair.
//!
//! [`CaChain`] holds the platform CA certificates that endorse the per-chip
//! VCEK/VLEK. Use [`CaChain::from_pem`] / [`CaChain::from_der`] with files, or
//! build from a PEM stack with [`CaChain::from_pem_bytes`] (OpenSSL). Combine
//! with a VCEK/VLEK in [`Chain`](super::Chain).

use super::*;

/// AMD Root Key and AMD Signing Key certificates.
///
/// Tuple conversions assume **(ASK, ARK)** order — signing key first, root second.
/// This matches firmware certificate table ordering and OpenSSL stack conventions.
#[derive(Clone, Debug)]
pub struct CaChain {
    /// AMD Root Key (self-signed platform root).
    pub ark: Certificate,

    /// AMD Signing Key (signs VCEK/VLEK certificates).
    pub ask: Certificate,
}

#[cfg(feature = "crypto-openssl")]
use openssl::x509::X509;

#[cfg(feature = "crypto-rust")]
use x509_cert::Certificate as X509Certificate;

#[cfg(feature = "crypto-openssl")]
impl From<(X509, X509)> for CaChain {
    /// Assumes the structure of ASK/ARK or ASVK/ARK
    fn from(value: (X509, X509)) -> Self {
        Self {
            ark: value.1.into(),
            ask: value.0.into(),
        }
    }
}

#[cfg(feature = "crypto-openssl")]
impl From<(&X509, &X509)> for CaChain {
    /// Assumes the structure of &ASK/&ARK or &ASVK/&ARK
    fn from(value: (&X509, &X509)) -> Self {
        (value.0.clone(), value.1.clone()).into()
    }
}

#[cfg(feature = "crypto-openssl")]
impl<'a: 'b, 'b> From<&'a CaChain> for (&'b X509, &'b X509) {
    /// Will always assume the tuple type to be (&ASK, &ARK) or (&ASVK, &ARK).
    fn from(value: &'a CaChain) -> Self {
        ((&value.ask).into(), (&value.ark).into())
    }
}

#[cfg(feature = "crypto-openssl")]
impl From<&[X509]> for CaChain {
    /// Will only retrieve the first two certificates, ignoring the rest. Also
    /// assumes the structure to be (&ASK, &ARK) or (&ASVK, &ARK)
    fn from(value: &[X509]) -> Self {
        (&value[0], &value[1]).into()
    }
}

#[cfg(feature = "crypto-rust")]
impl From<(X509Certificate, X509Certificate)> for CaChain {
    /// Assumes the structure of ASK/ARK or ASVK/ARK
    fn from(value: (X509Certificate, X509Certificate)) -> Self {
        Self {
            ark: value.1.into(),
            ask: value.0.into(),
        }
    }
}

#[cfg(feature = "crypto-rust")]
impl From<(&X509Certificate, &X509Certificate)> for CaChain {
    /// Assumes the structure of &ASK/&ARK or &ASVK/&ARK
    fn from(value: (&X509Certificate, &X509Certificate)) -> Self {
        (value.0.clone(), value.1.clone()).into()
    }
}

#[cfg(feature = "crypto-rust")]
impl<'a: 'b, 'b> From<&'a CaChain> for (&'b X509Certificate, &'b X509Certificate) {
    /// Will always assume the tuple type to be (&ASK, &ARK) or (&ASVK, &ARK).
    fn from(value: &'a CaChain) -> Self {
        ((&value.ask).into(), (&value.ark).into())
    }
}

#[cfg(feature = "crypto-rust")]
impl From<&[X509Certificate]> for CaChain {
    /// Will only retrieve the first two certificates, ignoring the rest. Also
    /// assumes the structure to be (&ASK, &ARK) or (&ASVK, &ARK)
    fn from(value: &[X509Certificate]) -> Self {
        (&value[0], &value[1]).into()
    }
}

impl From<(Certificate, Certificate)> for CaChain {
    /// Assumes the structure of ASK/ARK or ASVK/ARK
    fn from(value: (Certificate, Certificate)) -> Self {
        Self {
            ark: value.1,
            ask: value.0,
        }
    }
}

impl From<(&Certificate, &Certificate)> for CaChain {
    /// Assumes the structure of &ASK/&ARK or &ASVK/&ARK
    fn from(value: (&Certificate, &Certificate)) -> Self {
        Self {
            ark: value.1.clone(),
            ask: value.0.clone(),
        }
    }
}

impl<'a: 'b, 'b> From<&'a CaChain> for (&'b Certificate, &'b Certificate) {
    /// Will always assume the tuple type to be (&ASK, &ARK) or (&ASVK, &ARK).
    fn from(value: &'a CaChain) -> Self {
        (&value.ask, &value.ark)
    }
}

impl From<&[Certificate]> for CaChain {
    /// Will only retrieve the first two certificates, ignoring the rest. Also
    /// assumes the structure to be (&ASK, &ARK) or (&ASVK, &ARK)
    fn from(value: &[Certificate]) -> Self {
        (&value[0], &value[1]).into()
    }
}

impl CaChain {
    /// Build a CA chain from separate PEM-encoded ARK and ASK files or buffers.
    ///
    /// # Arguments
    ///
    /// * `ark` — PEM bytes for the AMD Root Key certificate.
    /// * `ask` — PEM bytes for the AMD Signing Key certificate.
    pub fn from_pem(ark: &[u8], ask: &[u8]) -> Result<Self> {
        Ok(Self {
            ark: Certificate::from_pem(ark)?,
            ask: Certificate::from_pem(ask)?,
        })
    }

    /// Build a CA chain from separate DER-encoded ARK and ASK buffers.
    pub fn from_der(ark: &[u8], ask: &[u8]) -> Result<Self> {
        Ok(Self {
            ark: Certificate::from_der(ark)?,
            ask: Certificate::from_der(ask)?,
        })
    }

    #[cfg(feature = "crypto-openssl")]
    /// Build a CA chain from a PEM stack containing ASK then ARK.
    ///
    /// Uses OpenSSL `stack_from_pem`. Index `0` is ASK, index `1` is ARK; any
    /// additional certificates are ignored.
    pub fn from_pem_bytes(stack: &[u8]) -> Result<Self> {
        let certificates = X509::stack_from_pem(stack)?;
        let ark_cert = &certificates[1];
        let ask_cert = &certificates[0];
        Ok(Self {
            ark: ark_cert.into(),
            ask: ask_cert.into(),
        })
    }
}
