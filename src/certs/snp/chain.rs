// SPDX-License-Identifier: Apache-2.0

use openssl::x509::X509;

use super::*;

use crate::firmware::host::{CertTableEntry, CertType};

/// Interfaces for a complete SEV-SNP certificate chain.

#[derive(Debug, Clone)]
pub struct Chain {
    /// The Certificate Authority (CA) chain.
    pub ca: ca::Chain,

    /// The Versioned Chip Endorsement Key or Versioned Loaded Endorsement Key.
    pub vek: Certificate,
}

impl<'a> Verifiable for &'a Chain {
    type Output = &'a Certificate;

    fn verify(self) -> Result<Self::Output> {
        // Verify that ARK is self-signed and ARK signs ASK.
        let ask = self.ca.verify()?;

        // Verify that ASK signs VCEK.
        (ask, &self.vek).verify()?;

        Ok(&self.vek)
    }
}

/// The format in which the FFI Certificate bytes are formatted.
enum ChainEncodingFormat {
    /// DER-encoded.
    Der,

    /// PEM-encoded.
    Pem,
}

impl From<(X509, X509, X509)> for Chain {
    /// Will presume the provided data is formated as (ASK,ARK,VCEK) or (ASVK,ARK,VLEK).
    fn from(value: (X509, X509, X509)) -> Self {
        Self {
            ca: ca::Chain {
                ark: value.1.into(),
                ask: value.0.into(),
            },
            vek: value.2.into(),
        }
    }
}

impl<'a: 'b, 'b> From<&'a Chain> for (&'b X509, &'b X509, &'b X509) {
    /// Will presume the provided data is formated as (ASK,ARK,VCEK) or (ASVK,ARK,VLEK).
    fn from(value: &'a Chain) -> Self {
        (&value.ca.ask.0, &value.ca.ark.0, &value.vek.0)
    }
}

impl From<(&X509, &X509, &X509)> for Chain {
    fn from(value: (&X509, &X509, &X509)) -> Self {
        (value.0.clone(), value.1.clone(), value.2.clone()).into()
    }
}

impl<'a: 'b, 'b> From<&'a Chain> for (&'b Certificate, &'b Certificate, &'b Certificate) {
    fn from(value: &'a Chain) -> Self {
        (&value.ca.ask, &value.ca.ark, &value.vek)
    }
}

impl From<(Certificate, Certificate, Certificate)> for Chain {
    fn from(value: (Certificate, Certificate, Certificate)) -> Self {
        value.into()
    }
}

impl From<(&Certificate, &Certificate, &Certificate)> for Chain {
    fn from(value: (&Certificate, &Certificate, &Certificate)) -> Self {
        value.into()
    }
}

impl From<&Chain> for (Certificate, Certificate, Certificate) {
    /// Will presume the user wants the format of (ASK,ARK,VCEK) or (ASVK,ARK,VLEK).
    fn from(value: &Chain) -> Self {
        (
            value.ca.ask.clone(),
            value.ca.ark.clone(),
            value.vek.clone(),
        )
    }
}

impl From<&[Certificate]> for Chain {
    /// Assumes the Format of ASK/ARK/VCEK or ASVK/ARK/VLEK. Any additional
    /// certificates are ignored.
    fn from(value: &[Certificate]) -> Self {
        (value[1].clone(), value[0].clone(), value[2].clone()).into()
    }
}

impl Chain {
    /// Derive a chain from a DER-encoded FFI Certificate table.
    pub fn from_cert_table_der(entries: Vec<CertTableEntry>) -> Result<Self> {
        Self::parse_from_cert_table(entries, ChainEncodingFormat::Der)
    }

    /// Derive a chain from a PEM-encoded FFI Certificate table.
    pub fn from_cert_table_pem(entries: Vec<CertTableEntry>) -> Result<Self> {
        Self::parse_from_cert_table(entries, ChainEncodingFormat::Pem)
    }

    /// Private function to parse the bytes. Used by both from_der() and from_pem().
    fn parse_from_cert_table(
        entries: Vec<CertTableEntry>,
        format: ChainEncodingFormat,
    ) -> Result<Self> {
        let mut ark: Option<Certificate> = None;
        let mut ask: Option<Certificate> = None;
        let mut vcek: Option<Certificate> = None;
        let mut vlek: Option<Certificate> = None;

        let other = ErrorKind::Other;

        // Traverse each certificate in the table, find the ARK, ASK, and VCEK.
        for entry in entries {
            let cert = match format {
                ChainEncodingFormat::Der => Certificate::from_der(entry.data.as_slice())?,
                ChainEncodingFormat::Pem => Certificate::from_pem(entry.data.as_slice())?,
            };

            match entry.cert_type {
                CertType::ARK => {
                    if ark.is_some() {
                        return Err(Error::new(other, "more than one ARK certificate found"));
                    }

                    ark = Some(cert);
                }
                CertType::ASK => {
                    if ask.is_some() {
                        return Err(Error::new(other, "more than one ASK certificate found"));
                    }

                    ask = Some(cert);
                }
                CertType::VCEK => {
                    if vcek.is_some() {
                        return Err(Error::new(other, "more than one VCEK certificate found"));
                    }

                    vcek = Some(cert);
                }
                CertType::VLEK => {
                    if vlek.is_some() {
                        return Err(Error::new(other, "more than one VLEK certificate found"));
                    }

                    vlek = Some(cert);
                }
                _ => continue,
            }
        }

        // Chain cannot be built without ARK, ASK, and VCEK.
        if ark.is_none() {
            return Err(Error::new(other, "ARK not found"));
        } else if ask.is_none() {
            return Err(Error::new(other, "ASK not found"));
        } else if vcek.is_none() && vlek.is_none() {
            return Err(Error::new(other, "VCEK/VLEK not found"));
        }

        // Use the VLEK whenever it is present, but use the VCEK when VLEK is missing.
        let vek_val = match (vcek, vlek) {
            (_, Some(vlek)) => vlek,
            (Some(vcek), None) => vcek,
            _ => unreachable!(),
        };

        Ok(Self {
            ca: ca::Chain {
                ark: ark.unwrap(),
                ask: ask.unwrap(),
            },
            vek: vek_val,
        })
    }

    /// Deserialize a PEM-encoded ARK, ASK, and VEK to a SEV-SNP chain.
    pub fn from_pem(ark: &[u8], ask: &[u8], vek: &[u8]) -> Result<Self> {
        Ok(Self {
            ca: ca::Chain::from_pem(ark, ask)?,
            vek: Certificate::from_pem(vek)?,
        })
    }

    /// Deserialize a DER-encoded ARK, ASK, and VEK to a SEV-SNP chain.
    pub fn from_der(ark: &[u8], ask: &[u8], vek: &[u8]) -> Result<Self> {
        Ok(Self {
            ca: ca::Chain::from_der(ark, ask)?,
            vek: Certificate::from_der(vek)?,
        })
    }
}
