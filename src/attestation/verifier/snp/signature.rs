// SPDX-License-Identifier: Apache-2.0

//! Attestation report signature verification by algorithm.
//!
//! Dispatches report signature checks based on the [`SignatureAlgorithm`] field
//! embedded in the report body. The algorithm value comes from **untrusted**
//! report bytes; a successful verification confirms authenticity of the signed
//! body but does not, by itself, validate other report fields.
//!
//! For most callers, prefer the higher-level impls in [`super::report`] that
//! assemble `(algorithm, body, signature, vek)` from a parsed
//! [`Report`](crate::attestation::evidence::snp::Report).

use crate::attestation::endorser::snp::Certificate;
use crate::attestation::evidence::snp::SignatureAlgorithm;
use crate::attestation::verifier::Verifiable;

use super::ecdsa;

use std::io::Result;

/// Verify an attestation report signature over its signed body using a VEK.
///
/// The tuple `(algorithm, body, signature, vek)` carries the inputs for
/// low-level SEV-SNP report signature verification:
///
/// - `algorithm`: [`SignatureAlgorithm`] read from the report body
/// - `body`: bytes covered by the report signature (offsets `0x00`..=`0x29F`)
/// - `signature`: firmware-provided signature bytes (offsets `0x2A0`..=`0x49F`)
/// - `vek`: the Versioned Endorsement Key ([`Certificate`]) whose public key
///   verifies the signature
///
/// The algorithm field comes from **untrusted** report bytes. It selects the
/// verification path but does not, by itself, establish authenticity. A
/// successful verification confirms that `body` was signed by the holder of
/// `vek`'s private key.
///
/// `vek` should be a trusted endorsement key, typically obtained after
/// validating a certificate chain via [`super::chain`].
impl Verifiable for (SignatureAlgorithm, &[u8], &[u8], &Certificate) {
    type Output = ();

    fn verify(self) -> Result<Self::Output> {
        let (algorithm, body, signature, vek) = self;
        match algorithm {
            SignatureAlgorithm::EcdsaSecp384r1 => {
                ecdsa::verify_ecdsa_signature(body, signature, vek)
            }
        }
    }
}
