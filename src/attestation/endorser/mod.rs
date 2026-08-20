// SPDX-License-Identifier: Apache-2.0

//! Endorser: endorsement material for attestation verification.
//!
//! SNP certificate chains are in [`snp`](self::snp). Legacy SEV chains are in
//! [`sev`](self::sev) (OpenSSL only), with platform certificate wire types under
//! [`sev::cert`](self::sev::cert).

#[cfg(all(
    feature = "snp",
    any(feature = "crypto-openssl", feature = "crypto-rust")
))]
pub mod snp;

#[cfg(all(feature = "sev", feature = "crypto-openssl"))]
pub mod sev;
