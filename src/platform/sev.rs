// SPDX-License-Identifier: Apache-2.0

//! First-generation SEV host platform management.
//!
//! Extends [`crate::platform::Firmware`] with legacy SEV ioctls for platform
//! ownership and certificate provisioning. These operations use the PEK
//! (Platform Endorsement Key) and PDH (Platform Diffie-Hellman) workflow
//! defined in the AMD SEV API specification.
//!
//! Requires the `sev`, `platform`, `endorser`, and `verifier` features. Not used for SEV-SNP attestation
//! report verification — see [`crate::attestation::endorser::snp`] and
//! [`crate::attestation::verifier::snp`] for SNP endorsement material.
//!
//! # Certificate provisioning workflow
//!
//! ```text
//!  platform_reset (optional)
//!       │
//!  pek_generate ──► pek_csr ──► (sign externally) ──► pek_cert_import
//!       │
//!  pdh_generate ──► pdh_cert_export ──► Chain { pdh, pek, oca, cek }
//! ```
//!
//! # API summary
//!
//! | Method | Purpose |
//! |--------|---------|
//! | [`Firmware::platform_reset`] | Clear platform persistent state |
//! | [`Firmware::pek_generate`] | Generate a new PEK |
//! | [`Firmware::pek_csr`] | Obtain PEK certificate signing request |
//! | [`Firmware::pek_cert_import`] | Import signed PEK + OCA to take ownership |
//! | [`Firmware::pdh_generate`] | Generate a new PDH key pair |
//! | [`Firmware::pdh_cert_export`] | Export PDH and three-certificate chain |
//!
//! Shared ioctls ([`Firmware::get_identifier`], [`Firmware::platform_status`])
//! are on the base [`crate::platform::Firmware`] impl in [`super`].

pub use crate::types::sev::{PlatformStatusFlags, State, Status, Version};

#[cfg(target_os = "linux")]
use super::Firmware;

#[cfg(target_os = "linux")]
use crate::attestation::endorser::sev::cert::{Certificate, Chain};

#[cfg(target_os = "linux")]
use crate::error::*;

#[cfg(target_os = "linux")]
use crate::firmware::host::{
    ioctl::*,
    types::{PdhCertExport, PdhGen, PekCertImport, PekCsr, PekGen, PlatformReset},
};

#[cfg(target_os = "linux")]
use std::mem::MaybeUninit;

#[cfg(target_os = "linux")]
impl Firmware {
    /// Reset the platform's persistent state.
    ///
    /// Clears ownership and key material. Typically used during initial platform
    /// setup before PEK/PDH provisioning.
    pub fn platform_reset(&mut self) -> Result<(), UserApiError> {
        let mut cmd_buf = Command::from(&PlatformReset);
        PLATFORM_RESET
            .ioctl(&mut self.0, &mut cmd_buf)
            .map_err(|_| cmd_buf.encapsulate())?;
        Ok(())
    }

    /// Generate a new Platform Endorsement Key (PEK).
    ///
    /// Must be called before [`Self::pek_csr`] on a fresh or reset platform.
    pub fn pek_generate(&mut self) -> Result<(), UserApiError> {
        let mut cmd_buf = Command::from(&PekGen);
        PEK_GEN
            .ioctl(&mut self.0, &mut cmd_buf)
            .map_err(|_| cmd_buf.encapsulate())?;
        Ok(())
    }

    /// Export the PEK certificate signing request (CSR).
    ///
    /// Returns a legacy SEV [`Certificate`] to be signed by the platform owner
    /// (OCA). Import the signed result via [`Self::pek_cert_import`].
    pub fn pek_csr(&mut self) -> Result<Certificate, UserApiError> {
        #[allow(clippy::uninit_assumed_init)]
        let mut pek: Certificate = unsafe { MaybeUninit::uninit().assume_init() };
        let mut csr = PekCsr::new(&mut pek);
        let mut cmd_buf = Command::from_mut(&mut csr);
        PEK_CSR
            .ioctl(&mut self.0, &mut cmd_buf)
            .map_err(|_| cmd_buf.encapsulate())?;

        Ok(pek)
    }

    /// Generate a new Platform Diffie-Hellman (PDH) key pair.
    pub fn pdh_generate(&mut self) -> Result<(), UserApiError> {
        let mut cmd_buf = Command::from(&PdhGen);
        PDH_GEN
            .ioctl(&mut self.0, &mut cmd_buf)
            .map_err(|_| cmd_buf.encapsulate())?;
        Ok(())
    }

    /// Export the PDH and the platform certificate chain.
    ///
    /// Returns a [`Chain`] containing the PDH, PEK, OCA, and CEK certificates
    /// populated by the firmware.
    pub fn pdh_cert_export(&mut self) -> Result<Chain, UserApiError> {
        #[allow(clippy::uninit_assumed_init)]
        let mut chain: [Certificate; 3] = unsafe { MaybeUninit::uninit().assume_init() };
        #[allow(clippy::uninit_assumed_init)]
        let mut pdh: Certificate = unsafe { MaybeUninit::uninit().assume_init() };
        let mut pdh_cert_export = PdhCertExport::new(&mut pdh, &mut chain);
        let mut cmd_buf = Command::from_mut(&mut pdh_cert_export);

        PDH_CERT_EXPORT
            .ioctl(&mut self.0, &mut cmd_buf)
            .map_err(|_| cmd_buf.encapsulate())?;

        Ok(Chain {
            pdh,
            pek: chain[0],
            oca: chain[1],
            cek: chain[2],
        })
    }

    /// Import signed PEK and OCA certificates to take platform ownership.
    ///
    /// Joins the platform to a domain after the PEK CSR has been signed
    /// externally.
    pub fn pek_cert_import(
        &mut self,
        pek: &Certificate,
        oca: &Certificate,
    ) -> Result<(), UserApiError> {
        let pek_cert_import = PekCertImport::new(pek, oca);
        let mut cmd_buf = Command::from(&pek_cert_import);

        PEK_CERT_IMPORT
            .ioctl(&mut self.0, &mut cmd_buf)
            .map_err(|_| cmd_buf.encapsulate())?;
        Ok(())
    }
}
