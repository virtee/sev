// SPDX-License-Identifier: Apache-2.0

//! Legacy SEV host ioctl payload layouts.
//!
//! Structures for first-generation SEV platform key provisioning ioctls:
//! Platform Endorsement Key (PEK) and Platform Diffie-Hellman (PDH) operations.
//!
//! Requires the `sev`, `platform`, `endorser`, and `verifier` features. Public wrappers are in
//! [`crate::platform::sev`].
//!
//! Shared legacy/SNP payloads ([`PlatformStatus`], [`GetId`]) live in
//! [`super::shared`].

#[cfg(target_os = "linux")]
use crate::attestation::endorser::sev::cert;

#[cfg(target_os = "linux")]
use std::marker::PhantomData;

/// Platform reset payload (no fields).
///
/// Used by the legacy-only `PLATFORM_RESET` ioctl. See AMD SEV API specification
/// chapter 5.5.
#[cfg(target_os = "linux")]
pub struct PlatformReset;

/// Generate a new Platform Endorsement Key (PEK).
///
/// See AMD SEV API specification chapter 5.7.
#[cfg(target_os = "linux")]
pub struct PekGen;

/// Request PEK certificate signing (CSR) payload.
///
/// Points at a legacy SEV [`Certificate`](crate::attestation::endorser::sev::cert::Certificate)
/// buffer the kernel fills. See chapter 5.8, table 27.
#[repr(C, packed)]
#[cfg(target_os = "linux")]
pub struct PekCsr<'a> {
    addr: u64,
    len: u32,
    _phantom: PhantomData<&'a ()>,
}

#[cfg(target_os = "linux")]
impl<'a> PekCsr<'a> {
    /// Build a CSR payload referencing a certificate buffer.
    pub fn new(cert: &'a mut cert::Certificate) -> Self {
        Self {
            addr: cert as *mut _ as _,
            len: std::mem::size_of_val(cert) as _,
            _phantom: PhantomData,
        }
    }
}

/// Import PEK and OCA certificates to join the platform to a domain.
///
/// See AMD SEV API specification chapter 5.9, table 29.
#[cfg(target_os = "linux")]
#[repr(C, packed)]
pub struct PekCertImport<'a> {
    pek_addr: u64,
    pek_len: u32,
    oca_addr: u64,
    oca_len: u32,
    _phantom: PhantomData<&'a ()>,
}

#[cfg(target_os = "linux")]
impl<'a> PekCertImport<'a> {
    /// Build an import payload from PEK and OCA certificate buffers.
    pub fn new(pek: &'a cert::Certificate, oca: &'a cert::Certificate) -> Self {
        Self {
            pek_addr: pek as *const _ as _,
            pek_len: std::mem::size_of_val(pek) as _,
            oca_addr: oca as *const _ as _,
            oca_len: std::mem::size_of_val(oca) as _,
            _phantom: PhantomData,
        }
    }
}

/// (Re)generate the Platform Diffie-Hellman (PDH) key.
///
/// See AMD SEV API specification chapter 5.10.
#[cfg(target_os = "linux")]
pub struct PdhGen;

/// Export PDH and platform certificate chain payload.
///
/// See AMD SEV API specification chapter 5.11.
#[cfg(target_os = "linux")]
#[repr(C, packed)]
pub struct PdhCertExport<'a> {
    pdh_addr: u64,
    pdh_len: u32,
    certs_addr: u64,
    certs_len: u32,
    _phantom: PhantomData<&'a ()>,
}

#[cfg(target_os = "linux")]
impl<'a> PdhCertExport<'a> {
    /// Build an export payload referencing PDH and a three-certificate chain buffer.
    pub fn new(pdh: &'a mut cert::Certificate, certs: &'a mut [cert::Certificate; 3]) -> Self {
        Self {
            pdh_addr: pdh as *mut _ as _,
            pdh_len: std::mem::size_of_val(pdh) as _,
            certs_addr: certs.as_mut_ptr() as _,
            certs_len: std::mem::size_of_val(certs) as _,
            _phantom: PhantomData,
        }
    }
}
