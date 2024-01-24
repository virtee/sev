// SPDX-License-Identifier: Apache-2.0

//! Operations for managing the SEV platform.
mod types;

pub use types::*;

#[cfg(target_os = "linux")]
use super::linux::host::{ioctl::*, types::GetId};

#[cfg(feature = "sev")]
#[cfg(target_os = "linux")]
use super::linux::host::types::{
    PdhCertExport, PdhGen, PekCertImport, PekCsr, PekGen, PlatformReset, PlatformStatus,
};

#[cfg(target_os = "linux")]
use crate::error::*;

#[cfg(feature = "sev")]
#[cfg(target_os = "linux")]
use crate::{
    certs::sev::sev::{Certificate, Chain},
    Build as CertBuild, Version as CertVersion,
};

#[cfg(target_os = "linux")]
use std::{
    fs::{File, OpenOptions},
    os::unix::io::{AsRawFd, RawFd},
};

#[cfg(feature = "sev")]
#[cfg(target_os = "linux")]
use std::mem::MaybeUninit;

#[cfg(feature = "snp")]
#[cfg(target_os = "linux")]
use std::convert::TryInto;

#[cfg(feature = "snp")]
#[cfg(target_os = "linux")]
use super::linux::host::types::SnpCommit;

/// The CPU-unique identifier for the platform.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Identifier(pub Vec<u8>);

impl From<Identifier> for Vec<u8> {
    fn from(id: Identifier) -> Vec<u8> {
        id.0
    }
}

impl std::fmt::Display for Identifier {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        for b in self.0.iter() {
            write!(f, "{b:02X}")?;
        }

        Ok(())
    }
}

/// A handle to the SEV platform.
#[cfg(target_os = "linux")]
pub struct Firmware(File);

#[cfg(target_os = "linux")]
impl Firmware {
    /// Create a handle to the SEV platform.
    pub fn open() -> std::io::Result<Firmware> {
        Ok(Firmware(
            OpenOptions::new().read(true).write(true).open("/dev/sev")?,
        ))
    }

    /// Reset the platform persistent state.
    #[cfg(feature = "sev")]
    pub fn platform_reset(&mut self) -> Result<(), Indeterminate<Error>> {
        PLATFORM_RESET.ioctl(&mut self.0, &mut Command::from(&PlatformReset))?;
        Ok(())
    }

    /// Query the platform status.
    #[cfg(feature = "sev")]
    pub fn platform_status(&mut self) -> Result<Status, Indeterminate<Error>> {
        let mut info: PlatformStatus = Default::default();
        PLATFORM_STATUS.ioctl(&mut self.0, &mut Command::from_mut(&mut info))?;

        Ok(Status {
            build: CertBuild {
                version: CertVersion {
                    major: info.version.major,
                    minor: info.version.minor,
                },
                build: info.build,
            },
            guests: info.guest_count,
            flags: info.flags,
            state: match info.state {
                0 => State::Uninitialized,
                1 => State::Initialized,
                2 => State::Working,
                _ => return Err(Indeterminate::Unknown),
            },
        })
    }

    /// Generate a new Platform Encryption Key (PEK).
    #[cfg(feature = "sev")]
    pub fn pek_generate(&mut self) -> Result<(), Indeterminate<Error>> {
        PEK_GEN.ioctl(&mut self.0, &mut Command::from(&PekGen))?;
        Ok(())
    }

    /// Request a signature for the PEK.
    #[cfg(feature = "sev")]
    pub fn pek_csr(&mut self) -> Result<Certificate, Indeterminate<Error>> {
        #[allow(clippy::uninit_assumed_init)]
        let mut pek: Certificate = unsafe { MaybeUninit::uninit().assume_init() };
        let mut csr = PekCsr::new(&mut pek);
        PEK_CSR.ioctl(&mut self.0, &mut Command::from_mut(&mut csr))?;

        Ok(pek)
    }

    /// Generate a new Platform Diffie-Hellman (PDH) key pair.
    #[cfg(feature = "sev")]
    pub fn pdh_generate(&mut self) -> Result<(), Indeterminate<Error>> {
        PDH_GEN.ioctl(&mut self.0, &mut Command::from(&PdhGen))?;
        Ok(())
    }

    /// Export the SEV certificate chain.
    #[cfg(feature = "sev")]
    pub fn pdh_cert_export(&mut self) -> Result<Chain, Indeterminate<Error>> {
        #[allow(clippy::uninit_assumed_init)]
        let mut chain: [Certificate; 3] = unsafe { MaybeUninit::uninit().assume_init() };
        #[allow(clippy::uninit_assumed_init)]
        let mut pdh: Certificate = unsafe { MaybeUninit::uninit().assume_init() };

        let mut pdh_cert_export = PdhCertExport::new(&mut pdh, &mut chain);
        PDH_CERT_EXPORT.ioctl(&mut self.0, &mut Command::from_mut(&mut pdh_cert_export))?;

        Ok(Chain {
            pdh,
            pek: chain[0],
            oca: chain[1],
            cek: chain[2],
        })
    }

    /// Take ownership of the SEV platform.
    #[cfg(feature = "sev")]
    pub fn pek_cert_import(
        &mut self,
        pek: &Certificate,
        oca: &Certificate,
    ) -> Result<(), Indeterminate<Error>> {
        let pek_cert_import = PekCertImport::new(pek, oca);
        PEK_CERT_IMPORT.ioctl(&mut self.0, &mut Command::from(&pek_cert_import))?;
        Ok(())
    }

    /// Get the unique CPU identifier.
    ///
    /// This is especially helpful for sending AMD an HTTP request to fetch
    /// the signed CEK certificate.
    #[cfg(any(feature = "sev", feature = "snp"))]
    pub fn get_identifier(&mut self) -> Result<Identifier, Indeterminate<Error>> {
        let mut bytes = [0u8; 64];
        let mut id = GetId::new(&mut bytes);

        GET_ID.ioctl(&mut self.0, &mut Command::from_mut(&mut id))?;

        Ok(Identifier(id.as_slice().to_vec()))
    }

    /// Query the SNP platform status.
    ///
    /// # Example:
    /// ```ignore
    /// use snp::firmware::host::*;
    ///
    /// let mut firmware: Firmware = Firmware::open().unwrap();
    ///
    /// let status: PlatformStatus = firmware.platform_status().unwrap();
    /// ```
    #[cfg(feature = "snp")]
    pub fn snp_platform_status(&mut self) -> Result<SnpPlatformStatus, Indeterminate<Error>> {
        let mut platform_status: SnpPlatformStatus = SnpPlatformStatus::default();

        SNP_PLATFORM_STATUS.ioctl(&mut self.0, &mut Command::from_mut(&mut platform_status))?;

        Ok(platform_status)
    }

    /// Commit the current SNP firmware
    ///
    /// # Example:
    /// ```ignore
    /// let mut firmware: Firmware = Firmware::open().unwrap();
    ///
    /// let status: bool = firmware.snp_commit().unwrap();
    /// ```
    #[cfg(feature = "snp")]
    pub fn snp_commit(&mut self) -> Result<(), UserApiError> {
        let mut buf: SnpCommit = Default::default();
        SNP_COMMIT.ioctl(&mut self.0, &mut Command::from_mut(&mut buf))?;

        Ok(())
    }

    /// Set the SNP Configuration.
    ///
    /// # Example:
    /// ```ignore
    /// let configuration = Config::new(
    ///     TcbVersion::new(3, 0, 10, 169),
    ///     0,
    /// );
    /// let mut firmware: Firmware = Firmware::open().unwrap();
    ///
    /// let status: bool = firmware.set_ext_config(configuration).unwrap();
    /// ```
    #[cfg(feature = "snp")]
    pub fn snp_set_config(&mut self, new_config: Config) -> Result<(), UserApiError> {

        SNP_SET_CONFIG.ioctl(&mut self.0, &mut Command::from_mut(&mut new_config.try_into()?))?;

        Ok(())
    }

    /// Start SNP configuration process
    ///
    /// # Example:
    /// ```ignore
    /// let mut firmware: Firmware = Firmware::open().unwrap();
    ///
    /// let config_id: configTransaction = firmware.snp_set_config_start().unwrap();
    /// ```
    #[cfg(feature = "snp")]
    pub fn snp_set_config_start(&mut self) -> Result<ConfigTransaction, UserApiError> {

        let mut config_start: FFI::types::SnpSetConfigStart = Default::default();

        SNP_SET_CONFIG_START.ioctl(&mut self.0, &mut Command::from_mut(&mut config_start))?;

        Ok(config_start.try_into()?)
    }

    /// End SNP configuration process
    ///
    /// # Example:
    /// ```ignore
    /// let mut firmware: Firmware = Firmware::open().unwrap();
    ///
    /// let start_config_id: configTransaction = firmware.snp_set_config_start().unwrap();
    /// 
    /// let end_config_id: configTransaction = firmware.snp_set_config_end().unwrap();
    /// 
    /// // if start and end error id's don't match, assume something process failed and start again. 
    /// if start_config_id != end_config_id {
    ///     Err(eprintln!("start id and end id don't match!""))
    /// }
    /// ```
    #[cfg(feature = "snp")]
    pub fn snp_set_config_end(&mut self) -> Result<ConfigTransaction, UserApiError> {
        
        let mut config_end: FFI::types::SnpSetConfigEnd = Default::default();

        SNP_SET_CONFIG_END.ioctl(&mut self.0, &mut Command::from_mut(&mut config_end))?;

        Ok(config_end.try_into()?)
    }
}

#[cfg(target_os = "linux")]
impl AsRawFd for Firmware {
    fn as_raw_fd(&self) -> RawFd {
        self.0.as_raw_fd()
    }
}
