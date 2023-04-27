// SPDX-License-Identifier: Apache-2.0

//! Operations for managing the SEV platform.
mod types;

pub use types::*;

use std::convert::TryInto;
use std::fs::{File, OpenOptions};
use std::mem::MaybeUninit;
use std::os::unix::io::{AsRawFd, RawFd};

use crate::error::*;
use crate::{
    certs::sev::sev::{Certificate, Chain},
    Build, Version,
};

use super::linux::host::{
    ioctl::*,
    types::{
        GetId, PdhCertExport, PdhGen, PekCertImport, PekCsr, PekGen, PlatformReset, PlatformStatus,
    },
};

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
pub struct Firmware(File);

impl Firmware {
    /// Create a handle to the SEV platform.
    pub fn open() -> std::io::Result<Firmware> {
        Ok(Firmware(
            OpenOptions::new().read(true).write(true).open("/dev/sev")?,
        ))
    }

    /// Reset the platform persistent state.
    pub fn platform_reset(&mut self) -> Result<(), Indeterminate<Error>> {
        PLATFORM_RESET.ioctl(&mut self.0, &mut Command::from(&PlatformReset))?;
        Ok(())
    }

    /// Query the platform status.
    pub fn platform_status(&mut self) -> Result<Status, Indeterminate<Error>> {
        let mut info: PlatformStatus = Default::default();
        PLATFORM_STATUS.ioctl(&mut self.0, &mut Command::from_mut(&mut info))?;

        Ok(Status {
            build: Build {
                version: Version {
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
    pub fn pek_generate(&mut self) -> Result<(), Indeterminate<Error>> {
        PEK_GEN.ioctl(&mut self.0, &mut Command::from(&PekGen))?;
        Ok(())
    }

    /// Request a signature for the PEK.
    pub fn pek_csr(&mut self) -> Result<Certificate, Indeterminate<Error>> {
        #[allow(clippy::uninit_assumed_init)]
        let mut pek: Certificate = unsafe { MaybeUninit::uninit().assume_init() };
        let mut csr = PekCsr::new(&mut pek);
        PEK_CSR.ioctl(&mut self.0, &mut Command::from_mut(&mut csr))?;

        Ok(pek)
    }

    /// Generate a new Platform Diffie-Hellman (PDH) key pair.
    pub fn pdh_generate(&mut self) -> Result<(), Indeterminate<Error>> {
        PDH_GEN.ioctl(&mut self.0, &mut Command::from(&PdhGen))?;
        Ok(())
    }

    /// Export the SEV certificate chain.
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
    pub fn snp_platform_status(&mut self) -> Result<SnpPlatformStatus, Indeterminate<Error>> {
        let mut platform_status: SnpPlatformStatus = SnpPlatformStatus::default();

        SNP_PLATFORM_STATUS.ioctl(&mut self.0, &mut Command::from_mut(&mut platform_status))?;

        Ok(platform_status)
    }

    /// Reset the configuration of the AMD secure processor. Useful for resetting the committed_tcb.
    /// # Example:
    /// ```ignore
    /// use snp::firmware::host::*;
    ///
    /// let mut firmware: Firmware = Firmware::open().unwrap();
    ///
    /// firmware.reset_config().unwrap();
    /// ```
    pub fn snp_reset_config(&mut self) -> Result<(), UserApiError> {
        let mut config: FFI::types::SnpSetExtConfig = FFI::types::SnpSetExtConfig {
            config_address: 0,
            certs_address: 0,
            certs_len: 0,
        };

        SNP_SET_EXT_CONFIG.ioctl(&mut self.0, &mut Command::from_mut(&mut config))?;

        Ok(())
    }
    /// Fetch the SNP Extended Configuration.
    ///
    /// # Example:
    /// ```ignore
    /// let mut firmware: Firmware = Firmware::open().unwrap();
    ///
    /// let status: ExtConfig = firmware.get_ext_config().unwrap();
    /// ```
    pub fn snp_get_ext_config(&mut self) -> Result<ExtConfig, UserApiError> {
        let mut raw_buf: Vec<u8> = vec![0; _4K_PAGE];
        let mut config = FFI::types::SnpGetExtConfig {
            config_address: 0,
            certs_address: raw_buf.as_mut_ptr() as *mut CertTableEntry as u64,
            certs_len: _4K_PAGE as u32,
        };

        SNP_GET_EXT_CONFIG
            .ioctl(&mut self.0, &mut Command::from_mut(&mut config))
            .or_else(|err| {
                // If the error occurred because the buffer was to small, it will have changed
                // the buffer. If it has, we will attempt to resize it.
                if config.certs_len <= _4K_PAGE as u32 {
                    return Err(err);
                }

                raw_buf = vec![0; config.certs_len as usize];
                config.certs_address = raw_buf.as_ptr() as *const CertTableEntry as u64;
                SNP_GET_EXT_CONFIG.ioctl(&mut self.0, &mut Command::from_mut(&mut config))
            })?;

        config.try_into().map_err(|op: uuid::Error| op.into())
    }

    /// Set the SNP Extended Configuration.
    ///
    /// # Example:
    /// ```ignore
    /// pub const ARK: &[u8] = include_bytes!("../../certs/builtin/milan/ark.pem");
    /// pub const ASK: &[u8] = include_bytes!("../../certs/builtin/genoa/ask.pem");
    /// pub const VCEK: &[u8] = include_bytes!("vcek.pem");
    ///
    /// let configuration = Config::new(
    ///     TcbVersion::new(3, 0, 10, 169),
    ///     0,
    /// );
    ///
    /// // Generate a vector of certificates to store in hypervisor memory.
    /// let certificates = vec![
    ///     CertTableEntry::new(CertType::ARK, ARK.to_vec()),
    ///     CertTableEntry::new(CertType::ASK, ASK.to_vec()),
    ///     CertTableEntry::new(CertType::VCEK, VCEK.to_vec()),
    /// ];
    ///
    /// // Call the `new` constructor to generate the extended configuration.
    /// let ext_config: ExtConfig = ExtConfig::new(configuration, certificates);
    ///
    /// let mut firmware: Firmware = Firmware::open().unwrap();
    ///
    /// let status: bool = firmware.set_ext_config(ext_config).unwrap();
    /// ```
    pub fn snp_set_ext_config(&mut self, mut new_config: ExtConfig) -> Result<(), UserApiError> {
        let mut bytes: Vec<u8> = vec![];

        if let Some(ref mut certificates) = new_config.certs {
            bytes = FFI::types::CertTableEntry::uapi_to_vec_bytes(certificates)?;
        }

        let mut new_ext_config: FFI::types::SnpSetExtConfig = new_config.try_into()?;
        new_ext_config.certs_address = bytes.as_mut_ptr() as u64;

        SNP_SET_EXT_CONFIG.ioctl(&mut self.0, &mut Command::from_mut(&mut new_ext_config))?;

        Ok(())
    }
}

impl AsRawFd for Firmware {
    fn as_raw_fd(&self) -> RawFd {
        self.0.as_raw_fd()
    }
}
