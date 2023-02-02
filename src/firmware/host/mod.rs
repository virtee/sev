// SPDX-License-Identifier: Apache-2.0

//! Operations for managing the SEV platform.
pub mod types;

use std::fs::{File, OpenOptions};
use std::mem::MaybeUninit;
use std::os::unix::io::{AsRawFd, RawFd};

use crate::{
    certs::{self, sev::Certificate},
    Build, SnpBuild, Version,
};
use types::*;

use super::linux::guest::types::_4K_PAGE;
use super::linux::host::{ioctl::*, types::CertTableEntry as FFICertTableEntry, types::*};

pub use super::linux::host::types::PlatformStatusFlags;

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
    pub fn pdh_cert_export(&mut self) -> Result<certs::sev::Chain, Indeterminate<Error>> {
        #[allow(clippy::uninit_assumed_init)]
        let mut chain: [Certificate; 3] = unsafe { MaybeUninit::uninit().assume_init() };
        #[allow(clippy::uninit_assumed_init)]
        let mut pdh: Certificate = unsafe { MaybeUninit::uninit().assume_init() };

        let mut pdh_cert_export = PdhCertExport::new(&mut pdh, &mut chain);
        PDH_CERT_EXPORT.ioctl(&mut self.0, &mut Command::from_mut(&mut pdh_cert_export))?;

        Ok(certs::sev::Chain {
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
    pub fn snp_platform_status(&mut self) -> Result<SnpStatus, Indeterminate<Error>> {
        let mut info: SnpPlatformStatus = Default::default();
        SNP_PLATFORM_STATUS.ioctl(&mut self.0, &mut Command::from_mut(&mut info))?;

        Ok(SnpStatus {
            build: SnpBuild {
                version: Version {
                    major: info.version.major,
                    minor: info.version.minor,
                },
                build: info.build_id,
            },
            guests: info.guest_count,
            tcb: SnpTcbStatus {
                platform_version: info.platform_tcb_version,
                reported_version: info.reported_tcb_version,
            },
            is_rmp_init: info.is_rmp_init == 1,
            mask_chip_id: info.mask_chip_id == 1,
            state: match info.state {
                0 => State::Uninitialized,
                1 => State::Initialized,
                // SNP platforms cannot be in the 'Working' State.
                _ => return Err(Indeterminate::Unknown),
            },
        })
    }

    /// Fetch the SNP Extended Configuration.
    pub fn snp_get_ext_config(&mut self) -> Result<SnpExtConfig, UserApiError> {
        let mut raw_buf: Vec<u8> = vec![0; _4K_PAGE];
        let mut config: SnpGetExtConfig = SnpGetExtConfig {
            config_address: 0,
            certs_address: raw_buf.as_mut_ptr() as *mut FFICertTableEntry as u64,
            certs_len: _4K_PAGE as u32,
        };
        if let Err(error) =
            SNP_GET_EXT_CONFIG.ioctl(&mut self.0, &mut Command::from_mut(&mut config))
        {
            // If the error occurred because the buffer was to small, it will have changed the
            // buffer. If it has, we will attempt to resize it.
            if config.certs_len > _4K_PAGE as u32 {
                raw_buf = vec![0; config.certs_len as usize];
                config.certs_address = raw_buf.as_mut_ptr() as *mut FFICertTableEntry as u64;

                SNP_GET_EXT_CONFIG.ioctl(&mut self.0, &mut Command::from_mut(&mut config))?;
            } else {
                return Err(error.into());
            }
        }

        match config.as_uapi() {
            Ok(config) => Ok(config),
            Err(error) => Err(error.into()),
        }
    }

    /// Set the SNP Extended Configuration.
    pub fn snp_set_ext_config(&mut self, new_config: &SnpExtConfig) -> Result<(), UserApiError> {
        let mut bytes: Vec<u8> = vec![];
        let mut config: SnpSetExtConfig = SnpSetExtConfig::from_uapi(new_config, &mut bytes)?;

        SNP_SET_EXT_CONFIG.ioctl(&mut self.0, &mut Command::from_mut(&mut config))?;
        Ok(())
    }
}

impl AsRawFd for Firmware {
    fn as_raw_fd(&self) -> RawFd {
        self.0.as_raw_fd()
    }
}
