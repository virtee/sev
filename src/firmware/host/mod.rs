// SPDX-License-Identifier: Apache-2.0

//! Operations for managing the SEV platform.
mod types;
pub use types::*;

#[cfg(feature = "snp")]
use crate::Generation;

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
use crate::certs::sev::sev::{Certificate, Chain};

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

#[cfg(all(target_os = "linux", feature = "snp"))]
use super::linux::host::types::{SnpPlatformStatus as FFISnpPlatformStatus, SnpSetConfig};

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
    pub fn platform_reset(&mut self) -> Result<(), UserApiError> {
        let mut cmd_buf = Command::from(&PlatformReset);
        PLATFORM_RESET
            .ioctl(&mut self.0, &mut cmd_buf)
            .map_err(|_| cmd_buf.encapsulate())?;
        Ok(())
    }

    /// Query the platform status.
    #[cfg(feature = "sev")]
    pub fn platform_status(&mut self) -> Result<Status, UserApiError> {
        let mut info: PlatformStatus = Default::default();
        let mut cmd_buf = Command::from_mut(&mut info);
        PLATFORM_STATUS
            .ioctl(&mut self.0, &mut cmd_buf)
            .map_err(|_| cmd_buf.encapsulate())?;

        Ok(Status {
            build: crate::firmware::host::types::Build {
                version: crate::firmware::host::types::Version {
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
                _ => return Err(SevError::InvalidPlatformState)?,
            },
        })
    }

    /// Generate a new Platform Encryption Key (PEK).
    #[cfg(feature = "sev")]
    pub fn pek_generate(&mut self) -> Result<(), UserApiError> {
        let mut cmd_buf = Command::from(&PekGen);
        PEK_GEN
            .ioctl(&mut self.0, &mut cmd_buf)
            .map_err(|_| cmd_buf.encapsulate())?;
        Ok(())
    }

    /// Request a signature for the PEK.
    #[cfg(feature = "sev")]
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
    #[cfg(feature = "sev")]
    pub fn pdh_generate(&mut self) -> Result<(), UserApiError> {
        let mut cmd_buf = Command::from(&PdhGen);
        PDH_GEN
            .ioctl(&mut self.0, &mut cmd_buf)
            .map_err(|_| cmd_buf.encapsulate())?;
        Ok(())
    }

    /// Export the SEV certificate chain.
    #[cfg(feature = "sev")]
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

    /// Take ownership of the SEV platform.
    #[cfg(feature = "sev")]
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

    /// Get the unique CPU identifier.
    ///
    /// This is especially helpful for sending AMD an HTTP request to fetch
    /// the signed CEK certificate.
    #[cfg(any(feature = "sev", feature = "snp"))]
    pub fn get_identifier(&mut self) -> Result<Identifier, UserApiError> {
        let mut bytes = [0u8; 64];
        let mut id = GetId::new(&mut bytes);
        let mut cmd_buf = Command::from_mut(&mut id);

        GET_ID
            .ioctl(&mut self.0, &mut cmd_buf)
            .map_err(|_| cmd_buf.encapsulate())?;
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
    pub fn snp_platform_status(&mut self) -> Result<SnpPlatformStatus, UserApiError> {
        // Create an empty buffer for the SNP Platform Status to be written to by the Kernel.
        let mut platform_status: FFISnpPlatformStatus = FFISnpPlatformStatus::default();

        let mut cmd_buf = Command::from_mut(&mut platform_status);

        SNP_PLATFORM_STATUS
            .ioctl(&mut self.0, &mut cmd_buf)
            .map_err(|_| cmd_buf.encapsulate())?;

        // Determine SEV-SNP CPU generation in order to parse platform status accordingly.
        let generation = Generation::identify_host_generation()?;

        Ok((generation, &*platform_status).try_into()?)
    }

    /// The firmware will perform the following actions:  
    /// - Set the CommittedTCB to the CurrentTCB of the current firmware.  
    /// - Set the CommittedVersion to the FirmwareVersion of the current firmware.  
    /// - Sets the ReportedTCB to the CurrentTCB.  
    /// - Deletes the VLEK hashstick if the ReportedTCB changed.
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
        let mut cmd_buf = Command::from_mut(&mut buf);

        SNP_COMMIT
            .ioctl(&mut self.0, &mut cmd_buf)
            .map_err(|_| cmd_buf.encapsulate())?;

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
    /// let status: bool = firmware.snp_set_config(configuration).unwrap();
    /// ```
    #[cfg(feature = "snp")]
    pub fn snp_set_config(&mut self, new_config: Config) -> Result<(), UserApiError> {
        let mut binding: SnpSetConfig = new_config.try_into()?;

        let mut cmd_buf = Command::from_mut(&mut binding);

        SNP_SET_CONFIG
            .ioctl(&mut self.0, &mut cmd_buf)
            .map_err(|_| cmd_buf.encapsulate())?;

        Ok(())
    }

    #[cfg(feature = "snp")]
    /// Insert a Version Loaded Endorsement Key Hashstick into the AMD Secure Processor.
    ///
    /// # Example:
    /// ```ignore
    /// # Read the VLEK Hashstick Bytes into your application.
    /// # Our variable will be "hashstick_bytes"
    ///
    /// let mut firmware: Firmware = Firmware::open().unwrap();
    ///
    /// // Parse the bytes into a `WrappedVlekHashstick` to verify content before passing to the firmware.:
    /// let generation = Generation::identify_host_generation()?;
    /// let hashstick = WrappedVlekHashstick::from_bytes(hashstick_bytes.as_slice(), generation)?;
    ///
    /// // Load the VLEK Hashstick into the AMD Secure Processor.
    /// firmware.snp_vlek_load(hashstick).unwrap();
    /// ```
    pub fn snp_vlek_load(&mut self, hashstick: WrappedVlekHashstick) -> Result<(), UserApiError> {
        use std::convert::TryFrom;

        use types::FFI::types::{SnpVlekLoad, WrappedVlekHashstick as FFIWrappedVlekHashstick};

        let generation = Generation::identify_host_generation()?;

        let mut buffer: [u8; 432] = [0; 432];

        hashstick.write_bytes(&mut buffer[..], generation)?;

        let parsed_bytes: FFIWrappedVlekHashstick =
            FFIWrappedVlekHashstick::try_from(buffer.as_slice())?;

        let mut vlek_load: SnpVlekLoad = SnpVlekLoad::new(&parsed_bytes);
        let mut cmd_buf = Command::from_mut(&mut vlek_load);

        SNP_VLEK_LOAD
            .ioctl(&mut self.0, &mut cmd_buf)
            .map_err(|_| cmd_buf.encapsulate())?;

        Ok(())
    }
}

#[cfg(target_os = "linux")]
impl AsRawFd for Firmware {
    fn as_raw_fd(&self) -> RawFd {
        self.0.as_raw_fd()
    }
}
