// SPDX-License-Identifier: Apache-2.0

//! An implementation of the SEV (non-ES, non-SNP) launch process as a type-state machine.
//! This ensures (at compile time) that the right steps are called in the
//! right order.

#[cfg(target_os = "linux")]
use crate::launch::linux::ioctl::*;
#[cfg(target_os = "linux")]
use crate::launch::linux::sev::*;
use crate::*;

use std::io::Result;
use std::mem::MaybeUninit;
use std::os::unix::io::RawFd;

use bitflags::bitflags;
use serde::{Deserialize, Serialize};

/// Launcher type-state that indicates a brand new launch.
pub struct New;

/// Launcher type-state that indicates an in-progress launch.
pub struct Started(Handle);

/// Launcher type-state that indicates the availability of a measurement.
pub struct Measured(Handle, Measurement);

/// Facilitates the correct execution of the SEV launch process.
pub struct Launcher<T> {
    state: T,
    vm_fd: RawFd,
    sev: RawFd,
}

impl<T> Launcher<T> {
    /// Give access to the vm fd to create vCPUs or such.
    pub fn as_mut_vmfd(&mut self) -> &mut RawFd {
        &mut self.vm_fd
    }
}

impl Launcher<New> {
    /// Begin the SEV launch process.
    pub fn new(kvm: RawFd, sev: RawFd) -> Result<Self> {
        let mut launcher = Launcher {
            vm_fd: kvm,
            sev,
            state: New,
        };

        let mut cmd = Command::from(&mut launcher.sev, &Init);
        INIT.ioctl(&mut launcher.vm_fd, &mut cmd)
            .map_err(|e| cmd.encapsulate(e))?;

        Ok(launcher)
    }

    /// Create an encrypted guest context.
    pub fn start(mut self, start: Start) -> Result<Launcher<Started>> {
        let mut launch_start = LaunchStart::new(&start.policy, &start.cert, &start.session);
        let mut cmd = Command::from_mut(&mut self.sev, &mut launch_start);
        LAUNCH_START
            .ioctl(&mut self.vm_fd, &mut cmd)
            .map_err(|e| cmd.encapsulate(e))?;

        let next = Launcher {
            state: Started(launch_start.into()),
            vm_fd: self.vm_fd,
            sev: self.sev,
        };

        Ok(next)
    }
}

impl Launcher<Started> {
    /// Encrypt guest data with its VEK.
    pub fn update_data(&mut self, data: &[u8]) -> Result<()> {
        let launch_update_data = LaunchUpdateData::new(data);
        let mut cmd = Command::from(&mut self.sev, &launch_update_data);

        KvmEncRegion::new(data).register(&mut self.vm_fd)?;

        LAUNCH_UPDATE_DATA
            .ioctl(&mut self.vm_fd, &mut cmd)
            .map_err(|e| cmd.encapsulate(e))?;

        Ok(())
    }

    /// Request a measurement from the SEV firmware.
    pub fn measure(mut self) -> Result<Launcher<Measured>> {
        let mut measurement = MaybeUninit::uninit();
        let mut launch_measure = LaunchMeasure::new(&mut measurement);
        let mut cmd = Command::from_mut(&mut self.sev, &mut launch_measure);
        LAUNCH_MEASUREMENT
            .ioctl(&mut self.vm_fd, &mut cmd)
            .map_err(|e| cmd.encapsulate(e))?;

        let next = Launcher {
            state: Measured(self.state.0, unsafe { measurement.assume_init() }),
            vm_fd: self.vm_fd,
            sev: self.sev,
        };

        Ok(next)
    }
}

impl Launcher<Measured> {
    /// Get the measurement that the SEV platform recorded.
    pub fn measurement(&self) -> Measurement {
        self.state.1
    }

    /// Inject a secret into the guest.
    ///
    /// ## Remarks
    ///
    /// This should only be called after a successful attestation flow.
    pub fn inject(&mut self, secret: &Secret, guest: usize) -> Result<()> {
        let launch_secret = LaunchSecret::new(&secret.header, guest, &secret.ciphertext[..]);
        let mut cmd = Command::from(&mut self.sev, &launch_secret);
        LAUNCH_SECRET
            .ioctl(&mut self.vm_fd, &mut cmd)
            .map_err(|e| cmd.encapsulate(e))?;
        Ok(())
    }

    /// Complete the SEV launch process.
    pub fn finish(mut self) -> Result<Handle> {
        let mut cmd = Command::from(&mut self.sev, &LaunchFinish);
        LAUNCH_FINISH
            .ioctl(&mut self.vm_fd, &mut cmd)
            .map_err(|e| cmd.encapsulate(e))?;
        Ok(self.state.0)
    }
}

bitflags! {
    /// Configurable SEV Policy options.
    #[derive(Default, Deserialize, Serialize)]
    pub struct PolicyFlags: u16 {
        /// When set, debugging the guest is forbidden.
        const NO_DEBUG        = 0b00000001u16.to_le();

        /// When set, sharing keys with other guests is prohibited.
        const NO_KEY_SHARING  = 0b00000010u16.to_le();

        /// When set, SEV-ES protections are required.
        const ENCRYPTED_STATE = 0b00000100u16.to_le();

        /// When set, the guest may not be sent to another platform.
        const NO_SEND         = 0b00001000u16.to_le();

        /// When set, the guest may not be transmitted to a platform
        /// that is outside of the domain.
        const DOMAIN          = 0b00010000u16.to_le();

        /// When set, the guest may not be transmitted to another
        /// platform that is not SEV-capable.
        const SEV             = 0b00100000u16.to_le();
    }
}

/// Describes a policy that the AMD Secure Processor will
/// enforce.
#[repr(C)]
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq, Deserialize, Serialize)]
pub struct Policy {
    /// The various policy optons are encoded as bit flags.
    pub flags: PolicyFlags,

    /// The desired minimum platform firmware version.
    pub minfw: Version,
}

/// Convert a policy represented as a u32 to a Policy struct.
impl From<u32> for Policy {
    fn from(p: u32) -> Self {
        let flags = p as u16;
        let flags = PolicyFlags::from_bits_truncate(flags);

        let p = p >> 16;
        let p = p as u16;
        let minfw = Version::from(p);

        Self { flags, minfw }
    }
}

/// A secure channel between the tenant and the AMD Secure
/// Processor.
#[repr(C)]
#[derive(Copy, Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Session {
    /// Used for deriving a shared secret between the tenant
    /// and the AMD SP.
    pub nonce: [u8; 16],

    /// The TEK and TIK concatenated together and wrapped by
    /// the Key Encryption Key and the Key Integrity Key.
    /// (KIK (KEK (TEK|TIK))).
    pub wrap_tk: [u8; 32],

    /// The initialization vector.
    pub wrap_iv: [u8; 16],

    /// Integrity protection for the wrapped keys (see the
    /// `wrap_tk` field of this struct).
    pub wrap_mac: [u8; 32],

    /// The integrity-protected SEV policy.
    pub policy_mac: [u8; 32],
}

/// Used to establish a secure session with the AMD SP.
#[repr(C)]
#[derive(Copy, Clone, Debug, PartialEq, Eq, Deserialize, Serialize)]
pub struct Start {
    /// The tenant's policy for this SEV guest.
    pub policy: Policy,

    /// The tenant's Diffie-Hellman certificate.
    pub cert: certs::sev::Certificate,

    /// A secure channel with the AMD SP.
    pub session: Session,
}

impl codicon::Decoder<()> for Start {
    type Error = std::io::Error;

    fn decode(mut reader: impl Read, _: ()) -> std::io::Result<Self> {
        reader.load()
    }
}

impl codicon::Encoder<()> for Start {
    type Error = std::io::Error;

    fn encode(&self, mut writer: impl Write, _: ()) -> std::io::Result<()> {
        writer.save(self)
    }
}

bitflags! {
    /// Additional descriptions of the secret header packet.
    #[derive(Default, Deserialize, Serialize)]
    pub struct HeaderFlags: u32 {
        /// If set, the contents of the packet are compressed and
        /// the AMD SP must decompress them.
        const COMPRESSED = 0b00000001u32.to_le();
    }
}

/// The header for a data packet that contains secret information
/// to be injected into the guest.
#[repr(C)]
#[derive(Copy, Clone, Debug, PartialEq, Eq, Deserialize, Serialize)]
pub struct Header {
    /// Describes the secret packet (for example: if it is
    /// compressed).
    pub flags: HeaderFlags,

    /// The initialization vector.
    pub iv: [u8; 16],

    /// Integrity protection MAC.
    pub mac: [u8; 32],
}

/// A packet containing secret information to be injected
/// into the guest.
#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize)]
pub struct Secret {
    /// The header for this packet.
    pub header: Header,

    /// The encrypted secret to inject.
    pub ciphertext: Vec<u8>,
}

impl codicon::Decoder<()> for Secret {
    type Error = std::io::Error;

    fn decode(mut reader: impl Read, _: ()) -> std::io::Result<Self> {
        let header = reader.load()?;
        let mut ciphertext = vec![];
        let _ = reader.read_to_end(&mut ciphertext)?;
        Ok(Self { header, ciphertext })
    }
}

impl codicon::Encoder<()> for Secret {
    type Error = std::io::Error;

    fn encode(&self, mut writer: impl Write, _: ()) -> std::io::Result<()> {
        writer.save(&self.header)?;
        writer.write_all(&self.ciphertext)
    }
}

/// A measurement of the SEV guest.
#[repr(C)]
#[derive(Copy, Clone, Debug, PartialEq, Eq, Deserialize, Serialize)]
pub struct Measurement {
    /// The measurement.
    pub measure: [u8; 32],

    /// A random nonce.
    pub mnonce: [u8; 16],
}

impl codicon::Decoder<()> for Measurement {
    type Error = std::io::Error;

    fn decode(mut reader: impl Read, _: ()) -> std::io::Result<Self> {
        reader.load()
    }
}

impl codicon::Encoder<()> for Measurement {
    type Error = std::io::Error;

    fn encode(&self, mut writer: impl Write, _: ()) -> std::io::Result<()> {
        writer.save(self)
    }
}
