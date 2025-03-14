// SPDX-License-Identifier: Apache-2.0

//! An implementation of the SEV-SNP launch process as a type-state machine.
//! This ensures (at compile time) that the right steps are called in the
//! right order.

#[cfg(target_os = "linux")]
use crate::{
    error::FirmwareError,
    firmware::guest::GuestPolicy,
    launch::linux::{ioctl::*, shared::*, snp::*},
};

use std::{marker::PhantomData, os::unix::io::AsRawFd, result::Result};

use bitflags::bitflags;
use serde::{Deserialize, Serialize};

/// Launcher type-state that indicates a brand new launch.
pub struct New;

/// Launcher type-state that indicates a SNP in-progress.
pub struct Started;

/// Facilitates the correct execution of the SEV launch process.
pub struct Launcher<T, U: AsRawFd, V: AsRawFd> {
    vm_fd: U,
    sev: V,
    state: PhantomData<T>,
}

impl<T, U: AsRawFd, V: AsRawFd> AsRef<U> for Launcher<T, U, V> {
    /// Give access to the vm fd to create vCPUs or such.
    fn as_ref(&self) -> &U {
        &self.vm_fd
    }
}

impl<T, U: AsRawFd, V: AsRawFd> AsMut<U> for Launcher<T, U, V> {
    /// Give access to the vm fd to create vCPUs or such.
    fn as_mut(&mut self) -> &mut U {
        &mut self.vm_fd
    }
}

impl<U: AsRawFd, V: AsRawFd> Launcher<New, U, V> {
    /// Begin the SEV-SNP launch process by creating a Launcher and issuing the
    /// KVM_SNP_INIT ioctl.
    pub fn new(vm_fd: U, sev: V) -> Result<Self, FirmwareError> {
        let mut launcher = Launcher {
            vm_fd,
            sev,
            state: PhantomData,
        };

        let init = Init2::init_default_snp();

        let mut cmd = Command::from(&launcher.sev, &init);

        INIT2
            .ioctl(&mut launcher.vm_fd, &mut cmd)
            .map_err(|_| cmd.encapsulate())?;

        Ok(launcher)
    }

    /// Initialize the flow to launch a guest.
    pub fn start(mut self, start: Start) -> Result<Launcher<Started, U, V>, FirmwareError> {
        let launch_start = LaunchStart::from(start);
        let mut cmd = Command::from(&self.sev, &launch_start);

        SNP_LAUNCH_START
            .ioctl(&mut self.vm_fd, &mut cmd)
            .map_err(|_| cmd.encapsulate())?;

        let launcher = Launcher {
            vm_fd: self.vm_fd,
            sev: self.sev,
            state: PhantomData,
        };

        Ok(launcher)
    }
}

impl<U: AsRawFd, V: AsRawFd> Launcher<Started, U, V> {
    /// Encrypt guest SNP data.
    pub fn update_data(
        &mut self,
        mut update: Update,
        gpa: u64,
        gpa_len: u64,
    ) -> Result<(), FirmwareError> {
        loop {
            let launch_update_data = LaunchUpdate::from(update);
            let mut cmd = Command::from(&self.sev, &launch_update_data);

            // Register the encryption region
            KvmEncRegion::new(update.uaddr).register(&mut self.vm_fd)?;

            // Set memory attributes to private
            KvmSetMemoryAttributes::new(gpa, gpa_len, KVM_MEMORY_ATTRIBUTE_PRIVATE)
                .set_attributes(&mut self.vm_fd)?;

            // Perform the SNP_LAUNCH_UPDATE ioctl call
            match SNP_LAUNCH_UPDATE.ioctl(&mut self.vm_fd, &mut cmd) {
                Ok(_) => {
                    // Check if the entire range has been processed
                    if launch_update_data.len == 0 {
                        break;
                    }

                    // Update the `update` object with the remaining range
                    update.start_gfn = launch_update_data.start_gfn;
                    update.uaddr = unsafe {
                        std::slice::from_raw_parts(
                            launch_update_data.uaddr as *const u8,
                            launch_update_data.len as usize,
                        )
                    };
                }
                Err(e) if e.raw_os_error() == Some(libc::EAGAIN) => {
                    // Retry the operation if `-EAGAIN` is returned
                    continue;
                }
                Err(_) => {
                    // Handle other errors
                    return Err(cmd.encapsulate());
                }
            }
        }

        Ok(())
    }

    /// Complete the SNP launch process.
    pub fn finish(mut self, finish: Finish) -> Result<(U, V), FirmwareError> {
        let launch_finish = LaunchFinish::from(finish);
        let mut cmd = Command::from(&self.sev, &launch_finish);

        SNP_LAUNCH_FINISH
            .ioctl(&mut self.vm_fd, &mut cmd)
            .map_err(|_| cmd.encapsulate())?;

        Ok((self.vm_fd, self.sev))
    }
}

/// Encapsulates the various data needed to begin the launch process.
#[derive(Default, Clone, Debug, PartialEq, Eq, Deserialize, Serialize)]
pub struct Start {
    /// Describes a policy that the AMD Secure Processor will enforce.
    pub(crate) policy: GuestPolicy,

    /// Hypervisor provided value to indicate guest OS visible workarounds.The format is hypervisor defined.
    pub(crate) gosvw: [u8; 16],

    /// Indicates that this launch flow is launching an IMI for the purpose of guest-assisted migration.
    pub(crate) flags: u16,
}

impl Start {
    /// Encapsulate all data needed for the SNP_LAUNCH_START ioctl.
    pub fn new(policy: GuestPolicy, gosvw: [u8; 16]) -> Self {
        Self {
            policy,
            gosvw,
            flags: 0,
        }
    }
}

/// Encoded page types for a launch update. See Table 58 of the SNP Firmware
/// specification for further details.
#[derive(Copy, Clone, Debug, PartialEq, Eq, Deserialize, Serialize)]
#[repr(C)]
#[non_exhaustive]
pub enum PageType {
    /// A normal data page.
    Normal = 0x1,

    /// A VMSA page.
    Vmsa = 0x2,

    /// A page full of zeroes.
    Zero = 0x3,

    /// A page that is encrypted but not measured
    Unmeasured = 0x4,

    /// A page for the firmware to store secrets for the guest.
    Secrets = 0x5,

    /// A page for the hypervisor to provide CPUID function values.
    Cpuid = 0x6,
}

/// Encapsulates the various data needed to begin the update process.
#[derive(Copy, Clone, Debug, PartialEq, Eq, Deserialize, Serialize)]
pub struct Update<'a> {
    /// guest start frame number.
    pub(crate) start_gfn: u64,

    /// The userspace of address of the encrypted region.
    pub(crate) uaddr: &'a [u8],

    /// Encoded page type.
    pub(crate) page_type: PageType,
}

impl<'a> Update<'a> {
    /// Encapsulate all data needed for the SNP_LAUNCH_UPDATE ioctl.
    pub fn new(start_gfn: u64, uaddr: &'a [u8], page_type: PageType) -> Self {
        Self {
            start_gfn,
            uaddr,
            page_type,
        }
    }
}

bitflags! {
    #[derive(Default, Deserialize, Serialize)]
    /// VMPL permission masks.
    pub struct VmplPerms: u8 {
        /// Page is readable by the VMPL.
        const READ = 1;

        /// Page is writeable by the VMPL.
        const WRITE = 1 << 1;

        /// Page is executable by the VMPL in CPL3.
        const EXECUTE_USER = 1 << 2;

        /// Page is executable by the VMPL in CPL2, CPL1, and CPL0.
        const EXECUTE_SUPERVISOR = 1 << 3;
    }
}

/// Encapsulates the data needed to complete a guest launch.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct Finish<'a, 'b> {
    /// The userspace address of the encrypted region.
    pub(crate) id_block: Option<&'a [u8]>,

    /// The userspace address of the authentication information of the ID block.
    pub(crate) id_auth: Option<&'b [u8]>,

    /// Opaque host-supplied data to describe the guest. The firmware does not interpret this
    /// value.
    pub(crate) host_data: [u8; KVM_SEV_SNP_FINISH_DATA_SIZE],
}

impl<'a, 'b> Finish<'a, 'b> {
    /// Encapsulate all data needed for the SNP_LAUNCH_FINISH ioctl.
    pub fn new(
        id_block: Option<&'a [u8]>,
        id_auth: Option<&'b [u8]>,
        host_data: [u8; KVM_SEV_SNP_FINISH_DATA_SIZE],
    ) -> Self {
        Self {
            id_block,
            id_auth,
            host_data,
        }
    }
}
