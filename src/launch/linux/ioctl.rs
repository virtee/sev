// SPDX-License-Identifier: Apache-2.0

use crate::firmware::{Error, Indeterminate};
use crate::impl_const_id;
use crate::kvm::types::*;
use iocuddle::*;

use std::marker::PhantomData;
use std::os::raw::c_ulong;
use std::os::unix::io::AsRawFd;

// These enum ordinal values are defined in the Linux kernel
// source code: include/uapi/linux/kvm.h
impl_const_id! {
    pub Id => u32;
    Init = 0,
    LaunchStart<'_> = 2,
    LaunchUpdateData<'_> = 3,
    LaunchSecret<'_> = 5,
    LaunchMeasure<'_> = 6,
    LaunchFinish = 7,
}

const KVM: Group = Group::new(0xAE);
const ENC_OP: Ioctl<WriteRead, &c_ulong> = unsafe { KVM.write_read(0xBA) };

// Note: the iocuddle::Ioctl::lie() constructor has been used here because
// KVM_MEMORY_ENCRYPT_OP ioctl was defined like this:
//
// _IOWR(KVMIO, 0xba, unsigned long)
//
// Instead of something like this:
//
// _IOWR(KVMIO, 0xba, struct kvm_sev_cmd)
//
// which would require extra work to wrap around the design decision for
// that ioctl.

/// Initialize the SEV platform context.
pub const INIT: Ioctl<WriteRead, &Command<Init>> = unsafe { ENC_OP.lie() };

/// Create encrypted guest context.
pub const LAUNCH_START: Ioctl<WriteRead, &Command<LaunchStart>> = unsafe { ENC_OP.lie() };

/// Encrypt guest data with its VEK.
pub const LAUNCH_UPDATE_DATA: Ioctl<WriteRead, &Command<LaunchUpdateData>> =
    unsafe { ENC_OP.lie() };

/// Inject a secret into the guest.
pub const LAUNCH_SECRET: Ioctl<WriteRead, &Command<LaunchSecret>> = unsafe { ENC_OP.lie() };

/// Get the guest's measurement.
pub const LAUNCH_MEASUREMENT: Ioctl<WriteRead, &Command<LaunchMeasure>> = unsafe { ENC_OP.lie() };

/// Complete the SEV launch flow and transition the guest into
/// the ready state.
pub const LAUNCH_FINISH: Ioctl<WriteRead, &Command<LaunchFinish>> = unsafe { ENC_OP.lie() };

#[repr(C)]
pub struct Command<'a, T: Id> {
    code: u32,
    data: u64,
    error: u32,
    sev_fd: u32,
    _phantom: PhantomData<&'a T>,
}

impl<'a, T: Id> Command<'a, T> {
    pub fn from_mut(sev: &'a mut impl AsRawFd, subcmd: &'a mut T) -> Self {
        Self {
            code: T::ID,
            data: subcmd as *mut T as _,
            error: 0,
            sev_fd: sev.as_raw_fd() as _,
            _phantom: PhantomData,
        }
    }

    pub fn from(sev: &'a mut impl AsRawFd, subcmd: &'a T) -> Self {
        Self {
            code: T::ID,
            data: subcmd as *const T as _,
            error: 0,
            sev_fd: sev.as_raw_fd() as _,
            _phantom: PhantomData,
        }
    }

    pub fn encapsulate(&self, err: std::io::Error) -> Indeterminate<Error> {
        match self.error {
            0 => Indeterminate::<Error>::from(err),
            _ => Indeterminate::<Error>::from(self.error as u32),
        }
    }
}
