// SPDX-License-Identifier: Apache-2.0

//! A collection of type-safe ioctl implementations for the AMD Secure Encrypted Virtualization
//! (SEV) platform. These ioctls are exported by the Linux kernel.

use crate::{
    error::{Error, Indeterminate},
    impl_const_id,
};

#[cfg(feature = "sev")]
use crate::launch::linux::sev;

#[cfg(feature = "snp")]
use crate::launch::linux::snp;

#[cfg(any(feature = "sev", feature = "snp"))]
use crate::launch::linux::shared;

use std::{
    marker::PhantomData,
    os::{raw::c_ulong, unix::io::AsRawFd},
};

use iocuddle::*;

// These enum ordinal values are defined in the Linux kernel
// source code: arch/x86/include/uapi/asm/kvm.h
#[cfg(all(feature = "sev", feature = "snp"))]
impl_const_id! {
    /// The ioctl sub number
    pub Id => u32;

    sev::Init = 0,
    sev::EsInit = 1,
    sev::LaunchStart<'_> = 2,
    sev::LaunchUpdateData<'_> = 3,
    sev::LaunchUpdateVmsa = 4,
    sev::LaunchSecret<'_> = 5,
    sev::LaunchMeasure<'_> = 6,
    sev::LaunchFinish = 7,
    sev::LaunchAttestation<'_> = 20,

    shared::Init2 = 22,

    snp::LaunchStart = 100,
    snp::LaunchUpdate<'_> = 101,
    snp::LaunchFinish<'_> = 102,
}

#[cfg(all(feature = "sev", not(feature = "snp")))]
impl_const_id! {
    /// The ioctl sub number
    pub Id => u32;

    sev::Init = 0,
    sev::EsInit = 1,
    sev::LaunchStart<'_> = 2,
    sev::LaunchUpdateData<'_> = 3,
    sev::LaunchUpdateVmsa = 4,
    sev::LaunchSecret<'_> = 5,
    sev::LaunchMeasure<'_> = 6,
    sev::LaunchFinish = 7,
    sev::LaunchAttestation<'_> = 20,

    shared::Init2 = 22
}

#[cfg(all(not(feature = "sev"), feature = "snp"))]
impl_const_id! {
    /// The ioctl sub number
    pub Id => u32;

    shared::Init2 = 22,

    snp::LaunchStart = 100,
    snp::LaunchUpdate<'_> = 101,
    snp::LaunchFinish<'_> = 102,
}

const KVM: Group = Group::new(0xAE);
const ENC_OP: Ioctl<WriteRead, &c_ulong> = unsafe { KVM.write_read(0xBA) };

#[cfg(feature = "snp")]
pub const KVM_MEMORY_ATTRIBUTE_PRIVATE: u64 = 1 << 3;

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
#[cfg(feature = "sev")]
#[deprecated(note = "Init2 should be used instead")]
pub const _INIT: Ioctl<WriteRead, &Command<sev::Init>> = unsafe { ENC_OP.lie() };

/// Initialize the SEV-ES platform context.
#[cfg(feature = "sev")]
#[deprecated(note = "Init2 should be used instead")]
pub const _ES_INIT: Ioctl<WriteRead, &Command<sev::EsInit>> = unsafe { ENC_OP.lie() };

/// Create encrypted guest context.
#[cfg(feature = "sev")]
pub const LAUNCH_START: Ioctl<WriteRead, &Command<sev::LaunchStart>> = unsafe { ENC_OP.lie() };

/// Encrypt guest data with its VEK.
#[cfg(feature = "sev")]
pub const LAUNCH_UPDATE_DATA: Ioctl<WriteRead, &Command<sev::LaunchUpdateData>> =
    unsafe { ENC_OP.lie() };

/// Encrypt the VMSA contents for SEV-ES.
#[cfg(feature = "sev")]
pub const LAUNCH_UPDATE_VMSA: Ioctl<WriteRead, &Command<sev::LaunchUpdateVmsa>> =
    unsafe { ENC_OP.lie() };

/// Inject a secret into the guest.
#[cfg(feature = "sev")]
pub const LAUNCH_SECRET: Ioctl<WriteRead, &Command<sev::LaunchSecret>> = unsafe { ENC_OP.lie() };

/// Get the guest's measurement.
#[cfg(feature = "sev")]
pub const LAUNCH_MEASUREMENT: Ioctl<WriteRead, &Command<sev::LaunchMeasure>> =
    unsafe { ENC_OP.lie() };

/// Complete the SEV launch flow and transition the guest into
/// the ready state.
#[cfg(feature = "sev")]
pub const LAUNCH_FINISH: Ioctl<WriteRead, &Command<sev::LaunchFinish>> = unsafe { ENC_OP.lie() };

/// Fetch a legacy SEV VM's attestation report.
#[cfg(feature = "sev")]
pub const LAUNCH_ATTESTATION: Ioctl<WriteRead, &Command<sev::LaunchAttestation>> =
    unsafe { ENC_OP.lie() };

/// Corresponds to the `KVM_MEMORY_ENCRYPT_REG_REGION` ioctl
#[cfg(any(feature = "sev", feature = "snp"))]
pub const ENC_REG_REGION: Ioctl<Write, &KvmEncRegion> =
    unsafe { KVM.read::<KvmEncRegion>(0xBB).lie() };

/// Corresponds to the `KVM_SET_MEMORY_ATTRIBUTES` ioctl
#[cfg(feature = "snp")]
pub const SET_MEMORY_ATTRIBUTES: Ioctl<Write, &KvmSetMemoryAttributes> =
    unsafe { KVM.write::<KvmSetMemoryAttributes>(0xd2) };

/// Use the KVM_SEV_INIT2 ioctl to initialize the SEV platform context.
#[cfg(any(feature = "sev", feature = "snp"))]
pub const INIT2: Ioctl<WriteRead, &Command<shared::Init2>> = unsafe { ENC_OP.lie() };

/// Initialize the flow to launch a guest.
#[cfg(feature = "snp")]
pub const SNP_LAUNCH_START: Ioctl<WriteRead, &Command<snp::LaunchStart>> = unsafe { ENC_OP.lie() };

/// Insert pages into the guest physical address space.
#[cfg(feature = "snp")]
pub const SNP_LAUNCH_UPDATE: Ioctl<WriteRead, &Command<snp::LaunchUpdate>> =
    unsafe { ENC_OP.lie() };

/// Complete the guest launch flow.
#[cfg(feature = "snp")]
pub const SNP_LAUNCH_FINISH: Ioctl<WriteRead, &Command<snp::LaunchFinish>> =
    unsafe { ENC_OP.lie() };

/// Corresponds to the kernel struct `kvm_enc_region`
#[repr(C)]
#[derive(Debug, Default, Copy, Clone, PartialEq, Eq)]
pub struct KvmEncRegion<'a> {
    addr: u64,
    size: u64,
    phantom: PhantomData<&'a [u8]>,
}

impl<'a> KvmEncRegion<'a> {
    /// Create a new `KvmEncRegion` referencing some memory assigned to the virtual machine.
    pub fn new(data: &'a [u8]) -> Self {
        Self {
            addr: data.as_ptr() as _,
            size: data.len() as _,
            phantom: PhantomData,
        }
    }

    /// Register the encrypted memory region to a virtual machine
    pub fn register(&mut self, vm_fd: &mut impl AsRawFd) -> std::io::Result<std::os::raw::c_uint> {
        ENC_REG_REGION.ioctl(vm_fd, self)
    }
}

/// Corresponds to the kernel struct `kvm_memory_attributes`
#[cfg(feature = "snp")]
#[repr(C)]
#[derive(Debug, Default, Copy, Clone, PartialEq, Eq)]
pub struct KvmSetMemoryAttributes {
    addr: u64,
    size: u64,
    attributes: u64,
    flags: u64,
}

#[cfg(feature = "snp")]
impl KvmSetMemoryAttributes {
    /// Create a new `KvmEncRegion` referencing some memory assigned to the virtual machine.
    pub fn new(data: u64, len: u64, attributes: u64) -> Self {
        Self {
            addr: data,
            size: len,
            attributes,
            flags: 0,
        }
    }

    /// Register the encrypted memory region to a virtual machine
    #[cfg(feature = "snp")]
    pub fn set_attributes(
        &mut self,
        vm_fd: &mut impl AsRawFd,
    ) -> std::io::Result<std::os::raw::c_uint> {
        SET_MEMORY_ATTRIBUTES.ioctl(vm_fd, self)
    }
}

/// A generic SEV command
#[repr(C)]
pub struct Command<'a, T: Id> {
    code: u32,
    data: u64,
    error: u32,
    sev_fd: u32,
    _phantom: PhantomData<&'a T>,
}

impl<'a, T: Id> Command<'a, T> {
    /// create the command from a mutable subcommand
    #[cfg(feature = "sev")]
    pub fn from_mut(sev: &'a impl AsRawFd, subcmd: &'a mut T) -> Self {
        Self {
            code: T::ID,
            data: subcmd as *mut T as _,
            error: 0,
            sev_fd: sev.as_raw_fd() as _,
            _phantom: PhantomData,
        }
    }

    /// create the command from a subcommand reference
    pub fn from(sev: &'a impl AsRawFd, subcmd: &'a T) -> Self {
        Self {
            code: T::ID,
            data: subcmd as *const T as _,
            error: 0,
            sev_fd: sev.as_raw_fd() as _,
            _phantom: PhantomData,
        }
    }

    /// encapsulate a `std::io::Error` in an `Indeterminate<Error>`
    pub fn encapsulate(&self, err: std::io::Error) -> Indeterminate<Error> {
        match self.error {
            0 => Indeterminate::<Error>::from(err),
            _ => Indeterminate::<Error>::from(self.error),
        }
    }
}
