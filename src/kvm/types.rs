// SPDX-License-Identifier: Apache-2.0

use crate::certs::sev;
use crate::launch::*;
use crate::launch::{Header, Measurement, Policy, Session};

use std::marker::PhantomData;
use std::mem::{size_of_val, MaybeUninit};

/// Initialize the SEV platform context.
#[repr(C)]
pub struct Init;

#[repr(transparent)]
pub struct Handle(u32);

impl From<LaunchStart<'_>> for Handle {
    fn from(ls: LaunchStart) -> Self {
        ls.handle
    }
}

/// Initiate SEV launch flow.
#[repr(C)]
pub struct LaunchStart<'a> {
    handle: Handle,
    policy: Policy,
    dh_addr: u64,
    dh_len: u32,
    session_addr: u64,
    session_len: u32,
    _phantom: PhantomData<&'a ()>,
}

impl<'a> LaunchStart<'a> {
    pub fn new(policy: &'a Policy, dh: &'a sev::Certificate, session: &'a Session) -> Self {
        Self {
            handle: Handle(0), /* platform will generate one for us */
            policy: *policy,
            dh_addr: dh as *const _ as _,
            dh_len: size_of_val(dh) as _,
            session_addr: session as *const _ as _,
            session_len: size_of_val(session) as _,
            _phantom: PhantomData,
        }
    }
}

/// Encrypt guest data with its VEK.
#[repr(C)]
pub struct LaunchUpdateData<'a> {
    addr: u64,
    len: u32,
    _phantom: PhantomData<&'a ()>,
}

impl<'a> LaunchUpdateData<'a> {
    pub fn new(data: &'a [u8]) -> Self {
        Self {
            addr: data.as_ptr() as _,
            len: data.len() as _,
            _phantom: PhantomData,
        }
    }
}

/// Inject a secret into the guest.
#[repr(C)]
pub struct LaunchSecret<'a> {
    hdr_addr: u64,
    hdr_len: u32,
    guest_addr: u64,
    guest_len: u32,
    trans_addr: u64,
    trans_len: u32,
    _phantom: PhantomData<&'a ()>,
}

impl<'a> LaunchSecret<'a> {
    pub fn new(header: &'a Header, guest: usize, trans: &'a [u8]) -> Self {
        Self {
            hdr_addr: header as *const _ as _,
            hdr_len: size_of_val(header) as _,
            guest_addr: guest as _,
            guest_len: trans.len() as _,
            trans_addr: trans.as_ptr() as _,
            trans_len: trans.len() as _,
            _phantom: PhantomData,
        }
    }
}

/// Get the guest's measurement.
#[repr(C)]
pub struct LaunchMeasure<'a> {
    addr: u64,
    len: u32,
    _phantom: PhantomData<&'a Measurement>,
}

impl<'a> LaunchMeasure<'a> {
    pub fn new(measurement: &'a mut MaybeUninit<Measurement>) -> Self {
        Self {
            addr: measurement.as_mut_ptr() as _,
            len: size_of_val(measurement) as _,
            _phantom: PhantomData,
        }
    }
}

/// Complete the SEV launch flow and transition guest into
/// ready state.
#[repr(C)]
pub struct LaunchFinish;

/// Initialize the SEV-SNP platform in KVM.
#[repr(C, packed)]
pub struct SnpInit {
    /// Reserved space, must be always set to 0 when issuing the ioctl.
    flags: u64,
}

impl Default for SnpInit {
    fn default() -> Self {
        Self { flags: 0 }
    }
}

/// Initialize the flow to launch a guest.
#[repr(C)]
pub struct SnpLaunchStart<'a> {
    /// Guest policy. See Table 7 of the AMD SEV-SNP Firmware
    /// specification for a description of the guest policy structure.
    policy: u64,

    /// Userspace address of migration agent
    ma_uaddr: u64,

    /// 1 if this guest is associated with a migration agent. Otherwise 0.
    ma_en: u8,

    /// 1 if this launch flow is launching an IMI for the purpose of
    /// guest-assisted migration. Otherwise 0.
    imi_en: u8,

    /// Hypervisor provided value to indicate guest OS visible workarounds.
    /// The format is hypervisor defined.
    gosvw: [u8; 16],

    _phantom: PhantomData<&'a [u8]>,
}

impl<'a> SnpLaunchStart<'a> {
    pub fn new(start: &'a SnpStart) -> Self {
        let uaddr = if let Some(addr) = start.ma_uaddr {
            addr.as_ptr() as u64
        } else {
            0
        };

        Self {
            policy: start.policy.as_u64(),
            ma_uaddr: uaddr,
            ma_en: start.ma_en as _,
            imi_en: start.imi_en as _,
            gosvw: start.gosvw,
            _phantom: PhantomData,
        }
    }
}

/// Insert pages into the guest physical address space.
#[repr(C)]
pub struct SnpLaunchUpdate<'a> {
    /// Userspace address of the page needed to be encrypted.
    uaddr: u64,

    /// Length of the page needed to be encrypted:
    /// (end encryption uaddr = uaddr + len).
    len: u32,

    /// Indicates that this page is part of the IMI of the guest.
    imi_page: u8,

    /// Encoded page type. See Table 58 if the SNP Firmware specification.
    page_type: u8,

    /// VMPL permission mask for VMPL3. See Table 59 of the SNP Firmware
    /// specification for the definition of the mask.
    vmpl3_perms: u8,

    /// VMPL permission mask for VMPL2.
    vmpl2_perms: u8,

    /// VMPL permission mask for VMPL1.
    vmpl1_perms: u8,

    _phantom: PhantomData<&'a ()>,
}

impl<'a, 'b> SnpLaunchUpdate<'a> {
    pub fn new(update: &'a SnpUpdate) -> Self {
        Self {
            uaddr: update.uaddr.as_ptr() as _,
            len: update.uaddr.len() as _,
            imi_page: if update.imi_page { 1 } else { 0 },
            page_type: update.page_type as _,
            vmpl3_perms: update.vmpl3_perms.bits(),
            vmpl2_perms: update.vmpl2_perms.bits(),
            vmpl1_perms: update.vmpl1_perms.bits(),
            _phantom: PhantomData,
        }
    }
}

pub const KVM_SEV_SNP_FINISH_DATA_SIZE: usize = 32;

/// Complete the guest launch flow.
#[repr(C)]
pub struct SnpLaunchFinish<'a> {
    /// Userspace address of the ID block. Ignored if ID_BLOCK_EN is 0.
    id_block_uaddr: u64,

    /// Userspace address of the authentication information of the ID block. Ignored if ID_BLOCK_EN is 0.
    id_auth_uaddr: u64,

    /// Indicates that the ID block is present.
    id_block_en: u8,

    /// Indicates that the author key is present in the ID authentication information structure.
    /// Ignored if ID_BLOCK_EN is 0.
    auth_key_en: u8,

    /// Opaque host-supplied data to describe the guest. The firmware does not interpret this value.
    host_data: [u8; KVM_SEV_SNP_FINISH_DATA_SIZE],

    _phantom: PhantomData<&'a [u8]>,
}

impl<'a> SnpLaunchFinish<'a> {
    pub fn new(finish: &'a SnpFinish) -> Self {
        let id_block = if let Some(addr) = finish.id_block {
            addr.as_ptr() as u64
        } else {
            0
        };

        let id_auth = if let Some(addr) = finish.id_auth {
            addr.as_ptr() as u64
        } else {
            0
        };

        Self {
            id_block_uaddr: id_block,
            id_auth_uaddr: id_auth,
            id_block_en: if finish.id_block_en { 1 } else { 0 },
            auth_key_en: if finish.auth_key_en { 1 } else { 0 },
            host_data: finish.host_data,
            _phantom: PhantomData,
        }
    }
}
