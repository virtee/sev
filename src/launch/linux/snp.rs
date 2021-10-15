// SPDX-License-Identifier: Apache-2.0

//! Types for interacting with the KVM SEV-SNP guest management API.

use crate::launch::snp::*;

use std::marker::PhantomData;

/// Initialize the SEV-SNP platform in KVM.
#[derive(Default)]
#[repr(C, packed)]
pub struct Init {
    /// Reserved space, must be always set to 0 when issuing the ioctl.
    flags: u64,
}

/// Initialize the flow to launch a guest.
#[repr(C)]
pub struct LaunchStart<'a> {
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

    pad: [u8; 6],

    _phantom: PhantomData<&'a [u8]>,
}

impl From<Start<'_>> for LaunchStart<'_> {
    fn from(start: Start) -> Self {
        Self {
            policy: start.policy.into(),
            ma_uaddr: if let Some(addr) = start.ma_uaddr {
                addr.as_ptr() as u64
            } else {
                0
            },
            ma_en: if start.ma_uaddr.is_some() { 1 } else { 0 },
            imi_en: start.imi_en as _,
            gosvw: start.gosvw,
            pad: [0u8; 6],
            _phantom: PhantomData,
        }
    }
}

/// Insert pages into the guest physical address space.
#[repr(C)]
pub struct LaunchUpdate<'a> {
    /// guest start frame number.
    start_gfn: u64,

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

impl From<Update<'_>> for LaunchUpdate<'_> {
    fn from(update: Update) -> Self {
        Self {
            start_gfn: update.start_gfn,
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
pub struct LaunchFinish<'a> {
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

    pad: [u8; 6],

    _phantom: PhantomData<&'a [u8]>,
}

impl From<Finish<'_, '_>> for LaunchFinish<'_> {
    fn from(finish: Finish) -> Self {
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
            id_block_en: if finish.id_block.is_some() { 1 } else { 0 },
            auth_key_en: if finish.id_auth.is_some() { 1 } else { 0 },
            host_data: finish.host_data,
            pad: [0u8; 6],
            _phantom: PhantomData,
        }
    }
}
